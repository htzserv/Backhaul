package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
)

type TlsServerConfig struct {
	BindAddr         string
	Token            string
	SnifferLog       string
	TLSCertFile      string
	TLSKeyFile       string
	SNI              string
	TunnelStatus     string
	Ports            []string
	Nodelay          bool
	Sniffer          bool
	Mux              bool
	KeepAlive        time.Duration
	Heartbeat        time.Duration
	ChannelSize      int
	MuxCon           int
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	WebPort          int
	MSS              int
	SO_RCVBUF        int
	SO_SNDBUF        int
	ProxyProtocol    bool
	AcceptUDP        bool
}

type TlsServerTransport struct {
	config           *TlsServerConfig
	smuxConfig       *smux.Config
	parentctx        context.Context
	ctx              context.Context
	cancel           context.CancelFunc
	logger           *logrus.Logger
	rawChannel       chan net.Conn
	muxChannel       chan *smux.Session
	handshakeChannel chan net.Conn
	localChannel     chan LocalTCPConn
	reqNewConnChan   chan struct{}
	controlMu        sync.RWMutex
	controlChannel   net.Conn
	usageMonitor     *web.Usage
	restartMutex     sync.Mutex
	streamCounter    int32
	sessionCounter   int32
}

func NewTLSServer(parentCtx context.Context, cfg *TlsServerConfig, logger *logrus.Logger) *TlsServerTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	return &TlsServerTransport{
		smuxConfig: &smux.Config{
			Version:           cfg.MuxVersion,
			KeepAliveInterval: 20 * time.Second,
			KeepAliveTimeout:  40 * time.Second,
			MaxFrameSize:      cfg.MaxFrameSize,
			MaxReceiveBuffer:  cfg.MaxReceiveBuffer,
			MaxStreamBuffer:   cfg.MaxStreamBuffer,
		},
		config:           cfg,
		parentctx:        parentCtx,
		ctx:              ctx,
		cancel:           cancel,
		logger:           logger,
		rawChannel:       make(chan net.Conn, cfg.ChannelSize),
		muxChannel:       make(chan *smux.Session, cfg.ChannelSize),
		handshakeChannel: make(chan net.Conn, 16),
		localChannel:     make(chan LocalTCPConn, cfg.ChannelSize),
		reqNewConnChan:   make(chan struct{}, cfg.ChannelSize),
		usageMonitor:     web.NewDataStore(fmt.Sprintf(":%v", cfg.WebPort), ctx, cfg.SnifferLog, cfg.Sniffer, &cfg.TunnelStatus, logger),
	}
}

func (s *TlsServerTransport) modeLabel() string {
	if s.config.Mux {
		return "TLSMUX"
	}
	return "TLS"
}

func (s *TlsServerTransport) getControl() net.Conn {
	s.controlMu.RLock()
	defer s.controlMu.RUnlock()
	return s.controlChannel
}

func (s *TlsServerTransport) setControl(c net.Conn) {
	s.controlMu.Lock()
	s.controlChannel = c
	s.controlMu.Unlock()
}

func (s *TlsServerTransport) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}
	s.usageMonitor.SetStatus(fmt.Sprintf("Disconnected (%s)", s.modeLabel()))

	go s.tunnelListener()
	s.channelHandshake()

	if s.getControl() != nil {
		s.usageMonitor.SetStatus(fmt.Sprintf("Connected (%s)", s.modeLabel()))
		numCPU := runtime.NumCPU()
		if numCPU > 4 {
			numCPU = 4
		}
		go s.parsePortMappings()
		go s.channelHandler()

		for i := 0; i < numCPU; i++ {
			if s.config.Mux {
				go s.handleMuxLoop()
			} else {
				go s.handleRawLoop()
			}
		}
	}
}

func (s *TlsServerTransport) Restart() {
	if !s.restartMutex.TryLock() {
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Infof("restarting %s server...", s.modeLabel())
	if cc := s.getControl(); cc != nil {
		_ = cc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		_ = utils.SendBinaryByte(cc, utils.SG_Closed)
		_ = cc.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
	time.Sleep(1500 * time.Millisecond)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel
	s.rawChannel = make(chan net.Conn, s.config.ChannelSize)
	s.muxChannel = make(chan *smux.Session, s.config.ChannelSize)
	s.handshakeChannel = make(chan net.Conn, 16)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.setControl(nil)
	atomic.StoreInt32(&s.streamCounter, 0)
	atomic.StoreInt32(&s.sessionCounter, 0)
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)

	go s.Start()
}

func (s *TlsServerTransport) tunnelListener() {
	tlsCfg, err := network.LoadOrGenerateTLSConfig(s.config.TLSCertFile, s.config.TLSKeyFile, s.config.SNI, []string{"http/1.1", "h2"})
	if err != nil {
		s.logger.Errorf("failed to load/generate TLS config: %v", err)
		return
	}

	var rawListener net.Listener
	for attempt := 0; attempt < 10; attempt++ {
		rawListener, err = network.ListenWithBuffers(
			"tcp",
			s.config.BindAddr,
			s.config.SO_RCVBUF,
			s.config.SO_SNDBUF,
			s.config.MSS,
			s.config.KeepAlive,
			!s.config.Nodelay,
		)
		if err == nil {
			break
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err != nil {
		s.logger.Errorf("failed to start %s listener on %s: %v", s.modeLabel(), s.config.BindAddr, err)
		go s.Restart()
		return
	}
	defer rawListener.Close()

	tlsListener := tls.NewListener(rawListener, tlsCfg)
	if s.config.TLSCertFile == "" {
		s.logger.Infof("%s server listening on %s (Auto-TLS enabled)", s.modeLabel(), rawListener.Addr().String())
	} else {
		s.logger.Infof("%s server listening on %s (Custom TLS cert)", s.modeLabel(), rawListener.Addr().String())
	}

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				conn, err := tlsListener.Accept()
				if err != nil {
					continue
				}

				go func(c net.Conn) {
					if tlsConn, ok := c.(*tls.Conn); ok {
						hsCtx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
						err := tlsConn.HandshakeContext(hsCtx)
						cancel()
						if err != nil {
							c.Close()
							return
						}
					}

					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					msg, transport, err := utils.ReceiveBinaryTransportString(c)
					if err != nil || msg != s.config.Token {
						c.Close()
						return
					}
					_ = c.SetReadDeadline(time.Time{})

					if transport == utils.SG_Chan {
						if cc := s.getControl(); cc != nil {
							s.logger.Warnf("new %s control channel arrived, triggering fast reconnect...", s.modeLabel())
							c.Close()
							cc.Close()
							go s.Restart()
							return
						}
						if err := utils.SendBinaryTransportString(c, s.config.Token, utils.SG_Chan); err != nil {
							c.Close()
							return
						}
						select {
						case s.handshakeChannel <- c:
						default:
							c.Close()
						}
						return
					}

					if s.getControl() == nil {
						c.Close()
						return
					}

					if s.config.Mux {
						session, err := smux.Client(c, s.smuxConfig)
						if err != nil {
							c.Close()
							return
						}
						select {
						case s.muxChannel <- session:
						default:
							session.Close()
						}
					} else {
						select {
						case s.rawChannel <- c:
						default:
							c.Close()
						}
					}
				}(conn)
			}
		}
	}()

	<-s.ctx.Done()
}

func (s *TlsServerTransport) channelHandshake() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case conn := <-s.handshakeChannel:
			if s.getControl() != nil {
				conn.Close()
				continue
			}
			s.setControl(conn)
			s.logger.Infof("%s control channel established successfully", s.modeLabel())
			return
		}
	}
}

func (s *TlsServerTransport) channelHandler() {
	cc := s.getControl()
	if cc == nil {
		return
	}
	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	messageChan := make(chan byte, 10)
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				readTimeout := s.config.Heartbeat*2 + 15*time.Second
				if readTimeout < 30*time.Second {
					readTimeout = 30 * time.Second
				}
				_ = cc.SetReadDeadline(time.Now().Add(readTimeout))
				msg, err := utils.ReceiveBinaryByte(cc)
				if err != nil {
					if s.ctx.Err() == nil {
						s.logger.Warnf("TLS control channel closed: %v", err)
						go s.Restart()
					}
					return
				}
				messageChan <- msg
			}
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			_ = cc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_ = utils.SendBinaryByte(cc, utils.SG_Closed)
			return
		case <-s.reqNewConnChan:
			if err := utils.SendBinaryByte(cc, utils.SG_Chan); err != nil {
				go s.Restart()
				return
			}
		case <-ticker.C:
			if err := utils.SendBinaryByte(cc, utils.SG_HB); err != nil {
				go s.Restart()
				return
			}
		case msg := <-messageChan:
			switch msg {
			case utils.SG_HB:
			case utils.SG_Closed:
				s.logger.Infof("received farewell goodbye from %s client, restarting...", s.modeLabel())
				go s.Restart()
				return
			}
		}
	}
}

func (s *TlsServerTransport) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
		parts := strings.Split(portMapping, "=")
		var localAddr, remoteAddr string
		if len(parts) == 1 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = localPortOrRange
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					s.logger.Errorf("invalid port range format: %s", localPortOrRange)
					continue
				}
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					s.logger.Errorf("invalid start port: %s", rangeParts[0])
					continue
				}
				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
					s.logger.Errorf("invalid end port: %s", rangeParts[1])
					continue
				}
				for port := startPort; port <= endPort; port++ {
					go s.localListener(fmt.Sprintf(":%d", port), strconv.Itoa(port))
					time.Sleep(1 * time.Millisecond)
				}
				continue
			}
			port, err := strconv.Atoi(localPortOrRange)
			if err != nil || port < 1 || port > 65535 {
				s.logger.Errorf("invalid port format: %s", localPortOrRange)
				continue
			}
			localAddr = fmt.Sprintf(":%d", port)
		} else if len(parts) == 2 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = strings.TrimSpace(parts[1])
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					s.logger.Errorf("invalid port range format: %s", localPortOrRange)
					continue
				}
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					s.logger.Errorf("invalid start port: %s", rangeParts[0])
					continue
				}
				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
					s.logger.Errorf("invalid end port: %s", rangeParts[1])
					continue
				}
				for port := startPort; port <= endPort; port++ {
					go s.localListener(fmt.Sprintf(":%d", port), remoteAddr)
					time.Sleep(1 * time.Millisecond)
				}
				continue
			}
			port, err := strconv.Atoi(localPortOrRange)
			if err == nil && port >= 1 && port <= 65535 {
				localAddr = fmt.Sprintf(":%d", port)
			} else {
				localAddr = localPortOrRange
			}
		} else {
			s.logger.Errorf("invalid port mapping format: %s", portMapping)
			continue
		}
		go s.localListener(localAddr, remoteAddr)
		if s.config.AcceptUDP && !s.config.Mux {
			go startGenericUDPListener(s.ctx, localAddr, remoteAddr, s.config.ChannelSize, s.rawChannel, s.reqNewConnChan, s.logger, s.usageMonitor, s.config.Sniffer, nil)
		}
	}
}

func (s *TlsServerTransport) localListener(localAddr, remoteAddr string) {
	var listener net.Listener
	var err error
	for attempt := 0; attempt < 6; attempt++ {
		listener, err = net.Listen("tcp", localAddr)
		if err == nil {
			break
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(400 * time.Millisecond):
		}
	}
	if err != nil {
		s.logger.Errorf("failed to listen on %s: %v", localAddr, err)
		return
	}
	defer listener.Close()
	s.logger.Infof("listener started successfully on %s", listener.Addr().String())

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				select {
				case s.localChannel <- LocalTCPConn{conn: conn, remoteAddr: remoteAddr, timeCreated: time.Now().UnixMilli()}:
					if s.config.Mux {
						atomic.AddInt32(&s.streamCounter, 1)
						if atomic.LoadInt32(&s.streamCounter) >= atomic.LoadInt32(&s.sessionCounter)*int32(s.config.MuxCon) {
							select {
							case s.reqNewConnChan <- struct{}{}:
							default:
							}
						}
					} else {
						select {
						case s.reqNewConnChan <- struct{}{}:
						default:
						}
					}
				default:
					conn.Close()
				}
			}
		}
	}()

	<-s.ctx.Done()
}

func (s *TlsServerTransport) handleRawLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case localConn := <-s.localChannel:
		loop:
			for {
				if time.Now().UnixMilli()-localConn.timeCreated > 3000 {
					localConn.conn.Close()
					break loop
				}
				select {
				case <-s.ctx.Done():
					return
				case tunnelConn := <-s.rawChannel:
					if err := utils.SendBinaryTransportString(tunnelConn, localConn.remoteAddr, utils.SG_TCP); err != nil {
						tunnelConn.Close()
						continue loop
					}
					go handlers.TCPConnectionHandler(s.ctx, s.config.ProxyProtocol, localConn.conn, tunnelConn, s.logger, s.usageMonitor, handlers.LocalPortOf(localConn.conn), s.config.Sniffer)
					break loop
				}
			}
		}
	}
}

func (s *TlsServerTransport) handleMuxLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case session := <-s.muxChannel:
			atomic.AddInt32(&s.sessionCounter, 1)
			go s.handleMuxSession(session)
		}
	}
}

func (s *TlsServerTransport) handleMuxSession(session *smux.Session) {
	counter := make(chan struct{}, s.config.MuxCon)
	defer session.Close()

	for {
		counter <- struct{}{}
		select {
		case <-s.ctx.Done():
			<-counter
			return
		case incomingConn := <-s.localChannel:
			if time.Now().UnixMilli()-incomingConn.timeCreated > 3000 {
				incomingConn.conn.Close()
				atomic.AddInt32(&s.streamCounter, -1)
				<-counter
				continue
			}
			stream, err := session.OpenStream()
			if err != nil {
				atomic.AddInt32(&s.sessionCounter, -1)
				<-counter
				select {
				case s.localChannel <- incomingConn:
				default:
					incomingConn.conn.Close()
				}
				select {
				case s.reqNewConnChan <- struct{}{}:
				default:
				}
				return
			}
			if err := utils.SendBinaryString(stream, incomingConn.remoteAddr); err != nil {
				stream.Close()
				<-counter
				select {
				case s.localChannel <- incomingConn:
				default:
					incomingConn.conn.Close()
				}
				continue
			}
			go func() {
				handlers.TCPConnectionHandler(s.ctx, s.config.ProxyProtocol, incomingConn.conn, stream, s.logger, s.usageMonitor, handlers.LocalPortOf(incomingConn.conn), s.config.Sniffer)
				atomic.AddInt32(&s.streamCounter, -1)
				<-counter
			}()
		}
	}
}

func (s *TlsServerTransport) Status() string { return s.usageMonitor.GetStatus() }
