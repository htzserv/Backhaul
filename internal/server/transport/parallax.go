package transport

import (
	"context"
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
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type ParallaxServerConfig struct {
	BindAddr         string
	Token            string
	SnifferLog       string
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
	ProxyProtocol    bool
	Parallax         network.ParallaxParams
}

type ParallaxServerTransport struct {
	config           *ParallaxServerConfig
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

func NewParallaxServer(parentCtx context.Context, cfg *ParallaxServerConfig, logger *logrus.Logger) *ParallaxServerTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	return &ParallaxServerTransport{
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

func (s *ParallaxServerTransport) modeLabel() string {
	if s.config.Mux {
		return "PARALLAXMUX"
	}
	return "PARALLAX"
}

func (s *ParallaxServerTransport) getControl() net.Conn {
	s.controlMu.RLock()
	defer s.controlMu.RUnlock()
	return s.controlChannel
}

func (s *ParallaxServerTransport) setControl(c net.Conn) {
	s.controlMu.Lock()
	s.controlChannel = c
	s.controlMu.Unlock()
}

func (s *ParallaxServerTransport) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}
	s.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", s.modeLabel())

	go s.tunnelListener()
	s.channelHandshake()

	if s.getControl() != nil {
		s.config.TunnelStatus = fmt.Sprintf("Connected (%s)", s.modeLabel())
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

func (s *ParallaxServerTransport) Restart() {
	if !s.restartMutex.TryLock() {
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Infof("restarting %s server...", s.modeLabel())
	if cc := s.getControl(); cc != nil {
		_ = cc.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
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

func (s *ParallaxServerTransport) tunnelListener() {
	var listener *kcp.Listener
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		listener, err = network.ListenParallaxKCP(s.ctx, s.config.BindAddr, s.config.Parallax)
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
	defer listener.Close()

	s.logger.Infof("%s server listening on %s (multi-lane TCP + KCP/FEC, stall=%ds)", s.modeLabel(), s.config.BindAddr, s.config.Parallax.StallSec)

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				sess, err := listener.AcceptKCP()
				if err != nil {
					continue
				}
				go func(sConn *kcp.UDPSession) {
					network.TuneKCPSession(sConn, s.config.Parallax.KCP)
					_ = sConn.SetReadDeadline(time.Now().Add(8 * time.Second))
					msg, transport, err := utils.ReceiveBinaryTransportString(sConn)
					if err != nil || msg != s.config.Token {
						sConn.Close()
						return
					}
					_ = sConn.SetReadDeadline(time.Time{})

					if transport == utils.SG_Chan {
						if cc := s.getControl(); cc != nil {
							s.logger.Warnf("new %s control channel arrived, triggering fast reconnect...", s.modeLabel())
							sConn.Close()
							cc.Close()
							go s.Restart()
							return
						}
						if err := utils.SendBinaryTransportString(sConn, s.config.Token, utils.SG_Chan); err != nil {
							sConn.Close()
							return
						}
						select {
						case s.handshakeChannel <- sConn:
						default:
							sConn.Close()
						}
						return
					}

					if s.getControl() == nil {
						sConn.Close()
						return
					}

					if s.config.Mux {
						muxSess, err := smux.Client(sConn, s.smuxConfig)
						if err != nil {
							sConn.Close()
							return
						}
						select {
						case s.muxChannel <- muxSess:
						default:
							muxSess.Close()
						}
					} else {
						select {
						case s.rawChannel <- sConn:
						default:
							sConn.Close()
						}
					}
				}(sess)
			}
		}
	}()

	<-s.ctx.Done()
}

func (s *ParallaxServerTransport) channelHandshake() {
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

func (s *ParallaxServerTransport) channelHandler() {
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
						s.logger.Warnf("%s control channel closed: %v", s.modeLabel(), err)
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
			_ = cc.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
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
				go s.Restart()
				return
			}
		}
	}
}

func (s *ParallaxServerTransport) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
		parts := strings.Split(portMapping, "=")
		var localAddr, remoteAddr string
		if len(parts) == 1 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = localPortOrRange
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					continue
				}
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					continue
				}
				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
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
				continue
			}
			localAddr = fmt.Sprintf(":%d", port)
		} else if len(parts) == 2 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = strings.TrimSpace(parts[1])
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					continue
				}
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					continue
				}
				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
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
			continue
		}
		go s.localListener(localAddr, remoteAddr)
	}
}

func (s *ParallaxServerTransport) localListener(localAddr, remoteAddr string) {
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

func (s *ParallaxServerTransport) handleRawLoop() {
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

func (s *ParallaxServerTransport) handleMuxLoop() {
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

func (s *ParallaxServerTransport) handleMuxSession(session *smux.Session) {
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
