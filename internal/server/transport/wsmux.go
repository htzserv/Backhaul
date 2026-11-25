package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"
	"github.com/xtaci/smux"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsMuxTransport struct {
	config         *WsMuxConfig
	smuxConfig     *smux.Config
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan *smux.Session
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel *websocket.Conn
	usageMonitor   *web.Usage
	restartMutex   sync.Mutex
	streamCounter  int32
	sessionCounter int32
}

type WsMuxConfig struct {
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
	KeepAlive        time.Duration
	Heartbeat        time.Duration
	ChannelSize      int
	MuxCon           int
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	WebPort          int
	Mode             config.TransportType
	ProxyProtocol    bool
}

func NewWSMuxServer(parentCtx context.Context, config *WsMuxConfig, logger *logrus.Logger) *WsMuxTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	return &WsMuxTransport{
		smuxConfig: &smux.Config{
			Version:           config.MuxVersion,
			KeepAliveInterval: 20 * time.Second,
			KeepAliveTimeout:  40 * time.Second,
			MaxFrameSize:      config.MaxFrameSize,
			MaxReceiveBuffer:  config.MaxReceiveBuffer,
			MaxStreamBuffer:   config.MaxStreamBuffer,
		},
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan *smux.Session, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
	}
}

func (s *WsMuxTransport) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}
	s.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", s.config.Mode)
	go s.tunnelListener()
}

func (s *WsMuxTransport) Restart() {
	if !s.restartMutex.TryLock() {
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Infof("restarting %s server...", s.config.Mode)
	if s.controlChannel != nil {
		_ = s.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
		_ = s.controlChannel.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
	time.Sleep(1500 * time.Millisecond)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel
	s.tunnelChannel = make(chan *smux.Session, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel = nil
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.config.TunnelStatus = ""
	atomic.StoreInt32(&s.streamCounter, 0)
	atomic.StoreInt32(&s.sessionCounter, 0)

	go s.Start()
}

func (s *WsMuxTransport) channelHandler() {
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
				_ = s.controlChannel.SetReadDeadline(time.Now().Add(readTimeout))
				_, msg, err := s.controlChannel.ReadMessage()
				if err != nil {
					if s.ctx.Err() == nil {
						s.logger.Warnf("wsmux control channel closed: %v", err)
						go s.Restart()
					}
					return
				}
				if len(msg) == 0 {
					continue
				}
				messageChan <- msg[0]
			}
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			_ = s.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
			return
		case <-s.reqNewConnChan:
			if err := s.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Chan}); err != nil {
				go s.Restart()
				return
			}
		case <-ticker.C:
			if err := s.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_HB}); err != nil {
				go s.Restart()
				return
			}
		case msg, ok := <-messageChan:
			if !ok {
				return
			}
			switch msg {
			case utils.SG_HB:
			case utils.SG_Closed:
				go s.Restart()
				return
			default:
				go s.Restart()
				return
			}
		}
	}
}

func (s *WsMuxTransport) tunnelListener() {
	addr := s.config.BindAddr
	upgrader := websocket.Upgrader{
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  32 * 1024,
		HandshakeTimeout: 30 * time.Second,
		CheckOrigin:      func(r *http.Request) bool { return true },
	}

	server := &http.Server{
		Addr:        addr,
		IdleTimeout: 0,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != fmt.Sprintf("Bearer %v", s.config.Token) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}

			if r.URL.Path == "/channel" {
				if s.controlChannel != nil {
					s.logger.Warn("new wsmux control channel requested, restarting...")
					s.controlChannel.Close()
					conn.Close()
					go s.Restart()
					return
				}
				s.controlChannel = conn
				s.logger.Infof("%s control channel established successfully", s.config.Mode)

				numCPU := runtime.NumCPU()
				if numCPU > 4 {
					numCPU = 4
				}
				go s.channelHandler()
				go s.parsePortMappings()
				for i := 0; i < numCPU; i++ {
					go s.handleLoop()
				}
				s.config.TunnelStatus = fmt.Sprintf("Connected (%s)", s.config.Mode)
			} else if strings.HasPrefix(r.URL.Path, "/tunnel") {
				session, err := smux.Client(network.NewWSNetConn(conn), s.smuxConfig)
				if err != nil {
					conn.Close()
					return
				}
				select {
				case s.tunnelChannel <- session:
				default:
					session.Close()
				}
			} else {
				conn.Close()
			}
		}),
	}

	if s.config.Mode == config.WSMUX {
		go func() {
			s.logger.Infof("%s server starting, listening on %s", s.config.Mode, addr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Errorf("failed to listen on %s: %v", addr, err)
			}
		}()
	} else {
		go func() {
			s.logger.Infof("%s server starting, listening on %s (Auto-TLS=%v)", s.config.Mode, addr, s.config.TLSCertFile == "")
			tlsCfg, tErr := network.LoadOrGenerateTLSConfig(s.config.TLSCertFile, s.config.TLSKeyFile, s.config.SNI, []string{"http/1.1"})
			if tErr != nil {
				s.logger.Errorf("failed to load/generate TLS config: %v", tErr)
				return
			}
			server.TLSConfig = tlsCfg
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				s.logger.Errorf("failed to listen on %s: %v", addr, err)
			}
		}()
	}

	<-s.ctx.Done()
	if s.controlChannel != nil {
		s.controlChannel.Close()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	_ = server.Close()
}

func (s *WsMuxTransport) parsePortMappings() {
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

func (s *WsMuxTransport) localListener(localAddr, remoteAddr string) {
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
		s.logger.Errorf("failed to start listener on %s: %v", localAddr, err)
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
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					_ = tcpConn.SetNoDelay(s.config.Nodelay)
					_ = tcpConn.SetKeepAlive(true)
					_ = tcpConn.SetKeepAlivePeriod(s.config.KeepAlive)
				}
				select {
				case s.localChannel <- LocalTCPConn{conn: conn, remoteAddr: remoteAddr, timeCreated: time.Now().UnixMilli()}:
					atomic.AddInt32(&s.streamCounter, 1)
					if atomic.LoadInt32(&s.streamCounter) >= atomic.LoadInt32(&s.sessionCounter)*int32(s.config.MuxCon) {
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

func (s *WsMuxTransport) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case session := <-s.tunnelChannel:
			atomic.AddInt32(&s.sessionCounter, 1)
			go s.handleSession(session)
		}
	}
}

func (s *WsMuxTransport) handleSession(session *smux.Session) {
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
