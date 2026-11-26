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
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsTransport struct {
	config         *WsConfig
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan TunnelChannel
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	ctrlMu         sync.Mutex
	controlChannel *websocket.Conn
	restartMutex   sync.Mutex
	usageMonitor   *web.Usage
}

type WsConfig struct {
	BindAddr     string
	SnifferLog   string
	TLSCertFile  string
	TLSKeyFile   string
	SNI          string
	TunnelStatus string
	Token        string
	Ports        []string
	Nodelay      bool
	Sniffer      bool
	KeepAlive    time.Duration
	Heartbeat    time.Duration
	ChannelSize  int
	WebPort      int
	Mode         config.TransportType
}

func NewWSServer(parentCtx context.Context, config *WsConfig, logger *logrus.Logger) *WsTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	return &WsTransport{
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan TunnelChannel, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		controlChannel: nil,
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
	}
}

func (s *WsTransport) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}
	s.usageMonitor.SetStatus(fmt.Sprintf("Disconnected (%s)", s.config.Mode))
	go s.tunnelListener()
}

func (s *WsTransport) Restart() {
	if !s.restartMutex.TryLock() {
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Infof("restarting %s server...", s.config.Mode)
	s.closeControl(true)
	if s.cancel != nil {
		s.cancel()
	}
	time.Sleep(1500 * time.Millisecond)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel
	s.tunnelChannel = make(chan TunnelChannel, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.setControl(nil)
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.usageMonitor.SetStatus("")

	go s.Start()
}

func (s *WsTransport) channelHandler() {
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
				_, msg, err := cc.ReadMessage()
				if err != nil {
					if s.ctx.Err() == nil {
						s.logger.Warnf("ws control channel closed: %v", err)
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
			_ = s.writeControl(websocket.BinaryMessage, []byte{utils.SG_Closed})
			return
		case <-s.reqNewConnChan:
			if err := s.writeControl(websocket.BinaryMessage, []byte{utils.SG_Chan}); err != nil {
				go s.Restart()
				return
			}
		case <-ticker.C:
			if err := s.writeControl(websocket.BinaryMessage, []byte{utils.SG_HB}); err != nil {
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

func (s *WsTransport) tunnelListener() {
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
				if s.getControl() != nil {
					s.logger.Warn("new ws control channel requested, restarting...")
					s.closeControl(false)
					conn.Close()
					go s.Restart()
					return
				}
				s.setControl(conn)
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
				s.usageMonitor.SetStatus(fmt.Sprintf("Connected (%s)", s.config.Mode))
			} else if strings.HasPrefix(r.URL.Path, "/tunnel") {
				wsConn := TunnelChannel{
					conn: conn,
					ping: make(chan struct{}),
					mu:   &sync.Mutex{},
				}
				select {
				case s.tunnelChannel <- wsConn:
					go s.keepAlive(&wsConn)
				default:
					conn.Close()
				}
			} else {
				conn.Close()
			}
		}),
	}

	if s.config.Mode == config.WS {
		go func() {
			s.logger.Infof("ws server starting, listening on %s", addr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Errorf("failed to listen on %s: %v", addr, err)
			}
		}()
	} else {
		go func() {
			s.logger.Infof("wss server starting, listening on %s (Auto-TLS=%v)", addr, s.config.TLSCertFile == "")
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
	s.closeControl(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	_ = server.Close()
}

func (s *WsTransport) parsePortMappings() {
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

func (s *WsTransport) localListener(localAddr, remoteAddr string) {
	var portListener net.Listener
	var err error
	for attempt := 0; attempt < 6; attempt++ {
		portListener, err = net.Listen("tcp", localAddr)
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
	defer portListener.Close()
	s.logger.Infof("listener started successfully on %s", portListener.Addr().String())

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				conn, err := portListener.Accept()
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
					select {
					case s.reqNewConnChan <- struct{}{}:
					default:
					}
				default:
					conn.Close()
				}
			}
		}
	}()

	<-s.ctx.Done()
}

func (s *WsTransport) handleLoop() {
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
				case tunnelConnection := <-s.tunnelChannel:
					close(tunnelConnection.ping)
					tunnelConnection.mu.Lock()
					err := tunnelConnection.conn.WriteMessage(websocket.TextMessage, []byte(localConn.remoteAddr))
					tunnelConnection.mu.Unlock()
					if err != nil {
						tunnelConnection.conn.Close()
						continue loop
					}
					go handlers.WSConnectionHandler(s.ctx, tunnelConnection.conn, localConn.conn, s.logger, s.usageMonitor, handlers.LocalPortOf(localConn.conn), s.config.Sniffer)
					break loop
				}
			}
		}
	}
}

func (s *WsTransport) keepAlive(conn *TunnelChannel) {
	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			conn.conn.Close()
			return
		case <-conn.ping:
			return
		case <-ticker.C:
			if !conn.mu.TryLock() {
				return
			}
			if err := conn.conn.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Ping}); err != nil {
				conn.mu.Unlock()
				conn.conn.Close()
				return
			}
			conn.mu.Unlock()
		}
	}
}


func (s *WsTransport) getControl() *websocket.Conn {
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	return s.controlChannel
}

func (s *WsTransport) setControl(conn *websocket.Conn) {
	s.ctrlMu.Lock()
	s.controlChannel = conn
	s.ctrlMu.Unlock()
}

func (s *WsTransport) writeControl(msgType int, data []byte) error {
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	if s.controlChannel == nil {
		return websocket.ErrCloseSent
	}
	_ = s.controlChannel.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return s.controlChannel.WriteMessage(msgType, data)
}

func (s *WsTransport) closeControl(sendFarewell bool) {
	s.ctrlMu.Lock()
	cc := s.controlChannel
	if cc != nil {
		if sendFarewell {
			_ = cc.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
			_ = cc.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
		}
		_ = cc.Close()
		s.controlChannel = nil
	}
	s.ctrlMu.Unlock()
}

func (s *WsTransport) Status() string { return s.usageMonitor.GetStatus() }
