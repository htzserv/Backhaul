package server

import (
	"context"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/server/transport"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/network"

	"github.com/sirupsen/logrus"
)

type Server struct {
	config   *config.ServerConfig
	ctx      context.Context
	cancel   context.CancelFunc
	logger   *logrus.Logger
	statusMu sync.RWMutex
	statusFn func() string
}

func (s *Server) setStatusFn(fn func() string) {
	s.statusMu.Lock()
	s.statusFn = fn
	s.statusMu.Unlock()
}

func (s *Server) IsConnected() bool {
	if s == nil {
		return false
	}
	s.statusMu.RLock()
	fn := s.statusFn
	s.statusMu.RUnlock()
	if fn == nil {
		return false
	}
	return strings.HasPrefix(fn(), "Connected")
}

func NewServer(cfg *config.ServerConfig, parentCtx context.Context) *Server {
	ctx, cancel := context.WithCancel(parentCtx)
	return &Server{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
		logger: utils.NewLogger(cfg.LogLevel),
	}
}

func (s *Server) Start() {
	if s.config.PPROF {
		go func() {
			s.logger.Info("pprof started at port 6060")
			_ = http.ListenAndServe("0.0.0.0:6060", nil)
		}()
	}

	if s.config.GameMode && len(s.config.GamePorts) > 0 {
		bh, bp, _ := net.SplitHostPort(s.config.BindAddr)
		gBase := s.config.GameBasePort
		if gBase <= 0 {
			p, _ := strconv.Atoi(bp)
			gBase = p + 10
		}
		go network.StartGameModeServer(s.ctx, network.GameModeConfig{
			Token:    s.config.Token,
			BindHost: bh,
			BasePort: gBase,
			Copies:   s.config.GameCopies,
			Ports:    s.config.GamePorts,
		}, s.logger)
	}

	switch s.config.Transport {
	case config.TCP:
		tcpConfig := &transport.TcpConfig{
			BindAddr:      s.config.BindAddr,
			Nodelay:       s.config.Nodelay,
			KeepAlive:     time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:     time.Duration(s.config.Heartbeat) * time.Second,
			Token:         s.config.Token,
			ChannelSize:   s.config.ChannelSize,
			Ports:         s.config.Ports,
			Sniffer:       s.config.Sniffer,
			WebPort:       s.config.WebPort,
			SnifferLog:    s.config.SnifferLog,
			AcceptUDP:     s.config.AcceptUDP,
			MSS:           s.config.MSS,
			SO_RCVBUF:     s.config.SO_RCVBUF,
			SO_SNDBUF:     s.config.SO_SNDBUF,
			ProxyProtocol: s.config.ProxyProtocol,
		}
		tcpServer := transport.NewTCPServer(s.ctx, tcpConfig, s.logger)
		s.setStatusFn(tcpServer.Status)
		go tcpServer.Start()

	case config.TCPMUX:
		tcpMuxConfig := &transport.TcpMuxConfig{
			BindAddr:         s.config.BindAddr,
			Nodelay:          s.config.Nodelay,
			KeepAlive:        time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:        time.Duration(s.config.Heartbeat) * time.Second,
			Token:            s.config.Token,
			ChannelSize:      s.config.ChannelSize,
			Ports:            s.config.Ports,
			MuxCon:           s.config.MuxCon,
			MuxVersion:       s.config.MuxVersion,
			MaxFrameSize:     s.config.MaxFrameSize,
			MaxReceiveBuffer: s.config.MaxReceiveBuffer,
			MaxStreamBuffer:  s.config.MaxStreamBuffer,
			Sniffer:          s.config.Sniffer,
			WebPort:          s.config.WebPort,
			SnifferLog:       s.config.SnifferLog,
			MSS:              s.config.MSS,
			SO_RCVBUF:        s.config.SO_RCVBUF,
			SO_SNDBUF:        s.config.SO_SNDBUF,
			ProxyProtocol:    s.config.ProxyProtocol,
		}
		tcpMuxServer := transport.NewTcpMuxServer(s.ctx, tcpMuxConfig, s.logger)
		s.setStatusFn(tcpMuxServer.Status)
		go tcpMuxServer.Start()

	case config.TLS, config.TLSMUX:
		tlsCfg := &transport.TlsServerConfig{
			BindAddr:         s.config.BindAddr,
			Token:            s.config.Token,
			SnifferLog:       s.config.SnifferLog,
			TLSCertFile:      s.config.TLSCertFile,
			TLSKeyFile:       s.config.TLSKeyFile,
			SNI:              s.config.SNI,
			Ports:            s.config.Ports,
			Nodelay:          s.config.Nodelay,
			Sniffer:          s.config.Sniffer,
			Mux:              s.config.Transport == config.TLSMUX,
			KeepAlive:        time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:        time.Duration(s.config.Heartbeat) * time.Second,
			ChannelSize:      s.config.ChannelSize,
			MuxCon:           s.config.MuxCon,
			MuxVersion:       s.config.MuxVersion,
			MaxFrameSize:     s.config.MaxFrameSize,
			MaxReceiveBuffer: s.config.MaxReceiveBuffer,
			MaxStreamBuffer:  s.config.MaxStreamBuffer,
			WebPort:          s.config.WebPort,
			MSS:              s.config.MSS,
			SO_RCVBUF:        s.config.SO_RCVBUF,
			SO_SNDBUF:        s.config.SO_SNDBUF,
			ProxyProtocol:    s.config.ProxyProtocol,
			AcceptUDP:        s.config.AcceptUDP,
		}
		tlsServer := transport.NewTLSServer(s.ctx, tlsCfg, s.logger)
		s.setStatusFn(tlsServer.Status)
		go tlsServer.Start()

	case config.WS, config.WSS:
		wsConfig := &transport.WsConfig{
			BindAddr:    s.config.BindAddr,
			Nodelay:     s.config.Nodelay,
			KeepAlive:   time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:   time.Duration(s.config.Heartbeat) * time.Second,
			Token:       s.config.Token,
			ChannelSize: s.config.ChannelSize,
			Ports:       s.config.Ports,
			Sniffer:     s.config.Sniffer,
			WebPort:     s.config.WebPort,
			SnifferLog:  s.config.SnifferLog,
			Mode:        s.config.Transport,
			TLSCertFile: s.config.TLSCertFile,
			TLSKeyFile:  s.config.TLSKeyFile,
			SNI:         s.config.SNI,
		}
		wsServer := transport.NewWSServer(s.ctx, wsConfig, s.logger)
		s.setStatusFn(wsServer.Status)
		go wsServer.Start()

	case config.WSMUX, config.WSSMUX:
		wsMuxConfig := &transport.WsMuxConfig{
			BindAddr:         s.config.BindAddr,
			Nodelay:          s.config.Nodelay,
			KeepAlive:        time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:        time.Duration(s.config.Heartbeat) * time.Second,
			Token:            s.config.Token,
			ChannelSize:      s.config.ChannelSize,
			Ports:            s.config.Ports,
			MuxCon:           s.config.MuxCon,
			MuxVersion:       s.config.MuxVersion,
			MaxFrameSize:     s.config.MaxFrameSize,
			MaxReceiveBuffer: s.config.MaxReceiveBuffer,
			MaxStreamBuffer:  s.config.MaxStreamBuffer,
			Sniffer:          s.config.Sniffer,
			WebPort:          s.config.WebPort,
			SnifferLog:       s.config.SnifferLog,
			Mode:             s.config.Transport,
			TLSCertFile:      s.config.TLSCertFile,
			TLSKeyFile:       s.config.TLSKeyFile,
			SNI:              s.config.SNI,
			ProxyProtocol:    s.config.ProxyProtocol,
		}
		wsMuxServer := transport.NewWSMuxServer(s.ctx, wsMuxConfig, s.logger)
		s.setStatusFn(wsMuxServer.Status)
		go wsMuxServer.Start()

	case config.UDP:
		udpConfig := &transport.UdpConfig{
			BindAddr:    s.config.BindAddr,
			Heartbeat:   time.Duration(s.config.Heartbeat) * time.Second,
			Token:       s.config.Token,
			ChannelSize: s.config.ChannelSize,
			Ports:       s.config.Ports,
			Sniffer:     s.config.Sniffer,
			WebPort:     s.config.WebPort,
			SnifferLog:  s.config.SnifferLog,
		}
		udpServer := transport.NewUDPServer(s.ctx, udpConfig, s.logger)
		s.setStatusFn(udpServer.Status)
		go udpServer.Start()

	case config.KCP, config.KCPMUX:
		kcpCfg := &transport.KcpServerConfig{
			BindAddr:         s.config.BindAddr,
			Token:            s.config.Token,
			SnifferLog:       s.config.SnifferLog,
			Ports:            s.config.Ports,
			Sniffer:          s.config.Sniffer,
			Mux:              s.config.Transport == config.KCPMUX,
			MuxCon:           s.config.MuxCon,
			MuxVersion:       s.config.MuxVersion,
			MaxFrameSize:     s.config.MaxFrameSize,
			MaxReceiveBuffer: s.config.MaxReceiveBuffer,
			MaxStreamBuffer:  s.config.MaxStreamBuffer,
			Heartbeat:        time.Duration(s.config.Heartbeat) * time.Second,
			ChannelSize:      s.config.ChannelSize,
			WebPort:          s.config.WebPort,
			ProxyProtocol:    s.config.ProxyProtocol,
			AcceptUDP:        s.config.AcceptUDP,
			KCP: network.KCPParams{
				Mode:            s.config.KCPMode,
				Key:             s.config.KCPKey,
				Crypt:           s.config.KCPCrypt,
				DataShard:       s.config.KCPDataShard,
				ParityShard:     s.config.KCPParityShard,
				MTU:             s.config.KCPMTU,
				SndWnd:          s.config.KCPSndWnd,
				RcvWnd:          s.config.KCPRcvWnd,
				NoDelay:         s.config.KCPNoDelay,
				Interval:        s.config.KCPInterval,
				Resend:          s.config.KCPResend,
				NC:              s.config.KCPNC,
				AckNoDelay:      s.config.KCPAcksNoDelay,
				DSCP:            s.config.KCPDSCP,
				SO_RCVBUF:       s.config.SO_RCVBUF,
				SO_SNDBUF:       s.config.SO_SNDBUF,
				PortHopRange:    s.config.PortHopRange,
				PortHopInterval: s.config.PortHopInterval,
			},
		}
		kcpServer := transport.NewKCPServer(s.ctx, kcpCfg, s.logger)
		s.setStatusFn(kcpServer.Status)
		go kcpServer.Start()

	case config.XHTTP, config.XHTTPS, config.XHTTPMUX, config.XHTTPSMUX:
		xhttpCfg := &transport.XhttpServerConfig{
			BindAddr:         s.config.BindAddr,
			Token:            s.config.Token,
			SnifferLog:       s.config.SnifferLog,
			TLSCertFile:      s.config.TLSCertFile,
			TLSKeyFile:       s.config.TLSKeyFile,
			SNI:              s.config.SNI,
			Ports:            s.config.Ports,
			Sniffer:          s.config.Sniffer,
			KeepAlive:        time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:        time.Duration(s.config.Heartbeat) * time.Second,
			ChannelSize:      s.config.ChannelSize,
			MuxCon:           s.config.MuxCon,
			MuxVersion:       s.config.MuxVersion,
			MaxFrameSize:     s.config.MaxFrameSize,
			MaxReceiveBuffer: s.config.MaxReceiveBuffer,
			MaxStreamBuffer:  s.config.MaxStreamBuffer,
			WebPort:          s.config.WebPort,
			Mode:             s.config.Transport,
			ProxyProtocol:    s.config.ProxyProtocol,
			FallbackAddr:     s.config.FallbackAddr,
			XHTTPPath:        s.config.XHTTPPath,
			XHTTPHost:        s.config.XHTTPHost,
		}
		xhttpServer := transport.NewXHTTPServer(s.ctx, xhttpCfg, s.logger)
		s.setStatusFn(xhttpServer.Status)
		go xhttpServer.Start()

	case config.PARALLAX, config.PARALLAXMUX:
		pxCfg := &transport.ParallaxServerConfig{
			BindAddr:         s.config.BindAddr,
			Token:            s.config.Token,
			SnifferLog:       s.config.SnifferLog,
			Ports:            s.config.Ports,
			Nodelay:          s.config.Nodelay,
			Sniffer:          s.config.Sniffer,
			Mux:              s.config.Transport == config.PARALLAXMUX,
			KeepAlive:        time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:        time.Duration(s.config.Heartbeat) * time.Second,
			ChannelSize:      s.config.ChannelSize,
			MuxCon:           s.config.MuxCon,
			MuxVersion:       s.config.MuxVersion,
			MaxFrameSize:     s.config.MaxFrameSize,
			MaxReceiveBuffer: s.config.MaxReceiveBuffer,
			MaxStreamBuffer:  s.config.MaxStreamBuffer,
			WebPort:          s.config.WebPort,
			ProxyProtocol:    s.config.ProxyProtocol,
			AcceptUDP:        s.config.AcceptUDP,
			Parallax: network.ParallaxParams{
				Token:     s.config.Token,
				Lanes:     s.config.ParallaxLanes,
				WarmupMin: s.config.ParallaxWarmupMin,
				WarmupMax: s.config.ParallaxWarmupMax,
				StallSec:  s.config.ParallaxStallSec,
				KeepAlive: time.Duration(s.config.Keepalive) * time.Second,
				NoDelay:   s.config.Nodelay,
				KCP: network.KCPParams{
					Mode:        s.config.KCPMode,
					Key:         s.config.KCPKey,
					Crypt:       s.config.KCPCrypt,
					DataShard:   s.config.KCPDataShard,
					ParityShard: s.config.KCPParityShard,
					MTU:         s.config.KCPMTU,
					SndWnd:      s.config.KCPSndWnd,
					RcvWnd:      s.config.KCPRcvWnd,
					AckNoDelay:  s.config.KCPAcksNoDelay,
					SO_RCVBUF:   s.config.SO_RCVBUF,
					SO_SNDBUF:   s.config.SO_SNDBUF,
				},
			},
		}
		pxServer := transport.NewParallaxServer(s.ctx, pxCfg, s.logger)
		s.setStatusFn(pxServer.Status)
		go pxServer.Start()

	case config.FAILOVER:
		go s.startFailover()

	default:
		s.logger.Errorf("invalid transport type: %s", s.config.Transport)
		return
	}

	<-s.ctx.Done()
	s.logger.Info("all workers stopped successfully")
}

func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}
