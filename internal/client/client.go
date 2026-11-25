package client

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/client/transport"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/network"

	"github.com/sirupsen/logrus"
)

type Client struct {
	config *config.ClientConfig
	ctx    context.Context
	cancel context.CancelFunc
	logger *logrus.Logger
}

func NewClient(cfg *config.ClientConfig, parentCtx context.Context) *Client {
	ctx, cancel := context.WithCancel(parentCtx)
	return &Client{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
		logger: utils.NewLogger(cfg.LogLevel),
	}
}

func (c *Client) Start() {
	if c.config.PPROF {
		go func() {
			c.logger.Info("pprof started at port 6061")
			http.ListenAndServe("0.0.0.0:6061", nil)
		}()
	}

	c.logger.Infof("client with remote address %s started successfully", c.config.RemoteAddr)

	switch c.config.Transport {
	case config.TCP:
		tcpConfig := &transport.TcpConfig{
			RemoteAddr:     c.config.RemoteAddr,
			Nodelay:        c.config.Nodelay,
			KeepAlive:      time.Duration(c.config.Keepalive) * time.Second,
			RetryInterval:  time.Duration(c.config.RetryInterval) * time.Second,
			DialTimeOut:    time.Duration(c.config.DialTimeout) * time.Second,
			ConnPoolSize:   c.config.ConnectionPool,
			Token:          c.config.Token,
			Sniffer:        c.config.Sniffer,
			WebPort:        c.config.WebPort,
			SnifferLog:     c.config.SnifferLog,
			AggressivePool: c.config.AggressivePool,
			MSS:            c.config.MSS,
			SO_RCVBUF:      c.config.SO_RCVBUF,
			SO_SNDBUF:      c.config.SO_SNDBUF,
		}
		tcpClient := transport.NewTCPClient(c.ctx, tcpConfig, c.logger)
		go tcpClient.Start()

	case config.TCPMUX:
		tcpMuxConfig := &transport.TcpMuxConfig{
			RemoteAddr:       c.config.RemoteAddr,
			Nodelay:          c.config.Nodelay,
			KeepAlive:        time.Duration(c.config.Keepalive) * time.Second,
			RetryInterval:    time.Duration(c.config.RetryInterval) * time.Second,
			DialTimeOut:      time.Duration(c.config.DialTimeout) * time.Second,
			ConnPoolSize:     c.config.ConnectionPool,
			Token:            c.config.Token,
			MuxVersion:       c.config.MuxVersion,
			MaxFrameSize:     c.config.MaxFrameSize,
			MaxReceiveBuffer: c.config.MaxReceiveBuffer,
			MaxStreamBuffer:  c.config.MaxStreamBuffer,
			Sniffer:          c.config.Sniffer,
			WebPort:          c.config.WebPort,
			SnifferLog:       c.config.SnifferLog,
			AggressivePool:   c.config.AggressivePool,
			MSS:              c.config.MSS,
			SO_RCVBUF:        c.config.SO_RCVBUF,
			SO_SNDBUF:        c.config.SO_SNDBUF,
		}
		tcpMuxClient := transport.NewMuxClient(c.ctx, tcpMuxConfig, c.logger)
		go tcpMuxClient.Start()

	case config.TLS, config.TLSMUX:
		tlsCfg := &transport.TlsClientConfig{
			RemoteAddr:       c.config.RemoteAddr,
			EdgeIP:           c.config.EdgeIP,
			SNI:              c.config.SNI,
			UTLSFingerprint:  c.config.UTLSFingerprint,
			TLSFragment:      c.config.TLSFragment,
			Token:            c.config.Token,
			SnifferLog:       c.config.SnifferLog,
			Nodelay:          c.config.Nodelay,
			Sniffer:          c.config.Sniffer,
			Mux:              c.config.Transport == config.TLSMUX,
			KeepAlive:        time.Duration(c.config.Keepalive) * time.Second,
			RetryInterval:    time.Duration(c.config.RetryInterval) * time.Second,
			DialTimeOut:      time.Duration(c.config.DialTimeout) * time.Second,
			ConnPoolSize:     c.config.ConnectionPool,
			WebPort:          c.config.WebPort,
			AggressivePool:   c.config.AggressivePool,
			MuxVersion:       c.config.MuxVersion,
			MaxFrameSize:     c.config.MaxFrameSize,
			MaxReceiveBuffer: c.config.MaxReceiveBuffer,
			MaxStreamBuffer:  c.config.MaxStreamBuffer,
			MSS:              c.config.MSS,
			SO_RCVBUF:        c.config.SO_RCVBUF,
			SO_SNDBUF:        c.config.SO_SNDBUF,
		}
		tlsClient := transport.NewTLSClient(c.ctx, tlsCfg, c.logger)
		go tlsClient.Start()

	case config.WS, config.WSS:
		WsConfig := &transport.WsConfig{
			RemoteAddr:      c.config.RemoteAddr,
			Nodelay:         c.config.Nodelay,
			KeepAlive:       time.Duration(c.config.Keepalive) * time.Second,
			RetryInterval:   time.Duration(c.config.RetryInterval) * time.Second,
			DialTimeOut:     time.Duration(c.config.DialTimeout) * time.Second,
			ConnPoolSize:    c.config.ConnectionPool,
			Token:           c.config.Token,
			Sniffer:         c.config.Sniffer,
			WebPort:         c.config.WebPort,
			SnifferLog:      c.config.SnifferLog,
			Mode:            c.config.Transport,
			AggressivePool:  c.config.AggressivePool,
			EdgeIP:          c.config.EdgeIP,
			SNI:             c.config.SNI,
			UTLSFingerprint: c.config.UTLSFingerprint,
			TLSFragment:     c.config.TLSFragment,
		}
		WsClient := transport.NewWSClient(c.ctx, WsConfig, c.logger)
		go WsClient.Start()

	case config.WSMUX, config.WSSMUX:
		wsMuxConfig := &transport.WsMuxConfig{
			RemoteAddr:       c.config.RemoteAddr,
			Nodelay:          c.config.Nodelay,
			KeepAlive:        time.Duration(c.config.Keepalive) * time.Second,
			RetryInterval:    time.Duration(c.config.RetryInterval) * time.Second,
			DialTimeOut:      time.Duration(c.config.DialTimeout) * time.Second,
			ConnPoolSize:     c.config.ConnectionPool,
			Token:            c.config.Token,
			MuxVersion:       c.config.MuxVersion,
			MaxFrameSize:     c.config.MaxFrameSize,
			MaxReceiveBuffer: c.config.MaxReceiveBuffer,
			MaxStreamBuffer:  c.config.MaxStreamBuffer,
			Sniffer:          c.config.Sniffer,
			WebPort:          c.config.WebPort,
			SnifferLog:       c.config.SnifferLog,
			Mode:             c.config.Transport,
			AggressivePool:   c.config.AggressivePool,
			EdgeIP:           c.config.EdgeIP,
			SNI:              c.config.SNI,
			UTLSFingerprint:  c.config.UTLSFingerprint,
			TLSFragment:      c.config.TLSFragment,
		}
		wsMuxClient := transport.NewWSMuxClient(c.ctx, wsMuxConfig, c.logger)
		go wsMuxClient.Start()

	case config.UDP:
		udpConfig := &transport.UdpConfig{
			RemoteAddr:     c.config.RemoteAddr,
			RetryInterval:  time.Duration(c.config.RetryInterval) * time.Second,
			DialTimeOut:    time.Duration(c.config.DialTimeout) * time.Second,
			ConnPoolSize:   c.config.ConnectionPool,
			Token:          c.config.Token,
			Sniffer:        c.config.Sniffer,
			WebPort:        c.config.WebPort,
			SnifferLog:     c.config.SnifferLog,
			AggressivePool: c.config.AggressivePool,
		}
		udpClient := transport.NewUDPClient(c.ctx, udpConfig, c.logger)
		go udpClient.Start()

	case config.KCP, config.KCPMUX:
		kcpCfg := &transport.KcpClientConfig{
			RemoteAddr:       c.config.RemoteAddr,
			Token:            c.config.Token,
			SnifferLog:       c.config.SnifferLog,
			KeepAlive:        time.Duration(c.config.Keepalive) * time.Second,
			RetryInterval:    time.Duration(c.config.RetryInterval) * time.Second,
			DialTimeOut:      time.Duration(c.config.DialTimeout) * time.Second,
			ConnPoolSize:     c.config.ConnectionPool,
			WebPort:          c.config.WebPort,
			Sniffer:          c.config.Sniffer,
			AggressivePool:   c.config.AggressivePool,
			Mux:              c.config.Transport == config.KCPMUX,
			MuxVersion:       c.config.MuxVersion,
			MaxFrameSize:     c.config.MaxFrameSize,
			MaxReceiveBuffer: c.config.MaxReceiveBuffer,
			MaxStreamBuffer:  c.config.MaxStreamBuffer,
			SO_RCVBUF:        c.config.SO_RCVBUF,
			SO_SNDBUF:        c.config.SO_SNDBUF,
			MSS:              c.config.MSS,
			KCP: network.KCPParams{
				Mode:        c.config.KCPMode,
				Key:         c.config.KCPKey,
				Crypt:       c.config.KCPCrypt,
				DataShard:   c.config.KCPDataShard,
				ParityShard: c.config.KCPParityShard,
				MTU:         c.config.KCPMTU,
				SndWnd:      c.config.KCPSndWnd,
				RcvWnd:      c.config.KCPRcvWnd,
				NoDelay:     c.config.KCPNoDelay,
				Interval:    c.config.KCPInterval,
				Resend:      c.config.KCPResend,
				NC:          c.config.KCPNC,
				AckNoDelay:  c.config.KCPAcksNoDelay,
				DSCP:        c.config.KCPDSCP,
				SO_RCVBUF:   c.config.SO_RCVBUF,
				SO_SNDBUF:   c.config.SO_SNDBUF,
			},
		}
		kcpClient := transport.NewKCPClient(c.ctx, kcpCfg, c.logger)
		go kcpClient.Start()

	case config.XHTTP, config.XHTTPS, config.XHTTPMUX, config.XHTTPSMUX:
		xhttpCfg := &transport.XhttpClientConfig{
			RemoteAddr:       c.config.RemoteAddr,
			Token:            c.config.Token,
			SnifferLog:       c.config.SnifferLog,
			Nodelay:          c.config.Nodelay,
			Sniffer:          c.config.Sniffer,
			KeepAlive:        time.Duration(c.config.Keepalive) * time.Second,
			RetryInterval:    time.Duration(c.config.RetryInterval) * time.Second,
			DialTimeOut:      time.Duration(c.config.DialTimeout) * time.Second,
			ConnPoolSize:     c.config.ConnectionPool,
			WebPort:          c.config.WebPort,
			Mode:             c.config.Transport,
			AggressivePool:   c.config.AggressivePool,
			EdgeIP:           c.config.EdgeIP,
			SNI:              c.config.SNI,
			UTLSFingerprint:  c.config.UTLSFingerprint,
			TLSFragment:      c.config.TLSFragment,
			MuxVersion:       c.config.MuxVersion,
			MaxFrameSize:     c.config.MaxFrameSize,
			MaxReceiveBuffer: c.config.MaxReceiveBuffer,
			MaxStreamBuffer:  c.config.MaxStreamBuffer,
			XHTTPPath:        c.config.XHTTPPath,
			XHTTPHost:        c.config.XHTTPHost,
			XHTTPMode:        c.config.XHTTPMode,
		}
		xhttpClient := transport.NewXHTTPClient(c.ctx, xhttpCfg, c.logger)
		go xhttpClient.Start()

	default:
		c.logger.Fatal("invalid transport type: ", c.config.Transport)
	}

	<-c.ctx.Done()
	c.logger.Info("all workers stopped successfully")
}

func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}
