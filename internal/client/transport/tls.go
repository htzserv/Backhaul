package transport

import (
	"context"
	"fmt"
	"net"
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

type TlsClientConfig struct {
	RemoteAddr       string
	EdgeIP           string
	SNI              string
	UTLSFingerprint  string
	TLSFragment      bool
	Token            string
	SnifferLog       string
	TunnelStatus     string
	Nodelay          bool
	Sniffer          bool
	Mux              bool
	KeepAlive        time.Duration
	RetryInterval    time.Duration
	DialTimeOut      time.Duration
	ConnPoolSize     int
	WebPort          int
	AggressivePool   bool
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	MSS              int
	SO_RCVBUF        int
	SO_SNDBUF        int
}

type TlsClientTransport struct {
	config          *TlsClientConfig
	smuxConfig      *smux.Config
	parentctx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlMu       sync.RWMutex
	controlChannel  net.Conn
	usageMonitor    *web.Usage
	restartMutex    sync.Mutex
	poolConnections int32
	loadConnections int32
	controlFlow     chan struct{}
}

func NewTLSClient(parentCtx context.Context, cfg *TlsClientConfig, logger *logrus.Logger) *TlsClientTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	return &TlsClientTransport{
		smuxConfig: &smux.Config{
			Version:           cfg.MuxVersion,
			KeepAliveInterval: 20 * time.Second,
			KeepAliveTimeout:  40 * time.Second,
			MaxFrameSize:      cfg.MaxFrameSize,
			MaxReceiveBuffer:  cfg.MaxReceiveBuffer,
			MaxStreamBuffer:   cfg.MaxStreamBuffer,
		},
		config:       cfg,
		parentctx:    parentCtx,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", cfg.WebPort), ctx, cfg.SnifferLog, cfg.Sniffer, &cfg.TunnelStatus, logger),
		controlFlow:  make(chan struct{}, 100),
	}
}

func (c *TlsClientTransport) modeLabel() string {
	if c.config.Mux {
		return "TLSMUX"
	}
	return "TLS"
}

func (c *TlsClientTransport) getControl() net.Conn {
	c.controlMu.RLock()
	defer c.controlMu.RUnlock()
	return c.controlChannel
}

func (c *TlsClientTransport) setControl(conn net.Conn) {
	c.controlMu.Lock()
	c.controlChannel = conn
	c.controlMu.Unlock()
}

func (c *TlsClientTransport) Start() {
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}
	c.usageMonitor.SetStatus(fmt.Sprintf("Disconnected (%s)", c.modeLabel()))
	go c.channelDialer()
}

func (c *TlsClientTransport) Restart() {
	if !c.restartMutex.TryLock() {
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Infof("restarting %s client...", c.modeLabel())
	if cc := c.getControl(); cc != nil {
		_ = cc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		_ = utils.SendBinaryByte(cc, utils.SG_Closed)
		_ = cc.Close()
	}
	if c.cancel != nil {
		c.cancel()
	}
	time.Sleep(1500 * time.Millisecond)

	ctx, cancel := context.WithCancel(c.parentctx)
	c.ctx = ctx
	c.cancel = cancel
	c.setControl(nil)
	c.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", c.config.WebPort), ctx, c.config.SnifferLog, c.config.Sniffer, &c.config.TunnelStatus, c.logger)
	atomic.StoreInt32(&c.poolConnections, 0)
	atomic.StoreInt32(&c.loadConnections, 0)
	c.controlFlow = make(chan struct{}, 100)

	go c.Start()
}

func (c *TlsClientTransport) dialTLS(nodelay bool, rcvBuf, sndBuf, mss int, retry int) (net.Conn, error) {
	dialAddr := c.config.RemoteAddr
	if c.config.EdgeIP != "" {
		_, port, err := net.SplitHostPort(c.config.RemoteAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid remote_addr: %w", err)
		}
		dialAddr = net.JoinHostPort(network.PickEdgeIP(c.config.EdgeIP), port)
	}

	rawConn, err := network.TcpDialer(c.ctx, dialAddr, "", c.config.DialTimeOut, c.config.KeepAlive, nodelay, retry, rcvBuf, sndBuf, mss)
	if err != nil {
		return nil, err
	}

	sni := c.config.SNI
	if sni == "" {
		sni = c.config.RemoteAddr
	}
	hsCtx, cancel := context.WithTimeout(c.ctx, c.config.DialTimeOut)
	defer cancel()
	return network.DialUTLSFragmented(hsCtx, rawConn, sni, c.config.UTLSFingerprint, []string{"http/1.1", "h2"}, c.config.TLSFragment)
}

func (c *TlsClientTransport) channelDialer() {
	c.logger.Infof("attempting to establish %s control channel to %s (SNI=%s, uTLS=%s, frag=%v)...", c.modeLabel(), c.config.RemoteAddr, c.config.SNI, c.config.UTLSFingerprint, c.config.TLSFragment)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			conn, err := c.dialTLS(true, 0, 0, 0, 2)
			if err != nil {
				c.logger.Errorf("%s channel dialer: %v", c.modeLabel(), err)
				time.Sleep(c.config.RetryInterval)
				continue
			}

			if err := utils.SendBinaryTransportString(conn, c.config.Token, utils.SG_Chan); err != nil {
				conn.Close()
				time.Sleep(c.config.RetryInterval)
				continue
			}

			_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
			msg, _, err := utils.ReceiveBinaryTransportString(conn)
			if err != nil || msg != c.config.Token {
				conn.Close()
				time.Sleep(c.config.RetryInterval)
				continue
			}
			_ = conn.SetReadDeadline(time.Time{})

			c.setControl(conn)
			c.logger.Infof("%s control channel established successfully", c.modeLabel())
			c.usageMonitor.SetStatus(fmt.Sprintf("Connected (%s)", c.modeLabel()))

			go c.poolMaintainer()
			go c.channelHandler()
			return
		}
	}
}

func (c *TlsClientTransport) poolMaintainer() {
	for i := 0; i < c.config.ConnPoolSize; i++ {
		go c.tunnelDialer()
	}

	a, b, x, y := 4, 5, 3, 4.0
	if c.config.AggressivePool {
		a, b, x, y = 1, 2, 0, 0.75
	}

	tickerPool := time.NewTicker(1 * time.Second)
	defer tickerPool.Stop()
	tickerLoad := time.NewTicker(10 * time.Second)
	defer tickerLoad.Stop()

	newPoolSize := c.config.ConnPoolSize
	var poolConnectionsSum int32

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-tickerPool.C:
			atomic.AddInt32(&poolConnectionsSum, atomic.LoadInt32(&c.poolConnections))
		case <-tickerLoad.C:
			loadConnections := (int(atomic.LoadInt32(&c.loadConnections)) + 9) / 10
			atomic.StoreInt32(&c.loadConnections, 0)
			poolConnectionsAvg := (int(atomic.LoadInt32(&poolConnectionsSum)) + 9) / 10
			atomic.StoreInt32(&poolConnectionsSum, 0)

			if (loadConnections + a) > poolConnectionsAvg*b {
				newPoolSize++
				go c.tunnelDialer()
			} else if float64(loadConnections+x) < float64(poolConnectionsAvg)*y && newPoolSize > c.config.ConnPoolSize {
				newPoolSize--
				c.controlFlow <- struct{}{}
			}
		}
	}
}

func (c *TlsClientTransport) channelHandler() {
	cc := c.getControl()
	if cc == nil {
		return
	}
	msgChan := make(chan byte, 1000)
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				readTimeout := c.config.KeepAlive * 2
				if readTimeout < 120*time.Second {
					readTimeout = 120 * time.Second
				}
				_ = cc.SetReadDeadline(time.Now().Add(readTimeout))
				msg, err := utils.ReceiveBinaryByte(cc)
				if err != nil {
					if c.ctx.Err() == nil {
						c.logger.Warnf("TLS control channel closed: %v", err)
						go c.Restart()
					}
					return
				}
				msgChan <- msg
			}
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			_ = cc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_ = utils.SendBinaryByte(cc, utils.SG_Closed)
			return
		case msg := <-msgChan:
			switch msg {
			case utils.SG_Chan:
				atomic.AddInt32(&c.loadConnections, 1)
				select {
				case <-c.controlFlow:
				default:
					go c.tunnelDialer()
				}
			case utils.SG_HB:
				_ = utils.SendBinaryByte(cc, utils.SG_HB)
			case utils.SG_Closed:
				c.logger.Infof("received farewell goodbye from %s server, reconnecting...", c.modeLabel())
				go c.Restart()
				return
			default:
				go c.Restart()
				return
			}
		}
	}
}

func (c *TlsClientTransport) tunnelDialer() {
	conn, err := c.dialTLS(c.config.Nodelay, c.config.SO_RCVBUF, c.config.SO_SNDBUF, c.config.MSS, 2)
	if err != nil {
		c.logger.Debugf("%s tunnel dialer: %v", c.modeLabel(), err)
		return
	}

	if err := utils.SendBinaryTransportString(conn, c.config.Token, utils.SG_TCP); err != nil {
		conn.Close()
		return
	}

	atomic.AddInt32(&c.poolConnections, 1)

	if c.config.Mux {
		defer atomic.AddInt32(&c.poolConnections, -1)
		session, err := smux.Server(conn, c.smuxConfig)
		if err != nil {
			conn.Close()
			return
		}
		for {
			select {
			case <-c.ctx.Done():
				session.Close()
				return
			default:
				stream, err := session.AcceptStream()
				if err != nil {
					session.Close()
					return
				}
				remoteAddr, err := utils.ReceiveBinaryString(stream)
				if err != nil {
					stream.Close()
					continue
				}
				go c.localDialer(stream, remoteAddr)
			}
		}
	}

	remoteAddr, transport, err := utils.ReceiveBinaryTransportString(conn)
	atomic.AddInt32(&c.poolConnections, -1)
	if err != nil {
		conn.Close()
		return
	}
	if transport == utils.SG_UDP {
		port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
		if err != nil {
			conn.Close()
			return
		}
		UDPDialer(conn, resolvedAddr, c.logger, c.usageMonitor, port, c.config.Sniffer)
		return
	}
	c.localDialer(conn, remoteAddr)
}

func (c *TlsClientTransport) localDialer(tunnelConn net.Conn, remoteAddr string) {
	port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
	if err != nil {
		tunnelConn.Close()
		return
	}
	var sendBuf, recvBuf int
	if strings.Contains(resolvedAddr, "127.0.0.1") {
		sendBuf = 32 * 1024
		recvBuf = 32 * 1024
	} else {
		sendBuf = c.config.SO_SNDBUF
		recvBuf = c.config.SO_RCVBUF
	}
	localConn, err := network.TcpDialer(c.ctx, resolvedAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 1, recvBuf, sendBuf, c.config.MSS)
	if err != nil {
		tunnelConn.Close()
		return
	}
	handlers.TCPConnectionHandler(c.ctx, false, tunnelConn, localConn, c.logger, c.usageMonitor, port, c.config.Sniffer)
}
