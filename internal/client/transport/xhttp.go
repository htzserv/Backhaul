package transport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
)

type XhttpClientConfig struct {
	RemoteAddr       string
	Token            string
	SnifferLog       string
	TunnelStatus     string
	Nodelay          bool
	Sniffer          bool
	KeepAlive        time.Duration
	RetryInterval    time.Duration
	DialTimeOut      time.Duration
	ConnPoolSize     int
	WebPort          int
	Mode             config.TransportType
	AggressivePool   bool
	EdgeIP           string
	SNI              string
	UTLSFingerprint  string
	TLSFragment      bool
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	XHTTPPath        string
	XHTTPHost        string
	XHTTPMode        string
}

type XhttpClientTransport struct {
	config          *XhttpClientConfig
	smuxConfig      *smux.Config
	parentctx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlMu       sync.RWMutex
	controlChannel  net.Conn
	sharedClients   *network.XHTTPSharedClients
	usageMonitor    *web.Usage
	restartMutex    sync.Mutex
	poolConnections int32
	loadConnections int32
	controlFlow     chan struct{}
}

func NewXHTTPClient(parentCtx context.Context, cfg *XhttpClientConfig, logger *logrus.Logger) *XhttpClientTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	return &XhttpClientTransport{
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

func (c *XhttpClientTransport) isMux() bool {
	return c.config.Mode == config.XHTTPMUX || c.config.Mode == config.XHTTPSMUX
}

func (c *XhttpClientTransport) isTLS() bool {
	return c.config.Mode == config.XHTTPS || c.config.Mode == config.XHTTPSMUX
}

func (c *XhttpClientTransport) getControl() net.Conn {
	c.controlMu.RLock()
	defer c.controlMu.RUnlock()
	return c.controlChannel
}

func (c *XhttpClientTransport) setControl(conn net.Conn) {
	c.controlMu.Lock()
	c.controlChannel = conn
	c.controlMu.Unlock()
}

func (c *XhttpClientTransport) Start() {
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}
	sc, err := network.NewXHTTPSharedClients(network.XHTTPDialConfig{
		RemoteAddr:      c.config.RemoteAddr,
		EdgeIP:          c.config.EdgeIP,
		SNI:             c.config.SNI,
		HostHeader:      c.config.XHTTPHost,
		BasePath:        c.config.XHTTPPath,
		Mode:            c.config.XHTTPMode,
		Token:           c.config.Token,
		UTLSFingerprint: c.config.UTLSFingerprint,
		TLSFragment:     c.config.TLSFragment,
		TLS:             c.isTLS(),
		DialTimeout:     c.config.DialTimeOut,
		KeepAlive:       c.config.KeepAlive,
		NoDelay:         c.config.Nodelay,
	})
	if err == nil {
		c.sharedClients = sc
	}
	c.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", c.config.Mode)
	go c.channelDialer()
}

func (c *XhttpClientTransport) Restart() {
	if !c.restartMutex.TryLock() {
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Infof("restarting %s client...", c.config.Mode)
	if cc := c.getControl(); cc != nil {
		_ = cc.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
		_ = utils.SendBinaryByte(cc, utils.SG_Closed)
		_ = cc.Close()
	}
	if c.cancel != nil {
		c.cancel()
	}
	if c.sharedClients != nil {
		c.sharedClients.Close()
		c.sharedClients = nil
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

func (c *XhttpClientTransport) dialPurpose(purpose string) (net.Conn, error) {
	dialCfg := network.XHTTPDialConfig{
		RemoteAddr:      c.config.RemoteAddr,
		EdgeIP:          c.config.EdgeIP,
		SNI:             c.config.SNI,
		HostHeader:      c.config.XHTTPHost,
		BasePath:        c.config.XHTTPPath,
		Purpose:         purpose,
		Mode:            c.config.XHTTPMode,
		Token:           c.config.Token,
		UTLSFingerprint: c.config.UTLSFingerprint,
		TLSFragment:     c.config.TLSFragment,
		TLS:             c.isTLS(),
		DialTimeout:     c.config.DialTimeOut,
		KeepAlive:       c.config.KeepAlive,
		NoDelay:         c.config.Nodelay,
	}
	if c.sharedClients != nil {
		dialCfg.SharedH2Client = c.sharedClients.H2
		dialCfg.SharedH1Client = c.sharedClients.H1
	}
	return network.DialXHTTP(c.ctx, dialCfg)
}

func (c *XhttpClientTransport) channelDialer() {
	c.logger.Infof("attempting to establish %s control channel to %s (SNI=%s, uTLS=%s, frag=%v)...", c.config.Mode, c.config.RemoteAddr, c.config.SNI, c.config.UTLSFingerprint, c.config.TLSFragment)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			conn, err := c.dialPurpose("channel")
			if err != nil {
				c.logger.Errorf("%s control channel dialer: %v", c.config.Mode, err)
				time.Sleep(c.config.RetryInterval)
				continue
			}
			c.setControl(conn)
			c.config.TunnelStatus = fmt.Sprintf("Connected (%s)", c.config.Mode)
			c.logger.Infof("%s control channel established successfully", c.config.Mode)

			go c.poolMaintainer()
			go c.channelHandler()
			return
		}
	}
}

func (c *XhttpClientTransport) poolMaintainer() {
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

func (c *XhttpClientTransport) channelHandler() {
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
						c.logger.Warnf("xhttp control channel closed: %v", err)
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
			_ = cc.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
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
				c.logger.Infof("received farewell goodbye from %s server, reconnecting...", c.config.Mode)
				go c.Restart()
				return
			default:
				go c.Restart()
				return
			}
		}
	}
}

func (c *XhttpClientTransport) tunnelDialer() {
	conn, err := c.dialPurpose("tunnel")
	if err != nil {
		c.logger.Debugf("%s tunnel dialer: %v", c.config.Mode, err)
		return
	}

	atomic.AddInt32(&c.poolConnections, 1)

	if c.isMux() {
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

	remoteAddr, err := utils.ReceiveBinaryString(conn)
	atomic.AddInt32(&c.poolConnections, -1)
	if err != nil {
		conn.Close()
		return
	}
	c.localDialer(conn, remoteAddr)
}

func (c *XhttpClientTransport) localDialer(tunnelConn net.Conn, remoteAddr string) {
	port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
	if err != nil {
		tunnelConn.Close()
		return
	}
	var sendBuf, recvBuf int
	if strings.Contains(resolvedAddr, "127.0.0.1") {
		sendBuf = 32 * 1024
		recvBuf = 32 * 1024
	}
	localConn, err := network.TcpDialer(c.ctx, resolvedAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 1, recvBuf, sendBuf, 0)
	if err != nil {
		tunnelConn.Close()
		return
	}
	handlers.TCPConnectionHandler(c.ctx, false, tunnelConn, localConn, c.logger, c.usageMonitor, port, c.config.Sniffer)
}
