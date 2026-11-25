package transport

import (
	"context"
	"fmt"
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
	config          *WsMuxConfig
	smuxConfig      *smux.Config
	parentctx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlChannel  *websocket.Conn
	usageMonitor    *web.Usage
	restartMutex    sync.Mutex
	poolConnections int32
	loadConnections int32
	controlFlow     chan struct{}
}

type WsMuxConfig struct {
	RemoteAddr       string
	Token            string
	SnifferLog       string
	TunnelStatus     string
	Nodelay          bool
	Sniffer          bool
	KeepAlive        time.Duration
	RetryInterval    time.Duration
	DialTimeOut      time.Duration
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	ConnPoolSize     int
	WebPort          int
	Mode             config.TransportType
	AggressivePool   bool
	EdgeIP           string
	SNI              string
	UTLSFingerprint  string
	TLSFragment      bool
}

func NewWSMuxClient(parentCtx context.Context, config *WsMuxConfig, logger *logrus.Logger) *WsMuxTransport {
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
		config:       config,
		parentctx:    parentCtx,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		controlFlow:  make(chan struct{}, 100),
	}
}

func (c *WsMuxTransport) Start() {
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}
	c.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", c.config.Mode)
	go c.channelDialer()
}

func (c *WsMuxTransport) Restart() {
	if !c.restartMutex.TryLock() {
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Infof("restarting %s client...", c.config.Mode)
	if c.controlChannel != nil {
		_ = c.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
		_ = c.controlChannel.Close()
	}
	if c.cancel != nil {
		c.cancel()
	}
	time.Sleep(1500 * time.Millisecond)

	ctx, cancel := context.WithCancel(c.parentctx)
	c.ctx = ctx
	c.cancel = cancel
	c.controlChannel = nil
	c.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", c.config.WebPort), ctx, c.config.SnifferLog, c.config.Sniffer, &c.config.TunnelStatus, c.logger)
	c.config.TunnelStatus = ""
	atomic.StoreInt32(&c.poolConnections, 0)
	atomic.StoreInt32(&c.loadConnections, 0)
	c.controlFlow = make(chan struct{}, 100)

	go c.Start()
}

func (c *WsMuxTransport) channelDialer() {
	c.logger.Infof("attempting to establish %s control channel to %s (SNI=%s, uTLS=%s, frag=%v)...", c.config.Mode, c.config.RemoteAddr, c.config.SNI, c.config.UTLSFingerprint, c.config.TLSFragment)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			tunnelWSConn, err := network.WebSocketDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, c.config.SNI, c.config.UTLSFingerprint, c.config.TLSFragment, "/channel", c.config.DialTimeOut, c.config.KeepAlive, true, c.config.Token, c.config.Mode, 2, 0, 0)
			if err != nil {
				c.logger.Errorf("control channel dialer: %v", err)
				time.Sleep(c.config.RetryInterval)
				continue
			}
			c.controlChannel = tunnelWSConn
			c.logger.Infof("%s control channel established successfully", c.config.Mode)
			c.config.TunnelStatus = fmt.Sprintf("Connected (%s)", c.config.Mode)

			go c.poolMaintainer()
			go c.channelHandler()
			return
		}
	}
}

func (c *WsMuxTransport) poolMaintainer() {
	for i := 0; i < c.config.ConnPoolSize; i++ {
		go c.tunnelDialer()
	}

	a, b, x, y := 4, 5, 3, 4.0
	if c.config.AggressivePool {
		a, b, x, y = 1, 2, 0, 0.75
	}

	tickerPool := time.NewTicker(time.Second * 1)
	defer tickerPool.Stop()
	tickerLoad := time.NewTicker(time.Second * 10)
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

func (c *WsMuxTransport) channelHandler() {
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
				_ = c.controlChannel.SetReadDeadline(time.Now().Add(readTimeout))
				_, msg, err := c.controlChannel.ReadMessage()
				if err != nil {
					if c.ctx.Err() == nil {
						c.logger.Warnf("wsmux control channel closed: %v", err)
						go c.Restart()
					}
					return
				}
				if len(msg) == 0 {
					continue
				}
				msgChan <- msg[0]
			}
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			_ = c.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
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
				if err := c.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_HB}); err != nil {
					go c.Restart()
					return
				}
			case utils.SG_Closed:
				go c.Restart()
				return
			default:
				go c.Restart()
				return
			}
		}
	}
}

func (c *WsMuxTransport) tunnelDialer() {
	tunnelWSConn, err := network.WebSocketDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, c.config.SNI, c.config.UTLSFingerprint, c.config.TLSFragment, "/tunnel", c.config.DialTimeOut, c.config.KeepAlive, c.config.Nodelay, c.config.Token, c.config.Mode, 2, 2*1024*1024, 2*1024*1024)
	if err != nil {
		c.logger.Debugf("wsmux tunnel dialer: %v", err)
		return
	}

	atomic.AddInt32(&c.poolConnections, 1)
	c.handleSession(tunnelWSConn)
}

func (c *WsMuxTransport) handleSession(tunnelConn *websocket.Conn) {
	defer atomic.AddInt32(&c.poolConnections, -1)

	session, err := smux.Server(network.NewWSNetConn(tunnelConn), c.smuxConfig)
	if err != nil {
		tunnelConn.Close()
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

func (c *WsMuxTransport) localDialer(stream *smux.Stream, remoteAddr string) {
	port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
	if err != nil {
		stream.Close()
		return
	}
	var sendBuf, recvBuf int
	if strings.Contains(resolvedAddr, "127.0.0.1") {
		sendBuf = 32 * 1024
		recvBuf = 32 * 1024
	}
	localConnection, err := network.TcpDialer(c.ctx, resolvedAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 1, recvBuf, sendBuf, 0)
	if err != nil {
		stream.Close()
		return
	}
	handlers.TCPConnectionHandler(c.ctx, false, stream, localConnection, c.logger, c.usageMonitor, port, c.config.Sniffer)
}
