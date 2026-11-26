package client

import (
	"net"
	"strconv"
	"strings"

	"github.com/musix/backhaul/config"
)

func (c *Client) startFailover() {
	remHost, portStr, err := net.SplitHostPort(c.config.RemoteAddr)
	if err != nil {
		c.logger.Errorf("failover: invalid remote_addr %q: %v", c.config.RemoteAddr, err)
		return
	}
	basePort := c.config.FailoverBasePort
	if basePort <= 0 {
		basePort, _ = strconv.Atoi(portStr)
	}
	transports := c.config.FailoverTransports
	if len(transports) < 2 {
		transports = []string{"tlsmux", "xhttpsmux"}
	}
	if len(transports) > 4 {
		transports = transports[:4]
	}

	c.logger.Infof("Multi-Transport Failover client starting %d parallel carriers to %s (base port %d)", len(transports), remHost, basePort)
	for idx, trName := range transports {
		tr := config.TransportType(strings.ToLower(strings.TrimSpace(trName)))
		if tr == "" || tr == config.FAILOVER {
			continue
		}
		childCfg := *c.config
		childCfg.Transport = tr
		childCfg.RemoteAddr = net.JoinHostPort(remHost, strconv.Itoa(basePort+idx))
		childCfg.WebPort = 0
		childCfg.PPROF = false
		childCfg.GameMode = false

		childCli := NewClient(&childCfg, c.ctx)
		go childCli.Start()
	}
}
