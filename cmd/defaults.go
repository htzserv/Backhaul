package cmd

import (
	"net"
	"strings"

	"github.com/musix/backhaul/config"
	"github.com/sirupsen/logrus"
)

const (
	defaultToken            = "musix"
	defaultChannelSize      = 2048
	defaultRetryInterval    = 3
	defaultConnectionPool   = 8
	defaultLogLevel         = "info"
	defaultMuxSession       = 1
	defaultKeepAlive        = 75
	deafultHeartbeat        = 40
	defaultDialTimeout      = 10
	defaultMuxVersion       = 1
	defaultMaxFrameSize     = 32768
	defaultMaxReceiveBuffer = 4194304
	defaultMaxStreamBuffer  = 65536
	defaultSnifferLog       = "backhaul.json"
	defaultMuxCon           = 8

	defaultSNI            = "www.cloudflare.com"
	defaultUTLS           = "chrome"
	defaultKCPMode        = "fast2"
	defaultKCPCrypt       = "aes"
	defaultKCPDataShard   = 10
	defaultKCPParityShard = 3
	defaultKCPMTU         = 1350
	defaultKCPSndWnd      = 1024
	defaultKCPRcvWnd      = 1024
	defaultXHTTPPath      = "/api/v1/stream"
	defaultXHTTPMode      = "auto"
)

func applyDefaults(cfg *config.Config) {
	if cfg.Server.Token == "" {
		cfg.Server.Token = defaultToken
	}
	if cfg.Client.Token == "" {
		cfg.Client.Token = defaultToken
	}
	if cfg.Server.ChannelSize <= 0 {
		cfg.Server.ChannelSize = defaultChannelSize
	}
	if _, err := logrus.ParseLevel(cfg.Client.LogLevel); err != nil {
		cfg.Client.LogLevel = defaultLogLevel
	}
	if _, err := logrus.ParseLevel(cfg.Server.LogLevel); err != nil {
		cfg.Server.LogLevel = defaultLogLevel
	}
	if cfg.Client.RetryInterval <= 0 {
		cfg.Client.RetryInterval = defaultRetryInterval
	}
	if cfg.Client.ConnectionPool <= 0 {
		cfg.Client.ConnectionPool = defaultConnectionPool
	}
	if cfg.Server.MuxSession <= 0 {
		cfg.Server.MuxSession = defaultMuxSession
	}
	if cfg.Client.MuxSession <= 0 {
		cfg.Client.MuxSession = defaultMuxSession
	}
	if cfg.Server.Keepalive <= 0 {
		cfg.Server.Keepalive = defaultKeepAlive
	}
	if cfg.Client.Keepalive <= 0 {
		cfg.Client.Keepalive = defaultKeepAlive
	}
	if cfg.Server.MuxVersion <= 0 || cfg.Server.MuxVersion > 2 {
		cfg.Server.MuxVersion = defaultMuxVersion
	}
	if cfg.Client.MuxVersion <= 0 || cfg.Client.MuxVersion > 2 {
		cfg.Client.MuxVersion = defaultMuxVersion
	}
	if cfg.Server.MaxFrameSize <= 0 {
		cfg.Server.MaxFrameSize = defaultMaxFrameSize
	}
	if cfg.Client.MaxFrameSize <= 0 {
		cfg.Client.MaxFrameSize = defaultMaxFrameSize
	}
	if cfg.Server.MaxReceiveBuffer <= 0 {
		cfg.Server.MaxReceiveBuffer = defaultMaxReceiveBuffer
	}
	if cfg.Client.MaxReceiveBuffer <= 0 {
		cfg.Client.MaxReceiveBuffer = defaultMaxReceiveBuffer
	}
	if cfg.Server.MaxStreamBuffer <= 0 {
		cfg.Server.MaxStreamBuffer = defaultMaxStreamBuffer
	}
	if cfg.Client.MaxStreamBuffer <= 0 {
		cfg.Client.MaxStreamBuffer = defaultMaxStreamBuffer
	}
	if cfg.Server.SnifferLog == "" {
		cfg.Server.SnifferLog = defaultSnifferLog
	}
	if cfg.Client.SnifferLog == "" {
		cfg.Client.SnifferLog = defaultSnifferLog
	}
	if cfg.Server.Heartbeat < 1 {
		cfg.Server.Heartbeat = deafultHeartbeat
	}
	if cfg.Client.DialTimeout < 1 {
		cfg.Client.DialTimeout = defaultDialTimeout
	}
	if cfg.Server.MuxCon < 1 {
		cfg.Server.MuxCon = defaultMuxCon
	}

	if cfg.Server.SNI == "" {
		cfg.Server.SNI = defaultSNI
	} else if h, _, err := net.SplitHostPort(cfg.Server.SNI); err == nil && h != "" {
		cfg.Server.SNI = h
	}
	if cfg.Client.SNI == "" {
		if cfg.Client.XHTTPHost != "" {
			host := cfg.Client.XHTTPHost
			if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
				host = h
			}
			cfg.Client.SNI = host
		} else if host, _, err := net.SplitHostPort(cfg.Client.RemoteAddr); err == nil && host != "" && net.ParseIP(host) == nil {
			cfg.Client.SNI = host
		} else {
			cfg.Client.SNI = defaultSNI
		}
	} else if h, _, err := net.SplitHostPort(cfg.Client.SNI); err == nil && h != "" {
		cfg.Client.SNI = h
	}
	if cfg.Client.UTLSFingerprint == "" {
		cfg.Client.UTLSFingerprint = defaultUTLS
	}

	// KCP Server defaults
	if cfg.Server.KCPMode == "" {
		cfg.Server.KCPMode = defaultKCPMode
	}
	if cfg.Server.KCPCrypt == "" {
		cfg.Server.KCPCrypt = defaultKCPCrypt
	}
	if cfg.Server.KCPKey == "" {
		cfg.Server.KCPKey = cfg.Server.Token
	}
	if cfg.Server.KCPNoFEC {
		cfg.Server.KCPDataShard = 0
		cfg.Server.KCPParityShard = 0
	} else {
		if cfg.Server.KCPDataShard <= 0 {
			cfg.Server.KCPDataShard = defaultKCPDataShard
		}
		if cfg.Server.KCPParityShard <= 0 {
			cfg.Server.KCPParityShard = defaultKCPParityShard
		}
	}
	if cfg.Server.KCPMTU <= 0 {
		cfg.Server.KCPMTU = defaultKCPMTU
	}
	if cfg.Server.KCPSndWnd <= 0 {
		cfg.Server.KCPSndWnd = defaultKCPSndWnd
	}
	if cfg.Server.KCPRcvWnd <= 0 {
		cfg.Server.KCPRcvWnd = defaultKCPRcvWnd
	}

	// KCP Client defaults
	if cfg.Client.KCPMode == "" {
		cfg.Client.KCPMode = defaultKCPMode
	}
	if cfg.Client.KCPCrypt == "" {
		cfg.Client.KCPCrypt = defaultKCPCrypt
	}
	if cfg.Client.KCPKey == "" {
		cfg.Client.KCPKey = cfg.Client.Token
	}
	if cfg.Client.KCPNoFEC {
		cfg.Client.KCPDataShard = 0
		cfg.Client.KCPParityShard = 0
	} else {
		if cfg.Client.KCPDataShard <= 0 {
			cfg.Client.KCPDataShard = defaultKCPDataShard
		}
		if cfg.Client.KCPParityShard <= 0 {
			cfg.Client.KCPParityShard = defaultKCPParityShard
		}
	}
	if cfg.Client.KCPMTU <= 0 {
		cfg.Client.KCPMTU = defaultKCPMTU
	}
	if cfg.Client.KCPSndWnd <= 0 {
		cfg.Client.KCPSndWnd = defaultKCPSndWnd
	}
	if cfg.Client.KCPRcvWnd <= 0 {
		cfg.Client.KCPRcvWnd = defaultKCPRcvWnd
	}

	// XHTTP defaults
	if cfg.Server.XHTTPPath == "" {
		cfg.Server.XHTTPPath = defaultXHTTPPath
	} else if !strings.HasPrefix(cfg.Server.XHTTPPath, "/") {
		cfg.Server.XHTTPPath = "/" + cfg.Server.XHTTPPath
	}
	if cfg.Server.XHTTPMode == "" {
		cfg.Server.XHTTPMode = defaultXHTTPMode
	}

	if cfg.Client.XHTTPPath == "" {
		cfg.Client.XHTTPPath = defaultXHTTPPath
	} else if !strings.HasPrefix(cfg.Client.XHTTPPath, "/") {
		cfg.Client.XHTTPPath = "/" + cfg.Client.XHTTPPath
	}
	if cfg.Client.XHTTPMode == "" {
		cfg.Client.XHTTPMode = defaultXHTTPMode
	}
}
