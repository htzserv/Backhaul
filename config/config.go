package config

// TransportType defines the type of transport.
type TransportType string

const (
	TCP         TransportType = "tcp"
	TCPMUX      TransportType = "tcpmux"
	TLS         TransportType = "tls"
	TLSMUX      TransportType = "tlsmux"
	WS          TransportType = "ws"
	WSS         TransportType = "wss"
	WSMUX       TransportType = "wsmux"
	WSSMUX      TransportType = "wssmux"
	UDP         TransportType = "udp"
	KCP         TransportType = "kcp"
	KCPMUX      TransportType = "kcpmux"
	XHTTP       TransportType = "xhttp"
	XHTTPS      TransportType = "xhttps"
	XHTTPMUX    TransportType = "xhttpmux"
	XHTTPSMUX   TransportType = "xhttpsmux"
	PARALLAX    TransportType = "parallax"
	PARALLAXMUX TransportType = "parallaxmux"
	FAILOVER    TransportType = "failover"
)

type ServerConfig struct {
	BindAddr         string        `toml:"bind_addr"`
	Transport        TransportType `toml:"transport"`
	Token            string        `toml:"token"`
	Nodelay          bool          `toml:"nodelay"`
	Keepalive        int           `toml:"keepalive_period"`
	ChannelSize      int           `toml:"channel_size"`
	LogLevel         string        `toml:"log_level"`
	Ports            []string      `toml:"ports"`
	PPROF            bool          `toml:"pprof"`
	MuxSession       int           `toml:"mux_session"`
	MuxVersion       int           `toml:"mux_version"`
	MaxFrameSize     int           `toml:"mux_framesize"`
	MaxReceiveBuffer int           `toml:"mux_recievebuffer"`
	MaxStreamBuffer  int           `toml:"mux_streambuffer"`
	Sniffer          bool          `toml:"sniffer"`
	WebPort          int           `toml:"web_port"`
	SnifferLog       string        `toml:"sniffer_log"`
	TLSCertFile      string        `toml:"tls_cert"`
	TLSKeyFile       string        `toml:"tls_key"`
	SNI              string        `toml:"sni"`
	Heartbeat        int           `toml:"heartbeat"`
	MuxCon           int           `toml:"mux_con"`
	AcceptUDP        bool          `toml:"accept_udp"`
	SkipOptz         bool          `toml:"skip_optz"`
	MSS              int           `toml:"mss"`
	SO_RCVBUF        int           `toml:"so_rcvbuf"`
	SO_SNDBUF        int           `toml:"so_sndbuf"`
	ProxyProtocol    bool          `toml:"proxy_protocol"`
	FallbackAddr     string        `toml:"fallback_addr"`

	// KCP options
	KCPMode        string `toml:"kcp_mode"`
	KCPKey         string `toml:"kcp_key"`
	KCPCrypt       string `toml:"kcp_crypt"`
	KCPNoFEC       bool   `toml:"kcp_nofec"`
	KCPDataShard   int    `toml:"kcp_datashard"`
	KCPParityShard int    `toml:"kcp_parityshard"`
	KCPMTU         int    `toml:"kcp_mtu"`
	KCPSndWnd      int    `toml:"kcp_sndwnd"`
	KCPRcvWnd      int    `toml:"kcp_rcvwnd"`
	KCPNoDelay     int    `toml:"kcp_nodelay"`
	KCPInterval    int    `toml:"kcp_interval"`
	KCPResend      int    `toml:"kcp_resend"`
	KCPNC          int    `toml:"kcp_nc"`
	KCPAcksNoDelay bool   `toml:"kcp_acknodelay"`
	KCPDSCP        int    `toml:"kcp_dscp"`

	// XHTTP & Anti-DPI options
	XHTTPPath   string `toml:"xhttp_path"`
	XHTTPHost   string `toml:"xhttp_host"`
	XHTTPMode   string `toml:"xhttp_mode"`
	TLSFragment bool   `toml:"tls_fragment"`

	// Phase 3: Parallax (Multi-Lane TCP + KCP/FEC)
	ParallaxLanes     int `toml:"parallax_lanes"`
	ParallaxWarmupMin int `toml:"parallax_warmup_min"`
	ParallaxWarmupMax int `toml:"parallax_warmup_max"`
	ParallaxStallSec  int `toml:"parallax_stall_sec"`

	// Phase 3: Multi-Transport Failover
	FailoverTransports []string `toml:"failover_transports"`
	FailoverBasePort   int      `toml:"failover_base_port"`
	FailoverProbeSec   int      `toml:"failover_probe_sec"`
	FailoverRestoreSec int      `toml:"failover_restore_sec"`

	// Phase 3: Game Mode (Multi-Copy Low-Latency Encrypted UDP Datagrams)
	GameMode     bool     `toml:"game_mode"`
	GameCopies   int      `toml:"game_copies"`
	GameBasePort int      `toml:"game_base_port"`
	GamePorts    []string `toml:"game_ports"`
}

type ClientConfig struct {
	RemoteAddr       string        `toml:"remote_addr"`
	Transport        TransportType `toml:"transport"`
	Token            string        `toml:"token"`
	ConnectionPool   int           `toml:"connection_pool"`
	RetryInterval    int           `toml:"retry_interval"`
	Nodelay          bool          `toml:"nodelay"`
	Keepalive        int           `toml:"keepalive_period"`
	LogLevel         string        `toml:"log_level"`
	PPROF            bool          `toml:"pprof"`
	MuxSession       int           `toml:"mux_session"`
	MuxVersion       int           `toml:"mux_version"`
	MaxFrameSize     int           `toml:"mux_framesize"`
	MaxReceiveBuffer int           `toml:"mux_recievebuffer"`
	MaxStreamBuffer  int           `toml:"mux_streambuffer"`
	Sniffer          bool          `toml:"sniffer"`
	WebPort          int           `toml:"web_port"`
	SnifferLog       string        `toml:"sniffer_log"`
	DialTimeout      int           `toml:"dial_timeout"`
	AggressivePool   bool          `toml:"aggressive_pool"`
	EdgeIP           string        `toml:"edge_ip"`
	SNI              string        `toml:"sni"`
	UTLSFingerprint  string        `toml:"utls_fingerprint"`
	SkipOptz         bool          `toml:"skip_optz"`
	MSS              int           `toml:"mss"`
	SO_RCVBUF        int           `toml:"so_rcvbuf"`
	SO_SNDBUF        int           `toml:"so_sndbuf"`

	// KCP options
	KCPMode        string `toml:"kcp_mode"`
	KCPKey         string `toml:"kcp_key"`
	KCPCrypt       string `toml:"kcp_crypt"`
	KCPNoFEC       bool   `toml:"kcp_nofec"`
	KCPDataShard   int    `toml:"kcp_datashard"`
	KCPParityShard int    `toml:"kcp_parityshard"`
	KCPMTU         int    `toml:"kcp_mtu"`
	KCPSndWnd      int    `toml:"kcp_sndwnd"`
	KCPRcvWnd      int    `toml:"kcp_rcvwnd"`
	KCPNoDelay     int    `toml:"kcp_nodelay"`
	KCPInterval    int    `toml:"kcp_interval"`
	KCPResend      int    `toml:"kcp_resend"`
	KCPNC          int    `toml:"kcp_nc"`
	KCPAcksNoDelay bool   `toml:"kcp_acknodelay"`
	KCPDSCP        int    `toml:"kcp_dscp"`

	// XHTTP & Anti-DPI options
	XHTTPPath   string `toml:"xhttp_path"`
	XHTTPHost   string `toml:"xhttp_host"`
	XHTTPMode   string `toml:"xhttp_mode"`
	TLSFragment bool   `toml:"tls_fragment"`

	// Phase 3: Parallax (Multi-Lane TCP + KCP/FEC)
	ParallaxLanes     int `toml:"parallax_lanes"`
	ParallaxWarmupMin int `toml:"parallax_warmup_min"`
	ParallaxWarmupMax int `toml:"parallax_warmup_max"`
	ParallaxStallSec  int `toml:"parallax_stall_sec"`

	// Phase 3: Multi-Transport Failover
	FailoverTransports []string `toml:"failover_transports"`
	FailoverBasePort   int      `toml:"failover_base_port"`
	FailoverProbeSec   int      `toml:"failover_probe_sec"`
	FailoverRestoreSec int      `toml:"failover_restore_sec"`

	// Phase 3: Game Mode (Multi-Copy Low-Latency Encrypted UDP Datagrams)
	GameMode     bool     `toml:"game_mode"`
	GameCopies   int      `toml:"game_copies"`
	GameBasePort int      `toml:"game_base_port"`
	GamePorts    []string `toml:"game_ports"`
}

type Config struct {
	Server ServerConfig `toml:"server"`
	Client ClientConfig `toml:"client"`
}
