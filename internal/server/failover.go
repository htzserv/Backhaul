package server

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/web"
)

type failoverBackend struct {
	name         string
	server       *Server
	portMap      map[string]string // public listen addr -> child loopback addr
	healthy      atomic.Bool
	healthySince int64
}

func allocLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := 0
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		port = ta.Port
	}
	_ = ln.Close()
	if port <= 0 {
		return 0, fmt.Errorf("failed to allocate loopback port")
	}
	return port, nil
}

type publicMapping struct {
	listenAddr string
	remoteAddr string
}

func expandPublicMappings(entries []string) []publicMapping {
	var out []publicMapping
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		lhs := strings.TrimSpace(parts[0])
		rhs := ""
		if len(parts) == 2 {
			rhs = strings.TrimSpace(parts[1])
		}
		if strings.Contains(lhs, "-") {
			rp := strings.SplitN(lhs, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(rp[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(rp[1]))
			if e1 == nil && e2 == nil && lo >= 1 && hi <= 65535 && hi >= lo && hi-lo <= 1024 {
				for p := lo; p <= hi; p++ {
					rem := strconv.Itoa(p)
					if rhs != "" {
						rem = rhs
					}
					out = append(out, publicMapping{listenAddr: fmt.Sprintf(":%d", p), remoteAddr: rem})
				}
			}
			continue
		}
		if p, err := strconv.Atoi(lhs); err == nil && p >= 1 && p <= 65535 {
			rem := strconv.Itoa(p)
			if rhs != "" {
				rem = rhs
			}
			out = append(out, publicMapping{listenAddr: fmt.Sprintf(":%d", p), remoteAddr: rem})
		} else {
			rem := lhs
			if rhs != "" {
				rem = rhs
			}
			out = append(out, publicMapping{listenAddr: lhs, remoteAddr: rem})
		}
	}
	return out
}

func (s *Server) startFailover() {
	bindHost, portStr, err := net.SplitHostPort(s.config.BindAddr)
	if err != nil {
		s.logger.Errorf("failover: invalid bind_addr %q: %v", s.config.BindAddr, err)
		return
	}
	basePort := s.config.FailoverBasePort
	if basePort <= 0 {
		basePort, _ = strconv.Atoi(portStr)
	}
	transports := s.config.FailoverTransports
	if len(transports) < 2 {
		transports = []string{"tlsmux", "xhttpsmux"}
	}
	if len(transports) > 4 {
		transports = transports[:4]
	}

	mappings := expandPublicMappings(s.config.Ports)
	var backends []*failoverBackend
	pubAddrs := []string{}
	pubSeen := map[string]bool{}

	for idx, trName := range transports {
		tr := config.TransportType(strings.ToLower(strings.TrimSpace(trName)))
		if tr == "" || tr == config.FAILOVER {
			continue
		}
		childCfg := *s.config
		childCfg.Transport = tr
		childCfg.BindAddr = net.JoinHostPort(bindHost, strconv.Itoa(basePort+idx))
		childCfg.WebPort = 0
		childCfg.PPROF = false
		childCfg.GameMode = false
		// Front listener writes Proxy Protocol v2 directly so real client IP is preserved
		childCfg.ProxyProtocol = false

		childPorts := make([]string, 0, len(mappings))
		pmap := map[string]string{}
		for _, m := range mappings {
			if !pubSeen[m.listenAddr] {
				pubSeen[m.listenAddr] = true
				pubAddrs = append(pubAddrs, m.listenAddr)
			}
			lp, lerr := allocLoopbackPort()
			if lerr != nil {
				continue
			}
			lbAddr := fmt.Sprintf("127.0.0.1:%d", lp)
			pmap[m.listenAddr] = lbAddr
			childPorts = append(childPorts, fmt.Sprintf("%s=%s", lbAddr, m.remoteAddr))
		}
		childCfg.Ports = childPorts

		childSrv := NewServer(&childCfg, s.ctx)
		fb := &failoverBackend{
			name:    fmt.Sprintf("%s(:%d)", tr, basePort+idx),
			server:  childSrv,
			portMap: pmap,
		}
		backends = append(backends, fb)
		go childSrv.Start()
	}

	if len(backends) == 0 {
		s.logger.Error("failover: no valid transports configured")
		return
	}

	failoverStatus := "Disconnected (FAILOVER)"
	usageMon := web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), s.ctx, s.config.SnifferLog, s.config.Sniffer, &failoverStatus, s.logger)
	s.setStatusFn(usageMon.GetStatus)
	if s.config.WebPort > 0 {
		go usageMon.Monitor()
	}

	var activeIdx atomic.Int32
	activeIdx.Store(0)
	s.logger.Infof("Multi-Transport Failover started with %d carriers (probe=%ds, restore=%ds)", len(backends), s.config.FailoverProbeSec, s.config.FailoverRestoreSec)

	go func() {
		probeEvery := time.Duration(s.config.FailoverProbeSec) * time.Second
		if probeEvery < 2*time.Second {
			probeEvery = 5 * time.Second
		}
		restoreDur := time.Duration(s.config.FailoverRestoreSec) * time.Second
		if restoreDur < 30*time.Second {
			restoreDur = 300 * time.Second
		}
		ticker := time.NewTicker(probeEvery)
		defer ticker.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().Unix()
				anyHealthy := false
				for _, b := range backends {
					ok := b.server.IsConnected()
					if ok {
						anyHealthy = true
					}
					prev := b.healthy.Swap(ok)
					if ok && !prev {
						b.healthySince = now
					} else if !ok {
						b.healthySince = 0
					}
				}
				cur := int(activeIdx.Load())
				if cur < 0 || cur >= len(backends) {
					cur = 0
				}
				if !backends[cur].healthy.Load() {
					for i, b := range backends {
						if b.healthy.Load() {
							activeIdx.Store(int32(i))
							cur = i
							s.logger.Warnf("FAILOVER SWITCH -> %s", b.name)
							break
						}
					}
				} else if cur > 0 {
					for i := 0; i < cur; i++ {
						if backends[i].healthy.Load() && backends[i].healthySince > 0 && time.Duration(now-backends[i].healthySince)*time.Second >= restoreDur {
							activeIdx.Store(int32(i))
							cur = i
							s.logger.Infof("FAILOVER RESTORE -> primary %s (healthy for %ds)", backends[i].name, now-backends[i].healthySince)
							break
						}
					}
				}
				if anyHealthy {
					usageMon.SetStatus(fmt.Sprintf("Connected (FAILOVER: %s)", backends[cur].name))
				} else {
					usageMon.SetStatus("Disconnected (FAILOVER)")
				}
			}
		}
	}()

	for _, pubAddr := range pubAddrs {
		listenAddr := pubAddr
		go func() {
			ln, err := net.Listen("tcp", listenAddr)
			if err != nil {
				s.logger.Errorf("failover public listener %s failed: %v", listenAddr, err)
				return
			}
			defer ln.Close()
			s.logger.Infof("failover front-listener active on %s", listenAddr)
			go func() {
				<-s.ctx.Done()
				_ = ln.Close()
			}()
			for {
				cli, err := ln.Accept()
				if err != nil {
					if s.ctx.Err() != nil {
						return
					}
					continue
				}
				go func(in net.Conn) {
					defer in.Close()
					cur := int(activeIdx.Load())
					var target net.Conn
					var dialErr error

					// Pass 1: try currently active & other healthy carriers first
					for step := 0; step < len(backends); step++ {
						idx := (cur + step) % len(backends)
						if !backends[idx].healthy.Load() {
							continue
						}
						dst := backends[idx].portMap[listenAddr]
						if dst == "" {
							continue
						}
						target, dialErr = net.DialTimeout("tcp", dst, 2*time.Second)
						if dialErr == nil {
							break
						}
					}
					// Pass 2: if status check hasn't ticked yet, fall back to active backend
					if target == nil {
						if dst := backends[cur].portMap[listenAddr]; dst != "" {
							target, _ = net.DialTimeout("tcp", dst, 2*time.Second)
						}
					}
					if target == nil {
						return
					}
					defer target.Close()

					if s.config.ProxyProtocol {
						if err := handlers.WriteProxyProtocol(in, target); err != nil {
							s.logger.Debugf("failover proxy protocol write failed: %v", err)
							return
						}
					}

					var wg sync.WaitGroup
					wg.Add(2)
					go func() {
						defer wg.Done()
						n, _ := io.Copy(target, in)
						if s.config.Sniffer {
							usageMon.AddOrUpdatePort(handlers.LocalPortOf(in), uint64(n))
						}
						_ = target.Close()
					}()
					go func() {
						defer wg.Done()
						n, _ := io.Copy(in, target)
						if s.config.Sniffer {
							usageMon.AddOrUpdatePort(handlers.LocalPortOf(in), uint64(n))
						}
						_ = in.Close()
					}()
					wg.Wait()
				}(cli)
			}
		}()
	}
}
