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
)

type failoverBackend struct {
	name          string
	server        *Server
	portMap       map[string]string // public listen addr -> child loopback addr
	healthy       atomic.Bool
	healthySince  int64
}

func allocLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func parsePublicMapping(mapping string) (string, string) {
	parts := strings.SplitN(mapping, "=", 2)
	local := strings.TrimSpace(parts[0])
	remote := local
	if len(parts) == 2 {
		remote = strings.TrimSpace(parts[1])
	}
	if p, err := strconv.Atoi(local); err == nil && p >= 1 && p <= 65535 {
		local = fmt.Sprintf(":%d", p)
	}
	return local, remote
}

func (s *Server) startFailover() {
	bindHost, portStr, err := net.SplitHostPort(s.config.BindAddr)
	if err != nil {
		s.logger.Fatalf("failover: invalid bind_addr %q: %v", s.config.BindAddr, err)
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

		childPorts := make([]string, 0, len(s.config.Ports))
		pmap := map[string]string{}
		for _, raw := range s.config.Ports {
			pubAddr, remoteTarget := parsePublicMapping(raw)
			if !pubSeen[pubAddr] {
				pubSeen[pubAddr] = true
				pubAddrs = append(pubAddrs, pubAddr)
			}
			lp, lerr := allocLoopbackPort()
			if lerr != nil {
				continue
			}
			lbAddr := fmt.Sprintf("127.0.0.1:%d", lp)
			pmap[pubAddr] = lbAddr
			childPorts = append(childPorts, fmt.Sprintf("%s=%s", lbAddr, remoteTarget))
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

	var activeIdx atomic.Int32
	activeIdx.Store(0)
	s.logger.Infof("Multi-Transport Failover started with %d carriers (probe=%ds, restore=%ds)", len(backends), s.config.FailoverProbeSec, s.config.FailoverRestoreSec)

	// Supervisor goroutine: tracks live Connected status & promotes/fails over cleanly
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
				for _, b := range backends {
					ok := b.server.IsConnected()
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
				// Immediate failover if current active transport is down
				if !backends[cur].healthy.Load() {
					for i, b := range backends {
						if b.healthy.Load() {
							activeIdx.Store(int32(i))
							s.logger.Warnf("FAILOVER SWITCH: %s -> %s", backends[cur].name, b.name)
							break
						}
					}
				} else if cur > 0 {
					// Hysteresis restore: return to higher-priority carrier once stable for restoreDur
					for i := 0; i < cur; i++ {
						if backends[i].healthy.Load() && backends[i].healthySince > 0 && time.Duration(now-backends[i].healthySince)*time.Second >= restoreDur {
							activeIdx.Store(int32(i))
							s.logger.Infof("FAILOVER RESTORE: %s -> primary %s (healthy for %ds)", backends[cur].name, backends[i].name, now-backends[i].healthySince)
							break
						}
					}
				}
			}
		}
	}()

	// Public port listeners routing each incoming connection to the currently active healthy carrier
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
					// Try active backend first, then fall through to any other healthy backend
					for step := 0; step < len(backends); step++ {
						idx := (cur + step) % len(backends)
						dst := backends[idx].portMap[listenAddr]
						if dst == "" {
							continue
						}
						target, dialErr = net.DialTimeout("tcp", dst, 2*time.Second)
						if dialErr == nil {
							break
						}
					}
					if target == nil {
						return
					}
					defer target.Close()
					var wg sync.WaitGroup
					wg.Add(2)
					go func() { defer wg.Done(); _, _ = io.Copy(target, in); _ = target.Close() }()
					go func() { defer wg.Done(); _, _ = io.Copy(in, target); _ = in.Close() }()
					wg.Wait()
				}(cli)
			}
		}()
	}
}
