package network

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	gamePktBeacon = 0x01
	gamePktUp     = 0x02
	gamePktDown   = 0x03
	gameHdrLen    = 1 + 4 + 8 + 4 + 2 // pktType(1) + epoch(4) + seq(8) + flowID(4) + targetPort(2) = 19 bytes
)

type GameModeConfig struct {
	Token      string
	BindHost   string
	RemoteHost string
	BasePort   int
	Copies     int
	Ports      []string
}

type gamePortRule struct {
	localPort  int
	targetPort int
	targetHost string
}

type gameDedup struct {
	mu     sync.Mutex
	epoch  uint32
	maxSeq uint64
	bits   [8]uint64 // 512-packet sliding deduplication window
}

// accept returns true only for the first arrival of (epoch, seq).
// When a peer restarts with a new random epoch, the window resets automatically.
func (d *gameDedup) accept(epoch uint32, seq uint64) bool {
	if seq == 0 || epoch == 0 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.epoch != epoch {
		d.epoch = epoch
		d.maxSeq = seq
		d.bits = [8]uint64{1}
		return true
	}
	if seq > d.maxSeq {
		shift := seq - d.maxSeq
		if shift >= 512 {
			d.bits = [8]uint64{}
		} else {
			for i := uint64(0); i < shift; i++ {
				var carry uint64
				for w := 0; w < 8; w++ {
					nextCarry := d.bits[w] >> 63
					d.bits[w] = (d.bits[w] << 1) | carry
					carry = nextCarry
				}
			}
		}
		d.maxSeq = seq
		d.bits[0] |= 1
		return true
	}
	diff := d.maxSeq - seq
	if diff >= 512 {
		return false
	}
	word := diff / 64
	bit := uint64(1) << (diff % 64)
	if d.bits[word]&bit != 0 {
		return false
	}
	d.bits[word] |= bit
	return true
}

func randomEpoch() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

func newGameAEAD(token string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte("bh-game-mode-v2:" + token))
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func sealGameDatagram(aead cipher.AEAD, pktType byte, epoch uint32, seq uint64, flowID uint32, targetPort uint16, payload []byte) []byte {
	plain := make([]byte, gameHdrLen+len(payload))
	plain[0] = pktType
	binary.BigEndian.PutUint32(plain[1:5], epoch)
	binary.BigEndian.PutUint64(plain[5:13], seq)
	binary.BigEndian.PutUint32(plain[13:17], flowID)
	binary.BigEndian.PutUint16(plain[17:19], targetPort)
	copy(plain[gameHdrLen:], payload)

	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, plain, nil)
}

func openGameDatagram(aead cipher.AEAD, raw []byte) (pktType byte, epoch uint32, seq uint64, flowID uint32, targetPort uint16, payload []byte, ok bool) {
	ns := aead.NonceSize()
	if len(raw) < ns+aead.Overhead()+gameHdrLen {
		return 0, 0, 0, 0, 0, nil, false
	}
	plain, err := aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil || len(plain) < gameHdrLen {
		return 0, 0, 0, 0, 0, nil, false
	}
	return plain[0],
		binary.BigEndian.Uint32(plain[1:5]),
		binary.BigEndian.Uint64(plain[5:13]),
		binary.BigEndian.Uint32(plain[13:17]),
		binary.BigEndian.Uint16(plain[17:19]),
		plain[gameHdrLen:],
		true
}

func parseGamePortMap(entries []string) []gamePortRule {
	var out []gamePortRule
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		lhs := strings.TrimSpace(parts[0])

		targetHost := "127.0.0.1"
		targetFixedPort := 0
		if len(parts) == 2 {
			rhs := strings.TrimSpace(parts[1])
			if h, pStr, err := net.SplitHostPort(rhs); err == nil {
				if h != "" {
					targetHost = h
				}
				if v, e := strconv.Atoi(pStr); e == nil && v >= 1 && v <= 65535 {
					targetFixedPort = v
				}
			} else if v, e := strconv.Atoi(rhs); e == nil && v >= 1 && v <= 65535 {
				targetFixedPort = v
			}
		}

		if strings.Contains(lhs, "-") {
			rp := strings.SplitN(lhs, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(rp[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(rp[1]))
			if e1 == nil && e2 == nil && lo >= 1 && hi <= 65535 && hi >= lo && hi-lo <= 512 {
				for p := lo; p <= hi; p++ {
					tp := p
					if targetFixedPort > 0 {
						tp = targetFixedPort
					}
					out = append(out, gamePortRule{localPort: p, targetPort: tp, targetHost: targetHost})
				}
			}
			continue
		}

		lp, err := strconv.Atoi(lhs)
		if err != nil || lp < 1 || lp > 65535 {
			continue
		}
		tp := lp
		if targetFixedPort > 0 {
			tp = targetFixedPort
		}
		out = append(out, gamePortRule{localPort: lp, targetPort: tp, targetHost: targetHost})
	}
	return out
}

// StartGameModeServer accelerates configured UDP game ports by duplicating every datagram
// across `Copies` independent encrypted UDP carrier ports (first arrival wins).
func StartGameModeServer(ctx context.Context, cfg GameModeConfig, logger *logrus.Logger) {
	if cfg.Copies < 1 {
		cfg.Copies = 3
	}
	if cfg.Copies > 4 {
		cfg.Copies = 4
	}
	portRules := parseGamePortMap(cfg.Ports)
	if len(portRules) == 0 || cfg.BasePort <= 0 {
		return
	}
	aead, err := newGameAEAD(cfg.Token)
	if err != nil {
		logger.Errorf("game-mode cipher init failed: %v", err)
		return
	}

	carrierConns := make([]*net.UDPConn, 0, cfg.Copies)
	peerAddrs := make([]*net.UDPAddr, cfg.Copies)
	var peerMu sync.RWMutex
	for i := 0; i < cfg.Copies; i++ {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", cfg.BindHost, cfg.BasePort+i))
		if err != nil {
			continue
		}
		c, err := net.ListenUDP("udp", addr)
		if err != nil {
			logger.Warnf("game-mode carrier port %d busy: %v", cfg.BasePort+i, err)
			continue
		}
		carrierConns = append(carrierConns, c)
	}
	if len(carrierConns) == 0 {
		return
	}
	logger.Infof("Game Mode UDP accelerator active on %d carrier ports (%d..%d) for %d game ports",
		len(carrierConns), cfg.BasePort, cfg.BasePort+len(carrierConns)-1, len(portRules))

	type userFlow struct {
		id       uint32
		key      string
		listener *net.UDPConn
		addr     *net.UDPAddr
		lastSeen atomic.Int64
	}
	var flowMu sync.RWMutex
	flowsByKey := map[string]*userFlow{}
	flowsByID := map[uint32]*userFlow{}
	var nextFlowID uint32
	srvEpoch := randomEpoch()
	var seqCounter atomic.Uint64
	var downDedup gameDedup
	var beaconDedup gameDedup

	// Background flow reaper prevents memory leaks on long-running game servers
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-90 * time.Second).Unix()
				flowMu.Lock()
				for id, uf := range flowsByID {
					if uf.lastSeen.Load() < cutoff {
						delete(flowsByID, id)
						delete(flowsByKey, uf.key)
					}
				}
				flowMu.Unlock()
			}
		}
	}()

	// Listen for carrier packets (beacons + downlink game datagrams)
	for i, cc := range carrierConns {
		idx := i
		conn := cc
		go func() {
			defer conn.Close()
			buf := make([]byte, 8192)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, raddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				pktType, ep, seq, flowID, _, payload, ok := openGameDatagram(aead, buf[:n])
				if !ok {
					continue
				}
				if pktType == gamePktBeacon {
					if beaconDedup.accept(ep, seq) {
						peerMu.Lock()
						peerAddrs[idx] = raddr
						peerMu.Unlock()
					}
					continue
				}
				if pktType == gamePktDown {
					peerMu.Lock()
					peerAddrs[idx] = raddr
					peerMu.Unlock()
					if downDedup.accept(ep, seq) {
						flowMu.RLock()
						uf := flowsByID[flowID]
						flowMu.RUnlock()
						if uf != nil {
							uf.lastSeen.Store(time.Now().Unix())
							_, _ = uf.listener.WriteToUDP(payload, uf.addr)
						}
					}
				}
			}
		}()
	}

	// Listen on each public UDP game port
	for _, rule := range portRules {
		localPort, targetPort := rule.localPort, uint16(rule.targetPort)
		go func() {
			uaddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", localPort))
			if err != nil {
				return
			}
			uln, err := net.ListenUDP("udp", uaddr)
			if err != nil {
				logger.Warnf("game-mode listener :%d failed: %v", localPort, err)
				return
			}
			defer uln.Close()
			buf := make([]byte, 4096)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_ = uln.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, cliAddr, err := uln.ReadFromUDP(buf)
				if err != nil || n == 0 {
					continue
				}
				key := fmt.Sprintf("%d|%s", localPort, cliAddr.String())
				flowMu.Lock()
				uf, exists := flowsByKey[key]
				if !exists {
					nextFlowID++
					uf = &userFlow{id: nextFlowID, key: key, listener: uln, addr: cliAddr}
					flowsByKey[key] = uf
					flowsByID[uf.id] = uf
				}
				uf.lastSeen.Store(time.Now().Unix())
				flowMu.Unlock()

				seq := seqCounter.Add(1)
				pkt := sealGameDatagram(aead, gamePktUp, srvEpoch, seq, uf.id, targetPort, buf[:n])
				peerMu.RLock()
				for i, c := range carrierConns {
					if i < len(peerAddrs) && peerAddrs[i] != nil {
						_, _ = c.WriteToUDP(pkt, peerAddrs[i])
					}
				}
				peerMu.RUnlock()
			}
		}()
	}
}

// StartGameModeClient runs on the Foreign node, maintaining multi-port UDP carriers to the Iran server
// and forwarding deduplicated game datagrams directly to local UDP targets.
func StartGameModeClient(ctx context.Context, cfg GameModeConfig, logger *logrus.Logger) {
	if cfg.Copies < 1 {
		cfg.Copies = 3
	}
	if cfg.Copies > 4 {
		cfg.Copies = 4
	}
	if cfg.BasePort <= 0 || cfg.RemoteHost == "" {
		return
	}
	aead, err := newGameAEAD(cfg.Token)
	if err != nil {
		logger.Errorf("game-mode client cipher init failed: %v", err)
		return
	}

	// Optional per-port custom target host map if game_ports is also specified on client
	targetHostByPort := map[uint16]string{}
	for _, r := range parseGamePortMap(cfg.Ports) {
		if r.targetHost != "" && r.targetHost != "127.0.0.1" {
			targetHostByPort[uint16(r.targetPort)] = r.targetHost
		}
	}

	carrierConns := make([]*net.UDPConn, 0, cfg.Copies)
	for i := 0; i < cfg.Copies; i++ {
		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.RemoteHost, strconv.Itoa(cfg.BasePort+i)))
		if err != nil {
			continue
		}
		c, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			continue
		}
		carrierConns = append(carrierConns, c)
	}
	if len(carrierConns) == 0 {
		return
	}
	logger.Infof("Game Mode UDP client connected on %d parallel carrier ports (%s:%d..%d)",
		len(carrierConns), cfg.RemoteHost, cfg.BasePort, cfg.BasePort+len(carrierConns)-1)

	cliEpoch := randomEpoch()
	var seqCounter atomic.Uint64
	var beaconSeq atomic.Uint64
	var upDedup gameDedup
	var flowMu sync.Mutex
	flowConns := map[uint32]*net.UDPConn{}

	sendToAllCarriers := func(pkt []byte) {
		for _, c := range carrierConns {
			_, _ = c.Write(pkt)
		}
	}

	// Send independent beacon seq per carrier so Iran server records all carrier addresses
	go func() {
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		for {
			for _, c := range carrierConns {
				pkt := sealGameDatagram(aead, gamePktBeacon, cliEpoch, beaconSeq.Add(1), 0, 0, []byte("hb"))
				_, _ = c.Write(pkt)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	for _, cc := range carrierConns {
		conn := cc
		go func() {
			defer conn.Close()
			buf := make([]byte, 8192)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					continue
				}
				pktType, ep, seq, flowID, targetPort, payload, ok := openGameDatagram(aead, buf[:n])
				if !ok || pktType != gamePktUp || !upDedup.accept(ep, seq) {
					continue
				}
				flowMu.Lock()
				lc, exists := flowConns[flowID]
				if !exists {
					dstHost := targetHostByPort[targetPort]
					if dstHost == "" {
						dstHost = "127.0.0.1"
					}
					dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dstHost, strconv.Itoa(int(targetPort))))
					if err == nil {
						if dconn, derr := net.DialUDP("udp", nil, dst); derr == nil {
							lc = dconn
							flowConns[flowID] = lc
							go func(fid uint32, c *net.UDPConn) {
								defer func() {
									flowMu.Lock()
									delete(flowConns, fid)
									flowMu.Unlock()
									c.Close()
								}()
								rb := make([]byte, 4096)
								for {
									_ = c.SetReadDeadline(time.Now().Add(65 * time.Second))
									rn, rerr := c.Read(rb)
									if rerr != nil {
										return
									}
									respPkt := sealGameDatagram(aead, gamePktDown, cliEpoch, seqCounter.Add(1), fid, 0, rb[:rn])
									sendToAllCarriers(respPkt)
								}
							}(flowID, lc)
						}
					}
				}
				flowMu.Unlock()
				if lc != nil {
					_, _ = lc.Write(payload)
				}
			}
		}()
	}
}
