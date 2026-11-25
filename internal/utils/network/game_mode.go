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
)

type GameModeConfig struct {
	Token      string
	BindHost   string
	RemoteHost string
	BasePort   int
	Copies     int
	Ports      []string
}

type gameDedup struct {
	mu     sync.Mutex
	maxSeq uint64
	bits   [8]uint64 // 512-packet sliding deduplication window
}

func (d *gameDedup) accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if seq > d.maxSeq {
		shift := seq - d.maxSeq
		if shift >= 512 {
			d.bits = [8]uint64{}
		} else {
			for i := uint64(0); i < shift; i++ {
				// shift bitmap by 1 bit
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

func newGameAEAD(token string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte("bh-game-mode-v1:" + token))
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func sealGameDatagram(aead cipher.AEAD, pktType byte, seq uint64, flowID uint32, targetPort uint16, payload []byte) []byte {
	plain := make([]byte, 1+8+4+2+len(payload))
	plain[0] = pktType
	binary.BigEndian.PutUint64(plain[1:9], seq)
	binary.BigEndian.PutUint32(plain[9:13], flowID)
	binary.BigEndian.PutUint16(plain[13:15], targetPort)
	copy(plain[15:], payload)

	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, plain, nil)
}

func openGameDatagram(aead cipher.AEAD, raw []byte) (pktType byte, seq uint64, flowID uint32, targetPort uint16, payload []byte, ok bool) {
	ns := aead.NonceSize()
	if len(raw) <= ns+aead.Overhead()+15 {
		return 0, 0, 0, 0, nil, false
	}
	plain, err := aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil || len(plain) < 15 {
		return 0, 0, 0, 0, nil, false
	}
	return plain[0], binary.BigEndian.Uint64(plain[1:9]), binary.BigEndian.Uint32(plain[9:13]), binary.BigEndian.Uint16(plain[13:15]), plain[15:], true
}

func parseGamePortMap(entries []string) [][2]int {
	var out [][2]int
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		lp, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || lp < 1 || lp > 65535 {
			continue
		}
		rp := lp
		if len(parts) == 2 {
			_, pStr, err := net.SplitHostPort(strings.TrimSpace(parts[1]))
			if err == nil {
				if v, e := strconv.Atoi(pStr); e == nil && v >= 1 && v <= 65535 {
					rp = v
				}
			} else if v, e := strconv.Atoi(strings.TrimSpace(parts[1])); e == nil && v >= 1 && v <= 65535 {
				rp = v
			}
		}
		out = append(out, [2]int{lp, rp})
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
	portMap := parseGamePortMap(cfg.Ports)
	if len(portMap) == 0 || cfg.BasePort <= 0 {
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
		len(carrierConns), cfg.BasePort, cfg.BasePort+len(carrierConns)-1, len(portMap))

	type userFlow struct {
		id       uint32
		listener *net.UDPConn
		addr     *net.UDPAddr
		lastSeen int64
	}
	var flowMu sync.RWMutex
	flowsByKey := map[string]*userFlow{}
	flowsByID := map[uint32]*userFlow{}
	var nextFlowID uint32
	var seqCounter atomic.Uint64
	var downDedup gameDedup

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
				pktType, seq, flowID, _, payload, ok := openGameDatagram(aead, buf[:n])
				if !ok {
					continue
				}
				peerMu.Lock()
				peerAddrs[idx] = raddr
				peerMu.Unlock()

				if pktType == gamePktDown && downDedup.accept(seq) {
					flowMu.RLock()
					uf := flowsByID[flowID]
					flowMu.RUnlock()
					if uf != nil {
						_, _ = uf.listener.WriteToUDP(payload, uf.addr)
					}
				}
			}
		}()
	}

	// Listen on each public UDP game port
	for _, pair := range portMap {
		localPort, targetPort := pair[0], uint16(pair[1])
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
					uf = &userFlow{id: nextFlowID, listener: uln, addr: cliAddr}
					flowsByKey[key] = uf
					flowsByID[uf.id] = uf
				}
				uf.lastSeen = time.Now().Unix()
				flowMu.Unlock()

				seq := seqCounter.Add(1)
				pkt := sealGameDatagram(aead, gamePktUp, seq, uf.id, targetPort, buf[:n])
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

	var seqCounter atomic.Uint64
	var upDedup gameDedup
	var flowMu sync.Mutex
	flowConns := map[uint32]*net.UDPConn{}

	sendToAllCarriers := func(pkt []byte) {
		for _, c := range carrierConns {
			_, _ = c.Write(pkt)
		}
	}

	// Periodic beacons so Iran server always knows all carrier return addresses
	go func() {
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		for {
			pkt := sealGameDatagram(aead, gamePktBeacon, seqCounter.Add(1), 0, 0, []byte("hb"))
			sendToAllCarriers(pkt)
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
				pktType, seq, flowID, targetPort, payload, ok := openGameDatagram(aead, buf[:n])
				if !ok || pktType != gamePktUp || !upDedup.accept(seq) {
					continue
				}
				flowMu.Lock()
				lc, exists := flowConns[flowID]
				if !exists {
					dst, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", targetPort))
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
									respPkt := sealGameDatagram(aead, gamePktDown, seqCounter.Add(1), fid, 0, rb[:rn])
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
