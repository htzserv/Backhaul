package network

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

const (
	parallaxMagic     = "BHP2"
	parallaxRecData   = 0x01
	parallaxRecPad    = 0x02
	parallaxMaxRecLen = 64 * 1024
	parallaxSkewSec   = 300 // ±5 minutes anti-replay tolerance
)

type ParallaxParams struct {
	Token       string
	Lanes       int
	WarmupMin   int
	WarmupMax   int
	StallSec    int
	DialTimeout time.Duration
	KeepAlive   time.Duration
	NoDelay     bool
	KCP         KCPParams
}

type parallaxCipherPair struct {
	c2sAEAD   cipher.AEAD
	s2cAEAD   cipher.AEAD
	c2sPrefix [4]byte
	s2cPrefix [4]byte
}

func deriveParallaxAEADs(token string, nonce []byte) (*parallaxCipherPair, error) {
	mk := func(dir string) (cipher.AEAD, [4]byte, error) {
		h := sha256.New()
		h.Write([]byte("bh-parallax-v2-" + dir + ":"))
		h.Write([]byte(token))
		h.Write(nonce)
		key := h.Sum(nil)

		ph := sha256.New()
		ph.Write([]byte("bh-parallax-np-" + dir + ":"))
		ph.Write(nonce)
		ph.Write([]byte(token))
		var pfx [4]byte
		copy(pfx[:], ph.Sum(nil)[:4])

		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, pfx, err
		}
		aead, err := cipher.NewGCM(blk)
		return aead, pfx, err
	}
	c2s, c2sP, err := mk("c2s")
	if err != nil {
		return nil, err
	}
	s2c, s2cP, err := mk("s2c")
	if err != nil {
		return nil, err
	}
	return &parallaxCipherPair{
		c2sAEAD:   c2s,
		s2cAEAD:   s2c,
		c2sPrefix: c2sP,
		s2cPrefix: s2cP,
	}, nil
}

func makeFrameNonce(prefix [4]byte, seq uint64) [12]byte {
	var n [12]byte
	copy(n[:4], prefix[:])
	binary.BigEndian.PutUint64(n[4:12], seq)
	return n
}

func sessionAddr(sessID [16]byte) *net.UDPAddr {
	h := sha256.Sum256(sessID[:])
	port := int(binary.BigEndian.Uint16(h[3:5]))
	if port < 1024 {
		port += 1024
	}
	return &net.UDPAddr{
		IP:   net.IPv4(10, h[0], h[1], h[2]),
		Port: port,
	}
}

type parallaxLane struct {
	conn      net.Conn
	rAEAD     cipher.AEAD
	wAEAD     cipher.AEAD
	rPrefix   [4]byte
	wPrefix   [4]byte
	rSeq      uint64
	wSeq      uint64
	sendCh    chan []byte
	lastRecv  atomic.Int64
	closed    atomic.Bool
	closeOnce sync.Once
}

func (l *parallaxLane) Close() {
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		_ = l.conn.Close()
	})
}

func (l *parallaxLane) writeRecord(recType byte, payload []byte) error {
	if l.closed.Load() {
		return net.ErrClosed
	}
	plain := make([]byte, 1+len(payload))
	plain[0] = recType
	copy(plain[1:], payload)

	l.wSeq++
	nonce := makeFrameNonce(l.wPrefix, l.wSeq)
	ct := l.wAEAD.Seal(nil, nonce[:], plain, nil)

	frame := make([]byte, 2+len(ct))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(ct)))
	copy(frame[2:], ct)

	_ = l.conn.SetWriteDeadline(time.Now().Add(6 * time.Second))
	_, err := l.conn.Write(frame)
	return err
}

func (l *parallaxLane) readRecord(stallTimeout time.Duration) (byte, []byte, error) {
	var lenBuf [2]byte
	_ = l.conn.SetReadDeadline(time.Now().Add(stallTimeout))
	if _, err := io.ReadFull(l.conn, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	ctLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if ctLen < l.rAEAD.Overhead()+1 || ctLen > parallaxMaxRecLen+l.rAEAD.Overhead()+1 {
		return 0, nil, fmt.Errorf("parallax invalid frame length: %d", ctLen)
	}
	ct := make([]byte, ctLen)
	_ = l.conn.SetReadDeadline(time.Now().Add(stallTimeout))
	if _, err := io.ReadFull(l.conn, ct); err != nil {
		return 0, nil, err
	}
	l.rSeq++
	nonce := makeFrameNonce(l.rPrefix, l.rSeq)
	plain, err := l.rAEAD.Open(nil, nonce[:], ct, nil)
	if err != nil || len(plain) < 1 {
		return 0, nil, fmt.Errorf("parallax AEAD auth failed: %w", err)
	}
	l.lastRecv.Store(time.Now().UnixNano())
	return plain[0], plain[1:], nil
}

func (l *parallaxLane) writerLoop(ctx context.Context) {
	defer l.Close()
	idleTicker := time.NewTicker(1 * time.Second)
	defer idleTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-l.sendCh:
			if !ok {
				return
			}
			if err := l.writeRecord(parallaxRecData, pkt); err != nil {
				return
			}
		case <-idleTicker.C:
			if l.closed.Load() {
				return
			}
			pad := make([]byte, 16+mrand.Intn(48))
			_, _ = rand.Read(pad)
			if err := l.writeRecord(parallaxRecPad, pad); err != nil {
				return
			}
		}
	}
}

type parallaxInbound struct {
	data []byte
	addr net.Addr
}

// parallaxSessionConn wraps *kcp.UDPSession so Close() tears down the underlying
// ParallaxClientPacketConn and all its TCP lanes & maintainer goroutines with zero leaks.
type parallaxSessionConn struct {
	*kcp.UDPSession
	pc        *ParallaxClientPacketConn
	closeOnce sync.Once
}

func (p *parallaxSessionConn) Close() error {
	var err error
	p.closeOnce.Do(func() {
		err = p.UDPSession.Close()
		_ = p.pc.Close()
	})
	return err
}

// ParallaxClientPacketConn multiplexes one KCP+FEC session over N parallel AEAD-authenticated TCP lanes.
type ParallaxClientPacketConn struct {
	ctx        context.Context
	cancel     context.CancelFunc
	remoteAddr string
	params     ParallaxParams
	sessID     [16]byte
	peerAddr   *net.UDPAddr
	localAddr  *net.UDPAddr

	mu        sync.RWMutex
	lanes     []*parallaxLane
	stickyIdx int
	recvCh    chan parallaxInbound
	closeOnce sync.Once
	closed    atomic.Bool

	readDlMu  sync.Mutex
	readTimer *time.Timer
	readDlCh  chan struct{}
	readExp   atomic.Bool
}

func DialParallaxKCP(parentCtx context.Context, remoteAddr string, params ParallaxParams) (net.Conn, error) {
	if params.Lanes < 2 {
		params.Lanes = 4
	}
	if params.StallSec <= 0 {
		params.StallSec = 4
	}
	ctx, cancel := context.WithCancel(parentCtx)
	var sid [16]byte
	_, _ = rand.Read(sid[:])

	pc := &ParallaxClientPacketConn{
		ctx:        ctx,
		cancel:     cancel,
		remoteAddr: remoteAddr,
		params:     params,
		sessID:     sid,
		peerAddr:   sessionAddr(sid),
		localAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		lanes:      make([]*parallaxLane, params.Lanes),
		recvCh:     make(chan parallaxInbound, 512),
		readDlCh:   make(chan struct{}),
	}

	firstLane, err := pc.dialOneLane(0)
	if err != nil {
		cancel()
		return nil, err
	}
	pc.lanes[0] = firstLane
	go pc.runClientLane(0, firstLane)

	for i := 1; i < params.Lanes; i++ {
		go pc.maintainClientLane(i)
	}

	block, err := NewKCPBlockCrypt(params.KCP.Crypt, params.KCP.Key)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	sess, err := kcp.NewConn2(pc.peerAddr, block, params.KCP.DataShard, params.KCP.ParityShard, pc)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	TuneKCPSession(sess, params.KCP)
	return &parallaxSessionConn{UDPSession: sess, pc: pc}, nil
}

func (pc *ParallaxClientPacketConn) dialOneLane(laneIdx int) (*parallaxLane, error) {
	raw, err := TcpDialer(pc.ctx, pc.remoteAddr, "", pc.params.DialTimeout, pc.params.KeepAlive, pc.params.NoDelay, 1, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	if nonce[0] == 0x16 {
		nonce[0] ^= 0x5A
	}
	cp, err := deriveParallaxAEADs(pc.params.Token, nonce)
	if err != nil {
		raw.Close()
		return nil, err
	}

	wMin, wMax := pc.params.WarmupMin, pc.params.WarmupMax
	if wMin <= 0 {
		wMin = 32 * 1024
	}
	if wMax < wMin {
		wMax = wMin + 16*1024
	}
	warmupLen := wMin
	if wMax > wMin {
		warmupLen = wMin + mrand.Intn(wMax-wMin+1)
	}

	// Authenticated handshake header (33 bytes plain -> 49 bytes with GCM tag):
	// magic(4) | sessID(16) | laneID(1) | unixSec(8) | warmupLen(4)
	hdrPlain := make([]byte, 33)
	copy(hdrPlain[0:4], []byte(parallaxMagic))
	copy(hdrPlain[4:20], pc.sessID[:])
	hdrPlain[20] = byte(laneIdx)
	binary.BigEndian.PutUint64(hdrPlain[21:29], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint32(hdrPlain[29:33], uint32(warmupLen))

	hsNonce := makeFrameNonce(cp.c2sPrefix, 0)
	hdrSealed := cp.c2sAEAD.Seal(nil, hsNonce[:], hdrPlain, nonce)

	_ = raw.SetWriteDeadline(time.Now().Add(8 * time.Second))
	if _, err := raw.Write(nonce); err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := raw.Write(hdrSealed); err != nil {
		raw.Close()
		return nil, err
	}

	// Send randomized high-entropy warm-up padding to mask lane start pattern
	rem := warmupLen
	padBuf := make([]byte, 16*1024)
	for rem > 0 {
		chunk := len(padBuf)
		if rem < chunk {
			chunk = rem
		}
		_, _ = rand.Read(padBuf[:chunk])
		if _, err := raw.Write(padBuf[:chunk]); err != nil {
			raw.Close()
			return nil, err
		}
		rem -= chunk
	}
	_ = raw.SetWriteDeadline(time.Time{})

	ln := &parallaxLane{
		conn:    raw,
		rAEAD:   cp.s2cAEAD,
		wAEAD:   cp.c2sAEAD,
		rPrefix: cp.s2cPrefix,
		wPrefix: cp.c2sPrefix,
		sendCh:  make(chan []byte, 128),
	}
	ln.lastRecv.Store(time.Now().UnixNano())
	return ln, nil
}

func (pc *ParallaxClientPacketConn) runClientLane(idx int, ln *parallaxLane) {
	go ln.writerLoop(pc.ctx)
	stallDur := time.Duration(pc.params.StallSec) * time.Second
	if stallDur < 3*time.Second {
		stallDur = 3 * time.Second
	}
	for {
		recType, payload, err := ln.readRecord(stallDur)
		if err != nil {
			ln.Close()
			break
		}
		if recType == parallaxRecData && len(payload) > 0 {
			select {
			case pc.recvCh <- parallaxInbound{data: payload, addr: pc.peerAddr}:
			default:
			}
		}
	}
	pc.mu.Lock()
	if pc.lanes[idx] == ln {
		pc.lanes[idx] = nil
	}
	pc.mu.Unlock()
	if !pc.closed.Load() {
		go pc.maintainClientLane(idx)
	}
}

func (pc *ParallaxClientPacketConn) maintainClientLane(idx int) {
	backoff := 250 * time.Millisecond
	for {
		select {
		case <-pc.ctx.Done():
			return
		default:
		}
		ln, err := pc.dialOneLane(idx)
		if err != nil {
			timer := time.NewTimer(backoff)
			select {
			case <-pc.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < 3*time.Second {
				backoff *= 2
			}
			continue
		}
		pc.mu.Lock()
		pc.lanes[idx] = ln
		pc.mu.Unlock()
		pc.runClientLane(idx, ln)
		return
	}
}

func (pc *ParallaxClientPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if pc.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if pc.readExp.Load() {
		return 0, nil, os.ErrDeadlineExceeded
	}
	pc.readDlMu.Lock()
	dlCh := pc.readDlCh
	pc.readDlMu.Unlock()

	select {
	case <-pc.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-dlCh:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt := <-pc.recvCh:
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	}
}

func (pc *ParallaxClientPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if pc.closed.Load() {
		return 0, net.ErrClosed
	}
	cp := make([]byte, len(p))
	copy(cp, p)

	pc.mu.Lock()
	nLanes := len(pc.lanes)
	start := pc.stickyIdx
	if start >= nLanes {
		start = 0
	}
	for step := 0; step < nLanes; step++ {
		idx := (start + step) % nLanes
		ln := pc.lanes[idx]
		if ln == nil || ln.closed.Load() {
			continue
		}
		select {
		case ln.sendCh <- cp:
			pc.stickyIdx = idx
			pc.mu.Unlock()
			return len(p), nil
		default:
		}
	}
	pc.mu.Unlock()
	return len(p), nil
}

func (pc *ParallaxClientPacketConn) Close() error {
	pc.closeOnce.Do(func() {
		pc.closed.Store(true)
		pc.readDlMu.Lock()
		if pc.readTimer != nil {
			pc.readTimer.Stop()
			pc.readTimer = nil
		}
		pc.readDlMu.Unlock()
		pc.cancel()
		pc.mu.Lock()
		for i, ln := range pc.lanes {
			if ln != nil {
				ln.Close()
				pc.lanes[i] = nil
			}
		}
		pc.mu.Unlock()
	})
	return nil
}

func (pc *ParallaxClientPacketConn) LocalAddr() net.Addr              { return pc.localAddr }
func (pc *ParallaxClientPacketConn) SetDeadline(t time.Time) error     { return pc.SetReadDeadline(t) }
func (pc *ParallaxClientPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
func (pc *ParallaxClientPacketConn) SetReadDeadline(t time.Time) error {
	pc.readDlMu.Lock()
	defer pc.readDlMu.Unlock()
	if pc.readTimer != nil {
		pc.readTimer.Stop()
		pc.readTimer = nil
	}
	pc.readExp.Store(false)
	pc.readDlCh = make(chan struct{})
	ch := pc.readDlCh
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		pc.readExp.Store(true)
		close(ch)
		return nil
	}
	pc.readTimer = time.AfterFunc(d, func() {
		pc.readExp.Store(true)
		close(ch)
	})
	return nil
}

// ── Server Side Parallax PacketConn ──────────────────────────────────────────

type parallaxSrvSession struct {
	addr      *net.UDPAddr
	mu        sync.RWMutex
	lanes     []*parallaxLane
	stickyIdx int
	lastSeen  atomic.Int64
}

type ParallaxServerPacketConn struct {
	ctx       context.Context
	cancel    context.CancelFunc
	tcpLn     net.Listener
	params    ParallaxParams
	mu        sync.RWMutex
	sessions  map[string]*parallaxSrvSession
	nonceMu   sync.Mutex
	seenNonce map[[32]byte]int64
	recvCh    chan parallaxInbound
	closeOnce sync.Once
	closed    atomic.Bool
}

func ListenParallaxKCP(parentCtx context.Context, bindAddr string, params ParallaxParams) (*kcp.Listener, error) {
	if params.StallSec <= 0 {
		params.StallSec = 4
	}
	tcpLn, err := ListenWithBuffers("tcp", bindAddr, params.KCP.SO_RCVBUF, params.KCP.SO_SNDBUF, 0, params.KeepAlive, !params.NoDelay)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parentCtx)
	spc := &ParallaxServerPacketConn{
		ctx:       ctx,
		cancel:    cancel,
		tcpLn:     tcpLn,
		params:    params,
		sessions:  make(map[string]*parallaxSrvSession),
		seenNonce: make(map[[32]byte]int64),
		recvCh:    make(chan parallaxInbound, 1024),
	}
	go spc.acceptLoop()
	go spc.reapSessions()
	go func() {
		<-ctx.Done()
		_ = spc.Close()
	}()

	block, err := NewKCPBlockCrypt(params.KCP.Crypt, params.KCP.Key)
	if err != nil {
		_ = spc.Close()
		return nil, err
	}
	kcpLn, err := kcp.ServeConn(block, params.KCP.DataShard, params.KCP.ParityShard, spc)
	if err != nil {
		_ = spc.Close()
		return nil, err
	}
	return kcpLn, nil
}

func (s *ParallaxServerPacketConn) acceptLoop() {
	for {
		raw, err := s.tcpLn.Accept()
		if err != nil {
			if s.closed.Load() || s.ctx.Err() != nil {
				return
			}
			continue
		}
		go s.handleIncomingLane(raw)
	}
}

func (s *ParallaxServerPacketConn) recordNonce(nonce []byte) bool {
	var key [32]byte
	copy(key[:], nonce)
	now := time.Now().Unix()
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	if _, dup := s.seenNonce[key]; dup {
		return false
	}
	if len(s.seenNonce) > 8192 {
		cutoff := now - parallaxSkewSec*2
		for k, ts := range s.seenNonce {
			if ts < cutoff {
				delete(s.seenNonce, k)
			}
		}
	}
	s.seenNonce[key] = now
	return true
}

func (s *ParallaxServerPacketConn) handleIncomingLane(raw net.Conn) {
	_ = raw.SetReadDeadline(time.Now().Add(8 * time.Second))
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(raw, nonce); err != nil {
		raw.Close()
		return
	}
	cp, err := deriveParallaxAEADs(s.params.Token, nonce)
	if err != nil {
		raw.Close()
		return
	}

	hdrSealed := make([]byte, 33+cp.c2sAEAD.Overhead())
	if _, err := io.ReadFull(raw, hdrSealed); err != nil {
		raw.Close()
		return
	}
	hsNonce := makeFrameNonce(cp.c2sPrefix, 0)
	hdr, err := cp.c2sAEAD.Open(nil, hsNonce[:], hdrSealed, nonce)
	if err != nil || len(hdr) != 33 || string(hdr[0:4]) != parallaxMagic {
		raw.Close()
		return
	}

	ts := int64(binary.BigEndian.Uint64(hdr[21:29]))
	diff := time.Now().Unix() - ts
	if diff < -parallaxSkewSec || diff > parallaxSkewSec {
		raw.Close()
		return
	}
	if !s.recordNonce(nonce) {
		raw.Close()
		return
	}

	var sid [16]byte
	copy(sid[:], hdr[4:20])
	warmupLen := int(binary.BigEndian.Uint32(hdr[29:33]))
	if warmupLen > 512*1024 {
		raw.Close()
		return
	}

	rem := warmupLen
	discard := make([]byte, 16*1024)
	for rem > 0 {
		chunk := len(discard)
		if rem < chunk {
			chunk = rem
		}
		if _, err := io.ReadFull(raw, discard[:chunk]); err != nil {
			raw.Close()
			return
		}
		rem -= chunk
	}
	_ = raw.SetReadDeadline(time.Time{})

	ln := &parallaxLane{
		conn:    raw,
		rAEAD:   cp.c2sAEAD,
		wAEAD:   cp.s2cAEAD,
		rPrefix: cp.c2sPrefix,
		wPrefix: cp.s2cPrefix,
		sendCh:  make(chan []byte, 128),
	}
	ln.lastRecv.Store(time.Now().UnixNano())

	addr := sessionAddr(sid)
	key := addr.String()

	s.mu.Lock()
	sess, ok := s.sessions[key]
	if !ok {
		sess = &parallaxSrvSession{addr: addr}
		s.sessions[key] = sess
	}
	s.mu.Unlock()
	sess.lastSeen.Store(time.Now().Unix())

	sess.mu.Lock()
	sess.lanes = append(sess.lanes, ln)
	sess.mu.Unlock()

	go ln.writerLoop(s.ctx)
	stallDur := time.Duration(s.params.StallSec+3) * time.Second
	for {
		recType, payload, err := ln.readRecord(stallDur)
		if err != nil {
			ln.Close()
			break
		}
		sess.lastSeen.Store(time.Now().Unix())
		if recType == parallaxRecData && len(payload) > 0 {
			select {
			case s.recvCh <- parallaxInbound{data: payload, addr: addr}:
			default:
			}
		}
	}

	sess.mu.Lock()
	kept := sess.lanes[:0]
	for _, x := range sess.lanes {
		if x != ln && !x.closed.Load() {
			kept = append(kept, x)
		}
	}
	sess.lanes = kept
	sess.mu.Unlock()
}

func (s *ParallaxServerPacketConn) reapSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * time.Minute).Unix()
			s.mu.Lock()
			for k, sess := range s.sessions {
				sess.mu.RLock()
				nLanes := len(sess.lanes)
				sess.mu.RUnlock()
				if nLanes == 0 && sess.lastSeen.Load() < cutoff {
					delete(s.sessions, k)
				}
			}
			s.mu.Unlock()

			nonceCutoff := time.Now().Unix() - parallaxSkewSec*2
			s.nonceMu.Lock()
			for k, ts := range s.seenNonce {
				if ts < nonceCutoff {
					delete(s.seenNonce, k)
				}
			}
			s.nonceMu.Unlock()
		}
	}
}

func (s *ParallaxServerPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if s.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	select {
	case <-s.ctx.Done():
		return 0, nil, net.ErrClosed
	case pkt := <-s.recvCh:
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	}
}

func (s *ParallaxServerPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s.closed.Load() || addr == nil {
		return 0, net.ErrClosed
	}
	s.mu.RLock()
	sess := s.sessions[addr.String()]
	s.mu.RUnlock()
	if sess == nil {
		return len(p), nil
	}
	cp := make([]byte, len(p))
	copy(cp, p)

	sess.mu.Lock()
	nLanes := len(sess.lanes)
	if nLanes == 0 {
		sess.mu.Unlock()
		return len(p), nil
	}
	start := sess.stickyIdx % nLanes
	for step := 0; step < nLanes; step++ {
		idx := (start + step) % nLanes
		ln := sess.lanes[idx]
		if ln == nil || ln.closed.Load() {
			continue
		}
		select {
		case ln.sendCh <- cp:
			sess.stickyIdx = idx
			sess.mu.Unlock()
			return len(p), nil
		default:
		}
	}
	sess.mu.Unlock()
	return len(p), nil
}

func (s *ParallaxServerPacketConn) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		_ = s.tcpLn.Close()
		s.mu.Lock()
		for _, sess := range s.sessions {
			sess.mu.Lock()
			for _, ln := range sess.lanes {
				ln.Close()
			}
			sess.lanes = nil
			sess.mu.Unlock()
		}
		s.mu.Unlock()
	})
	return nil
}

func (s *ParallaxServerPacketConn) LocalAddr() net.Addr               { return s.tcpLn.Addr() }
func (s *ParallaxServerPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (s *ParallaxServerPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (s *ParallaxServerPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
