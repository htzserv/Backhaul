package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var xhttpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

type XHTTPDialConfig struct {
	RemoteAddr      string
	EdgeIP          string
	SNI             string
	HostHeader      string
	BasePath        string
	Purpose         string
	Mode            string
	Token           string
	UTLSFingerprint string
	TLSFragment     bool
	TLS             bool
	DialTimeout     time.Duration
	KeepAlive       time.Duration
	NoDelay         bool
	SharedH2Client  *http.Client
	SharedH1Client  *http.Client
}

type XHTTPSharedClients struct {
	H2 *http.Client
	H1 *http.Client
}

func NewXHTTPSharedClients(cfg XHTTPDialConfig) (*XHTTPSharedClients, error) {
	dialTarget := cfg.RemoteAddr
	if cfg.EdgeIP != "" {
		_, port, err := net.SplitHostPort(cfg.RemoteAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid remote_addr: %w", err)
		}
		dialTarget = net.JoinHostPort(PickEdgeIP(cfg.EdgeIP), port)
	}

	hostHeader := cfg.HostHeader
	if hostHeader == "" {
		hostHeader = cfg.RemoteAddr
	}
	sniHost := cfg.SNI
	if sniHost == "" {
		sniHost = hostHeader
	}
	if h, _, err := net.SplitHostPort(sniHost); err == nil {
		sniHost = h
	}

	res := &XHTTPSharedClients{}
	if cfg.TLS {
		h2t := &http2.Transport{
			DialTLSContext: func(dCtx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				raw, err := TcpDialer(dCtx, dialTarget, "", cfg.DialTimeout, cfg.KeepAlive, cfg.NoDelay, 2, 0, 0, 0)
				if err != nil {
					return nil, err
				}
				hsCtx, cancel := context.WithTimeout(dCtx, cfg.DialTimeout)
				defer cancel()
				return DialUTLSFragmented(hsCtx, raw, sniHost, cfg.UTLSFingerprint, []string{"h2"}, cfg.TLSFragment)
			},
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		}
		res.H2 = &http.Client{Transport: h2t}

		h1t := &http.Transport{
			DialTLSContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
				raw, err := TcpDialer(dCtx, dialTarget, "", cfg.DialTimeout, cfg.KeepAlive, cfg.NoDelay, 2, 0, 0, 0)
				if err != nil {
					return nil, err
				}
				hsCtx, cancel := context.WithTimeout(dCtx, cfg.DialTimeout)
				defer cancel()
				return DialUTLSFragmented(hsCtx, raw, sniHost, cfg.UTLSFingerprint, []string{"http/1.1"}, cfg.TLSFragment)
			},
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		}
		res.H1 = &http.Client{Transport: h1t}
	} else {
		h1t := &http.Transport{
			DialContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
				return TcpDialer(dCtx, dialTarget, "", cfg.DialTimeout, cfg.KeepAlive, cfg.NoDelay, 2, 0, 0, 0)
			},
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		}
		res.H1 = &http.Client{Transport: h1t}
	}
	return res, nil
}

func (sc *XHTTPSharedClients) Close() {
	if sc == nil {
		return
	}
	if sc.H2 != nil {
		sc.H2.CloseIdleConnections()
	}
	if sc.H1 != nil {
		sc.H1.CloseIdleConnections()
	}
}

type staticAddr struct {
	network string
	str     string
}

func (a staticAddr) Network() string { return a.network }
func (a staticAddr) String() string  { return a.str }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type xhttpPacket struct {
	seq  uint64
	data []byte
}

type XHTTPClientConn struct {
	ctx        context.Context
	cancel     context.CancelFunc
	client     *http.Client
	ownClient  bool
	baseURL    string
	hostHeader string
	token      string
	mode       string

	downBody io.ReadCloser
	upWriter *io.PipeWriter

	seq        uint64
	writeMu    sync.Mutex
	upCh       chan xhttpPacket
	writeErrMu sync.Mutex
	writeErr   error

	localAddr  net.Addr
	remoteAddr net.Addr

	closeOnce sync.Once
	closed    atomic.Bool

	readDeadlineMu  sync.Mutex
	readTimer       *time.Timer
	readTimedOut    atomic.Bool
	writeDeadlineMu sync.Mutex
	writeTimer      *time.Timer
	writeTimedOut   atomic.Bool
}

func DialXHTTP(parentCtx context.Context, cfg XHTTPDialConfig) (net.Conn, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	dialTarget := cfg.RemoteAddr
	if cfg.EdgeIP != "" {
		_, port, err := net.SplitHostPort(cfg.RemoteAddr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("invalid remote_addr: %w", err)
		}
		dialTarget = net.JoinHostPort(PickEdgeIP(cfg.EdgeIP), port)
	}

	hostHeader := cfg.HostHeader
	if hostHeader == "" {
		hostHeader = cfg.RemoteAddr
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" || mode == "auto" {
		if cfg.EdgeIP != "" || !cfg.TLS {
			mode = "packet-up"
		} else {
			mode = "stream-up"
		}
	}

	basePath := cfg.BasePath
	if basePath == "" {
		basePath = "/api/v1/stream"
	}
	basePath = "/" + strings.Trim(basePath, "/")

	scheme := "http"
	if cfg.TLS {
		scheme = "https"
	}

	h2Client := cfg.SharedH2Client
	h1Client := cfg.SharedH1Client
	ownClient := false
	if (cfg.TLS && h2Client == nil && h1Client == nil) || (!cfg.TLS && h1Client == nil) {
		sc, err := NewXHTTPSharedClients(cfg)
		if err != nil {
			cancel()
			return nil, err
		}
		h2Client = sc.H2
		h1Client = sc.H1
		ownClient = true
	}

	sessionID := randomHex(16)
	sessionURL := fmt.Sprintf("%s://%s%s/%s/%s", scheme, hostHeader, basePath, cfg.Purpose, sessionID)

	doGet := func(cl *http.Client) (*http.Response, error) {
		getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, sessionURL, nil)
		if err != nil {
			return nil, err
		}
		getReq.Host = hostHeader
		getReq.Header.Set("Authorization", "Bearer "+cfg.Token)
		getReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
		getReq.Header.Set("Accept", "application/octet-stream")
		getReq.Header.Set("Cache-Control", "no-cache")
		getReq.Header.Set("X-Session-Mode", mode)
		return cl.Do(getReq)
	}

	var activeClient *http.Client
	var getResp *http.Response
	var err error

	if cfg.TLS && h2Client != nil {
		activeClient = h2Client
		getResp, err = doGet(h2Client)
		if err != nil && h1Client != nil {
			activeClient = h1Client
			getResp, err = doGet(h1Client)
		}
	} else {
		activeClient = h1Client
		getResp, err = doGet(h1Client)
	}

	if err != nil {
		cancel()
		if ownClient && activeClient != nil {
			activeClient.CloseIdleConnections()
		}
		return nil, fmt.Errorf("xhttp downlink failed: %w", err)
	}
	if getResp.StatusCode != http.StatusOK {
		getResp.Body.Close()
		cancel()
		if ownClient && activeClient != nil {
			activeClient.CloseIdleConnections()
		}
		return nil, fmt.Errorf("xhttp downlink unexpected status: %d", getResp.StatusCode)
	}

	xc := &XHTTPClientConn{
		ctx:        ctx,
		cancel:     cancel,
		client:     activeClient,
		ownClient:  ownClient,
		baseURL:    sessionURL,
		hostHeader: hostHeader,
		token:      cfg.Token,
		mode:       mode,
		downBody:   getResp.Body,
		localAddr:  staticAddr{network: "xhttp", str: "127.0.0.1:0"},
		remoteAddr: staticAddr{network: "xhttp", str: dialTarget},
	}

	if mode == "stream-up" {
		pr, pw := io.Pipe()
		xc.upWriter = pw

		postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, sessionURL, pr)
		if err != nil {
			xc.Close()
			return nil, err
		}
		postReq.Host = hostHeader
		postReq.Header.Set("Authorization", "Bearer "+cfg.Token)
		postReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
		postReq.Header.Set("Content-Type", "application/octet-stream")
		postReq.Header.Set("Cache-Control", "no-store")
		postReq.Header.Set("X-Session-Mode", "stream-up")

		go func() {
			resp, pErr := activeClient.Do(postReq)
			if resp != nil && resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if pErr != nil && !xc.closed.Load() {
				xc.Close()
			}
		}()
	} else {
		// Pipelined parallel packet-up workers (4 concurrent HTTP POSTs)
		xc.upCh = make(chan xhttpPacket, 64)
		for i := 0; i < 4; i++ {
			go xc.packetUpWorker()
		}
	}

	return xc, nil
}

func (c *XHTTPClientConn) setWriteErr(err error) {
	c.writeErrMu.Lock()
	if c.writeErr == nil {
		c.writeErr = err
	}
	c.writeErrMu.Unlock()
}

func (c *XHTTPClientConn) getWriteErr() error {
	c.writeErrMu.Lock()
	err := c.writeErr
	c.writeErrMu.Unlock()
	return err
}

func (c *XHTTPClientConn) packetUpWorker() {
	retryDelays := []time.Duration{150 * time.Millisecond, 350 * time.Millisecond, 700 * time.Millisecond}
	for {
		select {
		case <-c.ctx.Done():
			return
		case pkt, ok := <-c.upCh:
			if !ok {
				return
			}
			postURL := fmt.Sprintf("%s/%d", c.baseURL, pkt.seq)
			var lastErr error
			sent := false
			for attempt := 0; attempt <= len(retryDelays); attempt++ {
				req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, postURL, bytes.NewReader(pkt.data))
				if err != nil {
					lastErr = err
					break
				}
				req.Host = c.hostHeader
				req.Header.Set("Authorization", "Bearer "+c.token)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
				req.Header.Set("Content-Type", "application/octet-stream")
				req.Header.Set("X-Session-Mode", "packet-up")

				resp, err := c.client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
						sent = true
						break
					}
					lastErr = fmt.Errorf("xhttp packet-up status: %d", resp.StatusCode)
					// Only retry transient CDN/proxy errors (429, 5xx)
					if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
						break
					}
				} else {
					lastErr = err
					if c.ctx.Err() != nil {
						break
					}
				}
				if attempt < len(retryDelays) {
					timer := time.NewTimer(retryDelays[attempt] + time.Duration(mrand.Intn(80))*time.Millisecond)
					select {
					case <-c.ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
				}
			}
			if !sent {
				c.setWriteErr(lastErr)
				c.Close()
				return
			}
		}
	}
}

func (c *XHTTPClientConn) Read(b []byte) (int, error) {
	if c.readTimedOut.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.downBody.Read(b)
	if c.readTimedOut.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *XHTTPClientConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if err := c.getWriteErr(); err != nil {
		return 0, err
	}
	if c.writeTimedOut.Load() {
		return 0, os.ErrDeadlineExceeded
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.mode == "stream-up" {
		n, err := c.upWriter.Write(b)
		if c.writeTimedOut.Load() {
			return n, os.ErrDeadlineExceeded
		}
		return n, err
	}

	const maxChunk = 64 * 1024
	total := 0
	for total < len(b) {
		end := total + maxChunk
		if end > len(b) {
			end = len(b)
		}
		chunkCopy := make([]byte, end-total)
		copy(chunkCopy, b[total:end])
		seq := atomic.AddUint64(&c.seq, 1) - 1

		select {
		case <-c.ctx.Done():
			if err := c.getWriteErr(); err != nil {
				return total, err
			}
			if c.writeTimedOut.Load() {
				return total, os.ErrDeadlineExceeded
			}
			return total, net.ErrClosed
		case c.upCh <- xhttpPacket{seq: seq, data: chunkCopy}:
			total += len(chunkCopy)
		}
	}
	return total, nil
}

func (c *XHTTPClientConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.cancel()
		c.readDeadlineMu.Lock()
		if c.readTimer != nil {
			c.readTimer.Stop()
			c.readTimer = nil
		}
		c.readDeadlineMu.Unlock()
		c.writeDeadlineMu.Lock()
		if c.writeTimer != nil {
			c.writeTimer.Stop()
			c.writeTimer = nil
		}
		c.writeDeadlineMu.Unlock()
		if c.upWriter != nil {
			_ = c.upWriter.Close()
		}
		if c.downBody != nil {
			_ = c.downBody.Close()
		}
		if c.ownClient && c.client != nil {
			c.client.CloseIdleConnections()
		}
	})
	return nil
}

func (c *XHTTPClientConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *XHTTPClientConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *XHTTPClientConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *XHTTPClientConn) SetReadDeadline(t time.Time) error {
	c.readDeadlineMu.Lock()
	defer c.readDeadlineMu.Unlock()
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	c.readTimedOut.Store(false)
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		c.readTimedOut.Store(true)
		_ = c.downBody.Close()
		return nil
	}
	c.readTimer = time.AfterFunc(d, func() {
		c.readTimedOut.Store(true)
		_ = c.downBody.Close()
	})
	return nil
}

func (c *XHTTPClientConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadlineMu.Lock()
	defer c.writeDeadlineMu.Unlock()
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	c.writeTimedOut.Store(false)
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		c.writeTimedOut.Store(true)
		if c.upWriter != nil {
			_ = c.upWriter.CloseWithError(os.ErrDeadlineExceeded)
		}
		return nil
	}
	c.writeTimer = time.AfterFunc(d, func() {
		c.writeTimedOut.Store(true)
		if c.upWriter != nil {
			_ = c.upWriter.CloseWithError(os.ErrDeadlineExceeded)
		}
	})
	return nil
}

type serverXHTTPSession struct {
	id          string
	purpose     string
	downReader  *io.PipeReader
	downWriter  *io.PipeWriter
	upReader    *io.PipeReader
	upWriter    *io.PipeWriter
	seqMu       sync.Mutex
	upWriteMu   sync.Mutex
	nextSeq     uint64
	pendingSeq  map[uint64][]byte
	remoteAddr  net.Addr
	localAddr   net.Addr
	createdAt   time.Time
	getAttached atomic.Bool
	closeOnce   sync.Once
	closed      atomic.Bool

	readDeadlineMu  sync.Mutex
	readTimer       *time.Timer
	readTimedOut    atomic.Bool
	writeDeadlineMu sync.Mutex
	writeTimer      *time.Timer
	writeTimedOut   atomic.Bool
}

func newServerXHTTPSession(id, purpose, remoteStr, localStr string) *serverXHTTPSession {
	dr, dw := io.Pipe()
	ur, uw := io.Pipe()
	return &serverXHTTPSession{
		id:         id,
		purpose:    purpose,
		downReader: dr,
		downWriter: dw,
		upReader:   ur,
		upWriter:   uw,
		pendingSeq: make(map[uint64][]byte),
		remoteAddr: staticAddr{network: "xhttp", str: remoteStr},
		localAddr:  staticAddr{network: "xhttp", str: localStr},
		createdAt:  time.Now(),
	}
}

func (s *serverXHTTPSession) Read(b []byte) (int, error) {
	if s.readTimedOut.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := s.upReader.Read(b)
	if s.readTimedOut.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (s *serverXHTTPSession) Write(b []byte) (int, error) {
	if s.writeTimedOut.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := s.downWriter.Write(b)
	if s.writeTimedOut.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (s *serverXHTTPSession) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		_ = s.downWriter.Close()
		_ = s.downReader.Close()
		_ = s.upWriter.Close()
		_ = s.upReader.Close()
	})
	return nil
}

func (s *serverXHTTPSession) LocalAddr() net.Addr  { return s.localAddr }
func (s *serverXHTTPSession) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *serverXHTTPSession) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *serverXHTTPSession) SetReadDeadline(t time.Time) error {
	s.readDeadlineMu.Lock()
	defer s.readDeadlineMu.Unlock()
	if s.readTimer != nil {
		s.readTimer.Stop()
		s.readTimer = nil
	}
	s.readTimedOut.Store(false)
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		s.readTimedOut.Store(true)
		_ = s.upReader.CloseWithError(os.ErrDeadlineExceeded)
		return nil
	}
	s.readTimer = time.AfterFunc(d, func() {
		s.readTimedOut.Store(true)
		_ = s.upReader.CloseWithError(os.ErrDeadlineExceeded)
	})
	return nil
}

func (s *serverXHTTPSession) SetWriteDeadline(t time.Time) error {
	s.writeDeadlineMu.Lock()
	defer s.writeDeadlineMu.Unlock()
	if s.writeTimer != nil {
		s.writeTimer.Stop()
		s.writeTimer = nil
	}
	s.writeTimedOut.Store(false)
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		s.writeTimedOut.Store(true)
		_ = s.downWriter.CloseWithError(os.ErrDeadlineExceeded)
		return nil
	}
	s.writeTimer = time.AfterFunc(d, func() {
		s.writeTimedOut.Store(true)
		_ = s.downWriter.CloseWithError(os.ErrDeadlineExceeded)
	})
	return nil
}

func (s *serverXHTTPSession) pushOrderedPacket(seq uint64, data []byte) error {
	s.seqMu.Lock()
	if seq < s.nextSeq {
		s.seqMu.Unlock()
		return nil
	}
	if len(s.pendingSeq) > 512 {
		s.seqMu.Unlock()
		return fmt.Errorf("too many out-of-order xhttp packets")
	}
	s.pendingSeq[seq] = data

	var ready [][]byte
	for {
		chunk, ok := s.pendingSeq[s.nextSeq]
		if !ok {
			break
		}
		delete(s.pendingSeq, s.nextSeq)
		s.nextSeq++
		ready = append(ready, chunk)
	}
	s.seqMu.Unlock()

	if len(ready) == 0 {
		return nil
	}
	s.upWriteMu.Lock()
	defer s.upWriteMu.Unlock()
	for _, chunk := range ready {
		if _, err := s.upWriter.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

type XHTTPServerHandler struct {
	token         string
	expectedHost  string
	basePath      string
	bindAddr      string
	fallbackProxy *httputil.ReverseProxy
	onAccept      func(purpose string, conn net.Conn)

	mu       sync.Mutex
	sessions map[string]*serverXHTTPSession
}

func NewXHTTPServerHandler(ctx context.Context, bindAddr, basePath, expectedHost, token, fallbackAddr string, onAccept func(purpose string, conn net.Conn)) http.Handler {
	if basePath == "" {
		basePath = "/api/v1/stream"
	}
	basePath = "/" + strings.Trim(basePath, "/")

	var fbProxy *httputil.ReverseProxy
	fb := strings.TrimSpace(fallbackAddr)
	if fb != "" {
		if !strings.HasPrefix(fb, "http://") && !strings.HasPrefix(fb, "https://") {
			fb = "http://" + fb
		}
		if u, err := url.Parse(fb); err == nil && u.Host != "" {
			fbProxy = httputil.NewSingleHostReverseProxy(u)
			fbProxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
	}

	h := &XHTTPServerHandler{
		token:         token,
		expectedHost:  strings.ToLower(strings.TrimSpace(expectedHost)),
		basePath:      basePath,
		bindAddr:      bindAddr,
		fallbackProxy: fbProxy,
		onAccept:      onAccept,
		sessions:      make(map[string]*serverXHTTPSession),
	}
	go h.reapStaleSessions(ctx)
	return h2c.NewHandler(h, &http2.Server{})
}

func (h *XHTTPServerHandler) serveFallback(w http.ResponseWriter, r *http.Request) {
	if h.fallbackProxy != nil {
		h.fallbackProxy.ServeHTTP(w, r)
		return
	}
	// Active-probe resistance: brief randomized delay before generic 404
	time.Sleep(time.Duration(40+mrand.Intn(120)) * time.Millisecond)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>"))
}

func (h *XHTTPServerHandler) reapStaleSessions(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var stale []*serverXHTTPSession
			h.mu.Lock()
			for id, s := range h.sessions {
				if (!s.getAttached.Load() && now.Sub(s.createdAt) > 20*time.Second) || s.closed.Load() {
					delete(h.sessions, id)
					stale = append(stale, s)
				}
			}
			h.mu.Unlock()
			for _, s := range stale {
				_ = s.Close()
			}
		}
	}
}

func (h *XHTTPServerHandler) getOrCreateSession(id, purpose, remoteAddr string) (*serverXHTTPSession, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.sessions[id]; ok {
		return s, false
	}
	s := newServerXHTTPSession(id, purpose, remoteAddr, h.bindAddr)
	h.sessions[id] = s
	return s, true
}

func (h *XHTTPServerHandler) removeSession(id string) {
	h.mu.Lock()
	s, ok := h.sessions[id]
	if ok {
		delete(h.sessions, id)
	}
	h.mu.Unlock()
	if ok {
		_ = s.Close()
	}
}

func (h *XHTTPServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	expectedAuth := "Bearer " + h.token
	gotAuth := r.Header.Get("Authorization")
	authOK := len(gotAuth) == len(expectedAuth) && subtle.ConstantTimeCompare([]byte(gotAuth), []byte(expectedAuth)) == 1
	hostOK := true
	if h.expectedHost != "" {
		reqHost := strings.ToLower(strings.TrimSpace(r.Host))
		if rh, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = rh
		}
		expHost := h.expectedHost
		if eh, _, err := net.SplitHostPort(expHost); err == nil {
			expHost = eh
		}
		hostOK = (reqHost == expHost)
	}
	if !authOK || !hostOK || !strings.HasPrefix(r.URL.Path, h.basePath+"/") {
		h.serveFallback(w, r)
		return
	}

	rel := strings.TrimPrefix(r.URL.Path, h.basePath+"/")
	parts := strings.Split(rel, "/")
	if len(parts) < 2 || len(parts) > 3 {
		h.serveFallback(w, r)
		return
	}
	purpose := parts[0]
	sessionID := parts[1]
	if (purpose != "channel" && purpose != "tunnel") || sessionID == "" {
		h.serveFallback(w, r)
		return
	}

	sess, created := h.getOrCreateSession(sessionID, purpose, r.RemoteAddr)
	if created {
		go h.onAccept(purpose, sess)
	}

	switch r.Method {
	case http.MethodGet:
		if !sess.getAttached.CompareAndSwap(false, true) {
			http.Error(w, "duplicate downlink", http.StatusConflict)
			return
		}
		defer h.removeSession(sessionID)

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		flusher, canFlush := w.(http.Flusher)
		if canFlush {
			flusher.Flush()
		}

		bufPtr := xhttpBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer xhttpBufPool.Put(bufPtr)

		for {
			n, err := sess.downReader.Read(buf)
			if n > 0 {
				if _, wErr := w.Write(buf[:n]); wErr != nil {
					return
				}
				if canFlush {
					flusher.Flush()
				}
			}
			if err != nil {
				return
			}
		}

	case http.MethodPost:
		if len(parts) == 2 {
			defer h.removeSession(sessionID)
			bufPtr := xhttpBufPool.Get().(*[]byte)
			buf := *bufPtr
			defer xhttpBufPool.Put(bufPtr)

			for {
				n, err := r.Body.Read(buf)
				if n > 0 {
					if _, wErr := sess.upWriter.Write(buf[:n]); wErr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		} else {
			seq, err := strconv.ParseUint(parts[2], 10, 64)
			if err != nil {
				http.Error(w, "invalid seq", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
			if err != nil {
				http.Error(w, "read error", http.StatusBadRequest)
				return
			}
			if err := sess.pushOrderedPacket(seq, body); err != nil {
				h.removeSession(sessionID)
				http.Error(w, "stream closed", http.StatusGone)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
