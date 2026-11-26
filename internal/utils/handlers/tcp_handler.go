package handlers

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// tokenBucket implements a lightweight, thread-safe bandwidth rate limiter.
type tokenBucket struct {
	mu           sync.Mutex
	bytesPerSec  float64
	burst        float64
	tokens       float64
	lastRefillAt time.Time
}

var globalLimiter atomic.Pointer[tokenBucket]

// SetGlobalRateLimitMbps configures an optional global bandwidth ceiling in Mbps (0 = unlimited).
func SetGlobalRateLimitMbps(mbps float64) {
	if mbps <= 0 {
		globalLimiter.Store(nil)
		return
	}
	bps := (mbps * 1_000_000.0) / 8.0
	burst := bps * 0.25 // 250ms burst window
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	globalLimiter.Store(&tokenBucket{
		bytesPerSec:  bps,
		burst:        burst,
		tokens:       burst,
		lastRefillAt: time.Now(),
	})
}

func (tb *tokenBucket) wait(ctx context.Context, n int) error {
	if tb == nil || n <= 0 {
		return nil
	}
	need := float64(n)
	for {
		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.lastRefillAt).Seconds()
		if elapsed > 0 {
			tb.tokens += elapsed * tb.bytesPerSec
			if tb.tokens > tb.burst {
				tb.tokens = tb.burst
			}
			tb.lastRefillAt = now
		}
		if tb.tokens >= need {
			tb.tokens -= need
			tb.mu.Unlock()
			return nil
		}
		deficit := need - tb.tokens
		tb.tokens = 0
		waitDur := time.Duration((deficit / tb.bytesPerSec) * float64(time.Second))
		tb.mu.Unlock()

		if waitDur < time.Millisecond {
			waitDur = time.Millisecond
		}
		timer := time.NewTimer(waitDur)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
}

// LocalPortOf safely extracts the local port of any net.Conn without panicking.
func LocalPortOf(c net.Conn) int {
	if c == nil || c.LocalAddr() == nil {
		return 0
	}
	switch a := c.LocalAddr().(type) {
	case *net.TCPAddr:
		return a.Port
	case *net.UDPAddr:
		return a.Port
	default:
		_, portStr, err := net.SplitHostPort(a.String())
		if err != nil {
			return 0
		}
		p, _ := strconv.Atoi(portStr)
		return p
	}
}

// RemoteIPOf safely extracts the remote IP string of any net.Conn without panicking.
func RemoteIPOf(c net.Conn) string {
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	switch a := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	default:
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return a.String()
		}
		return host
	}
}

func TCPConnectionHandler(ctx context.Context, proxyProtocol bool, from net.Conn, to net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	done := make(chan struct{})

	if proxyProtocol {
		err := WriteProxyProtocol(from, to)
		if err != nil {
			logger.Error(err)
			from.Close()
			to.Close()
			return
		}
	}

	go func() {
		defer close(done)
		transferData(ctx, from, to, logger, usage, remotePort, sniffer)
	}()

	transferData(ctx, to, from, logger, usage, remotePort, sniffer)

	select {
	case <-ctx.Done():
		from.Close()
		to.Close()
		return
	case <-done:
	}
}

func transferData(ctx context.Context, from net.Conn, to net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	bufPtr := copyBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer copyBufPool.Put(bufPtr)

	for {
		r, err := from.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				logger.Trace("reader stream closed or EOF received")
			} else {
				logger.Trace("unable to read from the connection: ", err)
			}
			from.Close()
			to.Close()
			return
		}

		if lim := globalLimiter.Load(); lim != nil {
			if err := lim.wait(ctx, r); err != nil {
				from.Close()
				to.Close()
				return
			}
		}

		totalWritten := 0
		for totalWritten < r {
			w, err := to.Write(buf[totalWritten:r])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logger.Trace("writer stream closed or EOF received")
				} else {
					logger.Trace("unable to write to the connection: ", err)
				}
				from.Close()
				to.Close()
				return
			}
			totalWritten += w
		}

		if sniffer && usage != nil {
			usage.AddOrUpdatePort(remotePort, uint64(totalWritten))
		}
	}
}
