package network

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

type KCPParams struct {
	Mode            string
	Key             string
	Crypt           string
	DataShard       int
	ParityShard     int
	MTU             int
	SndWnd          int
	RcvWnd          int
	NoDelay         int
	Interval        int
	Resend          int
	NC              int
	AckNoDelay      bool
	DSCP            int
	SO_RCVBUF       int
	SO_SNDBUF       int
	PortHopRange    string
	PortHopInterval int
}

// ParsePortHopRange parses "10000-10020" into (10000, 10020, true).
func ParsePortHopRange(spec string) (int, int, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, false
	}
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || hi <= lo {
		return 0, 0, false
	}
	if hi-lo > 256 {
		hi = lo + 256 // cap listening sockets to protect fd limits
	}
	return lo, hi, true
}

// ActiveHopPort computes a deterministic port inside [lo, hi] for the current time window.
func ActiveHopPort(token string, lo, hi, intervalSec int, now time.Time) int {
	if intervalSec <= 0 {
		intervalSec = 30
	}
	slot := now.Unix() / int64(intervalSec)
	h := sha256.Sum256([]byte(fmt.Sprintf("bh-hop:%s:%d", token, slot)))
	span := uint64(hi - lo + 1)
	v := uint64(h[0])<<24 | uint64(h[1])<<16 | uint64(h[2])<<8 | uint64(h[3])
	return lo + int(v%span)
}

func NewKCPBlockCrypt(cryptType, key string) (kcp.BlockCrypt, error) {
	pass32 := sha256.Sum256([]byte("backhaul-kcp:" + key))
	pass16 := pass32[:16]

	switch strings.ToLower(strings.TrimSpace(cryptType)) {
	case "", "none":
		return kcp.NewNoneBlockCrypt(pass16)
	case "aes", "aes-256":
		return kcp.NewAESBlockCrypt(pass32[:])
	case "aes-128":
		return kcp.NewAESBlockCrypt(pass16)
	case "salsa20":
		return kcp.NewSalsa20BlockCrypt(pass32[:])
	case "xor":
		return kcp.NewSimpleXORBlockCrypt(pass32[:])
	case "tea":
		return kcp.NewTEABlockCrypt(pass16)
	case "xtea":
		return kcp.NewXTEABlockCrypt(pass16)
	case "sm4":
		return kcp.NewSM4BlockCrypt(pass16)
	case "blowfish":
		return kcp.NewBlowfishBlockCrypt(pass32[:])
	case "twofish":
		return kcp.NewTwofishBlockCrypt(pass32[:])
	case "cast5":
		return kcp.NewCast5BlockCrypt(pass16)
	case "3des":
		return kcp.NewTripleDESBlockCrypt(pass32[:24])
	default:
		return nil, fmt.Errorf("unsupported kcp_crypt: %s", cryptType)
	}
}

func ResolveKCPNoDelay(cfg KCPParams) (int, int, int, int) {
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "fast3":
		return 1, 10, 2, 1
	case "fast2", "":
		return 1, 20, 2, 1
	case "fast":
		return 0, 30, 2, 1
	case "normal":
		return 0, 40, 0, 0
	case "manual":
		return cfg.NoDelay, cfg.Interval, cfg.Resend, cfg.NC
	default:
		return 1, 20, 2, 1
	}
}

func TuneKCPSession(sess *kcp.UDPSession, cfg KCPParams) {
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	nd, interval, resend, nc := ResolveKCPNoDelay(cfg)
	sess.SetNoDelay(nd, interval, resend, nc)
	if cfg.SndWnd > 0 && cfg.RcvWnd > 0 {
		sess.SetWindowSize(cfg.SndWnd, cfg.RcvWnd)
	}
	if cfg.MTU > 0 {
		sess.SetMtu(cfg.MTU)
	}
	sess.SetACKNoDelay(cfg.AckNoDelay)
	if cfg.DSCP > 0 {
		_ = sess.SetDSCP(cfg.DSCP)
	}
	if cfg.SO_RCVBUF > 0 {
		_ = sess.SetReadBuffer(cfg.SO_RCVBUF)
	}
	if cfg.SO_SNDBUF > 0 {
		_ = sess.SetWriteBuffer(cfg.SO_SNDBUF)
	}
}

func DialKCP(ctx context.Context, remoteAddr string, cfg KCPParams, timeout time.Duration, retry int) (*kcp.UDPSession, error) {
	if retry < 1 {
		retry = 1
	}
	backoff := 1 * time.Second
	var lastErr error

	targetAddr := remoteAddr
	if lo, hi, ok := ParsePortHopRange(cfg.PortHopRange); ok {
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			hopPort := ActiveHopPort(cfg.Key, lo, hi, cfg.PortHopInterval, time.Now())
			targetAddr = net.JoinHostPort(host, strconv.Itoa(hopPort))
		}
	}

	for i := 0; i < retry; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		block, err := NewKCPBlockCrypt(cfg.Crypt, cfg.Key)
		if err != nil {
			return nil, err
		}

		type dialRes struct {
			sess *kcp.UDPSession
			err  error
		}
		ch := make(chan dialRes, 1)
		go func() {
			s, e := kcp.DialWithOptions(targetAddr, block, cfg.DataShard, cfg.ParityShard)
			ch <- dialRes{s, e}
		}()

		dialCtx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			dialCtx, cancel = context.WithTimeout(ctx, timeout)
		}

		select {
		case <-dialCtx.Done():
			if cancel != nil {
				cancel()
			}
			// Prevent socket leak if DialWithOptions succeeds after timeout
			go func() {
				res := <-ch
				if res.err == nil && res.sess != nil {
					_ = res.sess.Close()
				}
			}()
			lastErr = dialCtx.Err()
		case res := <-ch:
			if cancel != nil {
				cancel()
			}
			if res.err == nil {
				TuneKCPSession(res.sess, cfg)
				return res.sess, nil
			}
			lastErr = res.err
		}

		if i < retry-1 {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			backoff *= 2
		}
	}
	return nil, lastErr
}

func ListenKCP(bindAddr string, cfg KCPParams) (*kcp.Listener, error) {
	block, err := NewKCPBlockCrypt(cfg.Crypt, cfg.Key)
	if err != nil {
		return nil, err
	}
	listener, err := kcp.ListenWithOptions(bindAddr, block, cfg.DataShard, cfg.ParityShard)
	if err != nil {
		return nil, err
	}
	if cfg.DSCP > 0 {
		_ = listener.SetDSCP(cfg.DSCP)
	}
	if cfg.SO_RCVBUF > 0 {
		_ = listener.SetReadBuffer(cfg.SO_RCVBUF)
	}
	if cfg.SO_SNDBUF > 0 {
		_ = listener.SetWriteBuffer(cfg.SO_SNDBUF)
	}
	return listener, nil
}
