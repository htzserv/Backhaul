package handlers

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestProxyProtocolV2IPv4AndIPv6(t *testing.T) {
	h4, err := buildProxyProtocolV2Header("1.2.3.4", "5.6.7.8", 12345, 443)
	if err != nil {
		t.Fatalf("IPv4 header failed: %v", err)
	}
	if len(h4) != 28 {
		t.Fatalf("expected 28-byte IPv4 PPv2 header, got %d", len(h4))
	}
	if !bytes.Equal(h4[:12], []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}) {
		t.Fatal("invalid PPv2 signature")
	}

	h6, err := buildProxyProtocolV2Header("2001:db8::1", "2001:db8::2", 54321, 8443)
	if err != nil {
		t.Fatalf("IPv6 header failed: %v", err)
	}
	if len(h6) != 52 {
		t.Fatalf("expected 52-byte IPv6 PPv2 header, got %d", len(h6))
	}
}

func TestLocalPortAndRemoteIPHelpers(t *testing.T) {
	if LocalPortOf(nil) != 0 || RemoteIPOf(nil) != "" {
		t.Fatal("nil conn helpers must return zero values")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if LocalPortOf(c) <= 0 || RemoteIPOf(c) != "127.0.0.1" {
		t.Fatalf("unexpected LocalPort=%d RemoteIP=%q", LocalPortOf(c), RemoteIPOf(c))
	}
}

func TestGlobalRateLimiter(t *testing.T) {
	SetGlobalRateLimitMbps(10)
	defer SetGlobalRateLimitMbps(0)

	lim := globalLimiter.Load()
	if lim == nil {
		t.Fatal("expected non-nil global limiter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := lim.wait(ctx, 1024); err != nil {
		t.Fatalf("unexpected rate limiter wait error: %v", err)
	}
}
