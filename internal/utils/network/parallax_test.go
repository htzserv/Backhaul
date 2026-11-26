package network

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestParallaxAEADRoundtripAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	params := ParallaxParams{
		Token:       "test-secret-token-123",
		Lanes:       3,
		WarmupMin:   1024,
		WarmupMax:   2048,
		StallSec:    4,
		DialTimeout: 3 * time.Second,
		KeepAlive:   10 * time.Second,
		NoDelay:     true,
		KCP: KCPParams{
			Mode:        "fast3",
			Key:         "test-secret-token-123",
			Crypt:       "aes",
			DataShard:   4,
			ParityShard: 2,
			MTU:         1350,
			SndWnd:      256,
			RcvWnd:      256,
		},
	}

	ln, err := ListenParallaxKCP(ctx, "127.0.0.1:0", params)
	if err != nil {
		t.Fatalf("ListenParallaxKCP failed: %v", err)
	}
	defer ln.Close()

	srvErrCh := make(chan error, 1)
	go func() {
		sConn, err := ln.AcceptKCP()
		if err != nil {
			srvErrCh <- err
			return
		}
		defer sConn.Close()
		TuneKCPSession(sConn, params.KCP)
		buf := make([]byte, 4096)
		n, err := sConn.Read(buf)
		if err != nil {
			srvErrCh <- err
			return
		}
		_, err = sConn.Write(buf[:n])
		srvErrCh <- err
	}()

	cliConn, err := DialParallaxKCP(ctx, ln.Addr().String(), params)
	if err != nil {
		t.Fatalf("DialParallaxKCP failed: %v", err)
	}
	defer cliConn.Close()

	payload := bytes.Repeat([]byte("backhaul-parallax-aead-ok!"), 64)
	if _, err := cliConn.Write(payload); err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	got := make([]byte, len(payload))
	_ = cliConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(cliConn, got); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	if err := <-srvErrCh; err != nil {
		t.Fatalf("server echo error: %v", err)
	}
	if err := cliConn.Close(); err != nil {
		t.Fatalf("client close error: %v", err)
	}
}

func TestParallaxReadDeadlineWakeup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc := &ParallaxClientPacketConn{
		ctx:      ctx,
		cancel:   cancel,
		recvCh:   make(chan parallaxInbound, 4),
		readDlCh: make(chan struct{}),
	}
	_ = pc.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	buf := make([]byte, 64)
	start := time.Now()
	_, _, err := pc.ReadFrom(buf)
	if err != os.ErrDeadlineExceeded {
		t.Fatalf("expected os.ErrDeadlineExceeded, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("ReadFrom did not wake promptly on deadline")
	}
	_ = pc.Close()
}

func TestPickEdgeIPAndPortHop(t *testing.T) {
	if got := PickEdgeIP(""); got != "" {
		t.Fatalf("expected empty edge IP, got %q", got)
	}
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		seen[PickEdgeIP("104.16.1.1, 104.16.1.2, 104.16.1.3")] = true
	}
	if len(seen) != 3 {
		t.Fatalf("expected all 3 edge IPs to rotate, saw %v", seen)
	}

	lo, hi, ok := ParsePortHopRange("20000-20050")
	if !ok || lo != 20000 || hi != 20050 {
		t.Fatalf("unexpected port hop range: %d-%d (%v)", lo, hi, ok)
	}
	now := time.Unix(1700000000, 0)
	p1 := ActiveHopPort("tok", lo, hi, 30, now)
	p2 := ActiveHopPort("tok", lo, hi, 30, now.Add(5*time.Second))
	if p1 != p2 || p1 < lo || p1 > hi {
		t.Fatalf("ActiveHopPort inconsistent in same window: %d vs %d", p1, p2)
	}
	_ = net.IPv4(127, 0, 0, 1)
}
