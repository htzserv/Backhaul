package network

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestXHTTPOrderedPacketReassemblyNoDeadlock(t *testing.T) {
	sess := newServerXHTTPSession("s1", "tunnel", "127.0.0.1:1", "127.0.0.1:2")
	defer sess.Close()

	// Concurrent reader draining the pipe
	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 12)
		_, _ = io.ReadFull(sess, buf)
		readDone <- buf
	}()

	// Push packets out-of-order: seq 2, then seq 0, then seq 1
	if err := sess.pushOrderedPacket(2, []byte("CCCC")); err != nil {
		t.Fatalf("push seq 2 failed: %v", err)
	}
	if err := sess.pushOrderedPacket(0, []byte("AAAA")); err != nil {
		t.Fatalf("push seq 0 failed: %v", err)
	}
	if err := sess.pushOrderedPacket(1, []byte("BBBB")); err != nil {
		t.Fatalf("push seq 1 failed: %v", err)
	}

	got := <-readDone
	if !bytes.Equal(got, []byte("AAAABBBBCCCC")) {
		t.Fatalf("unexpected reassembled stream: %q", string(got))
	}
}

func TestXHTTPServerAuthAndHostCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := NewXHTTPServerHandler(ctx, "127.0.0.1:8080", "/stream", "cdn.example.com", "secret-tok", "", func(string, net.Conn) {})

	// Wrong token -> 404 fallback
	req := httptest.NewRequest(http.MethodGet, "http://cdn.example.com/stream/channel/abc", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong token, got %d", rec.Code)
	}

	// Wrong Host header -> 404 fallback
	req2 := httptest.NewRequest(http.MethodGet, "http://evil.example.com/stream/channel/abc", nil)
	req2.Host = "evil.example.com"
	req2.Header.Set("Authorization", "Bearer secret-tok")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong host, got %d", rec2.Code)
	}
}
