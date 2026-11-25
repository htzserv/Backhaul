package network

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/musix/backhaul/config"
)

func WebSocketDialer(ctx context.Context, addr string, edgeIP string, sni string, fingerprint string, tlsFragment bool, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, mode config.TransportType, retry int, SO_RCVBUF int, SO_SNDBUF int) (*websocket.Conn, error) {
	var tunnelWSConn *websocket.Conn
	var err error

	retries := retry
	if retries < 1 {
		retries = 1
	}
	backoff := 1 * time.Second

	for i := 0; i < retries; i++ {
		tunnelWSConn, err = attemptDialWebSocket(ctx, addr, edgeIP, sni, fingerprint, tlsFragment, path, timeout, keepalive, nodelay, token, mode, SO_RCVBUF, SO_SNDBUF)
		if err == nil {
			return tunnelWSConn, nil
		}
		if i == retries-1 {
			break
		}
		time.Sleep(backoff)
		backoff *= 2
	}

	return nil, err
}

func attemptDialWebSocket(ctx context.Context, addr string, edgeIP string, sni string, fingerprint string, tlsFragment bool, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, mode config.TransportType, SO_RCVBUF int, SO_SNDBUF int) (*websocket.Conn, error) {
	randomUserID := rand.Int31()

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
	}
	randomUserAgent := userAgents[rand.Intn(len(userAgents))]

	headers := http.Header{}
	headers.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	headers.Add("X-User-Id", fmt.Sprintf("%d", randomUserID))
	headers.Add("User-Agent", randomUserAgent)

	dialTarget := addr
	if edgeIP != "" {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format, failed to parse: %w", err)
		}
		dialTarget = net.JoinHostPort(edgeIP, port)
	}

	if sni == "" {
		if h, _, err := net.SplitHostPort(addr); err == nil {
			sni = h
		} else {
			sni = addr
		}
	}

	if path != "/channel" {
		path = fmt.Sprintf("%s/%s", path, strconv.Itoa(int(randomUserID)))
	}

	var wsURL string
	var dialer websocket.Dialer

	switch mode {
	case config.WS, config.WSMUX:
		wsURL = fmt.Sprintf("ws://%s%s", addr, path)
		dialer = websocket.Dialer{
			EnableCompression: false,
			HandshakeTimeout:  30 * time.Second,
			NetDialContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
				return TcpDialer(dCtx, dialTarget, "", timeout, keepalive, nodelay, 1, SO_RCVBUF, SO_SNDBUF, 0)
			},
		}
	case config.WSS, config.WSSMUX:
		wsURL = fmt.Sprintf("wss://%s%s", addr, path)
		dialer = websocket.Dialer{
			EnableCompression: false,
			HandshakeTimeout:  30 * time.Second,
			NetDialTLSContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
				raw, err := TcpDialer(dCtx, dialTarget, "", timeout, keepalive, nodelay, 1, SO_RCVBUF, SO_SNDBUF, 0)
				if err != nil {
					return nil, err
				}
				hsCtx, cancel := context.WithTimeout(dCtx, timeout)
				defer cancel()
				return DialUTLSFragmented(hsCtx, raw, sni, fingerprint, []string{"http/1.1"}, tlsFragment)
			},
		}
	default:
		return nil, fmt.Errorf("unsupported websocket mode: %s", mode)
	}

	tunnelWSConn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return nil, err
	}
	return tunnelWSConn, nil
}
