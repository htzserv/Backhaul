package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ResolveRemoteAddr(remoteAddr string) (int, string, error) {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return 0, "", fmt.Errorf("empty remote address")
	}

	if port, err := strconv.Atoi(remoteAddr); err == nil && port >= 1 && port <= 65535 {
		return port, fmt.Sprintf("127.0.0.1:%d", port), nil
	}

	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid address format %q: %w", remoteAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("invalid port format %q: %w", portStr, err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return port, net.JoinHostPort(host, portStr), nil
}
