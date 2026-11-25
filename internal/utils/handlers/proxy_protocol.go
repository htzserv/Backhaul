package handlers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

func extractIPPort(addr net.Addr) (string, int, error) {
	if addr == nil {
		return "", 0, fmt.Errorf("nil network address")
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String(), a.Port, nil
	case *net.UDPAddr:
		return a.IP.String(), a.Port, nil
	default:
		host, portStr, err := net.SplitHostPort(addr.String())
		if err != nil {
			return "", 0, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}
}

func WriteProxyProtocol(from, to net.Conn) error {
	srcIP, srcPort, err := extractIPPort(from.RemoteAddr())
	if err != nil {
		return fmt.Errorf("invalid source address: %v", err)
	}
	dstIP, dstPort, err := extractIPPort(from.LocalAddr())
	if err != nil {
		dstIP = srcIP
		dstPort = srcPort
	}

	header, err := buildProxyProtocolV2Header(srcIP, dstIP, srcPort, dstPort)
	if err != nil {
		return fmt.Errorf("failed to build Proxy Protocol v2 header: %v", err)
	}

	_, err = to.Write(header)
	if err != nil {
		return fmt.Errorf("failed to send Proxy Protocol v2 header: %v", err)
	}
	return nil
}

func buildProxyProtocolV2Header(srcIP, dstIP string, srcPort, dstPort int) ([]byte, error) {
	var buf bytes.Buffer

	buf.Write([]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a})
	buf.WriteByte(0x21)

	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	if src == nil || dst == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	src4 := src.To4()
	dst4 := dst.To4()

	var familyAndProtocol byte
	var addressLength uint16
	if src4 != nil && dst4 != nil {
		familyAndProtocol = 0x11
		addressLength = 12
		buf.WriteByte(familyAndProtocol)
		binary.Write(&buf, binary.BigEndian, addressLength)
		buf.Write(src4)
		buf.Write(dst4)
	} else {
		src16 := src.To16()
		dst16 := dst.To16()
		if src16 == nil || dst16 == nil {
			return nil, fmt.Errorf("invalid IPv6 address (src: %s, dst: %s)", srcIP, dstIP)
		}
		familyAndProtocol = 0x21
		addressLength = 36
		buf.WriteByte(familyAndProtocol)
		binary.Write(&buf, binary.BigEndian, addressLength)
		buf.Write(src16)
		buf.Write(dst16)
	}

	binary.Write(&buf, binary.BigEndian, uint16(srcPort))
	binary.Write(&buf, binary.BigEndian, uint16(dstPort))

	return buf.Bytes(), nil
}
