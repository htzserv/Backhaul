package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

const BufferSize = 16 * 1024

func UDPDialer(tcp net.Conn, remoteAddr string, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	defer tcp.Close()

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		logger.Errorf("failed to resolve remote UDP address %s: %v", remoteAddr, err)
		return
	}

	remoteConn, err := net.DialUDP("udp", nil, remoteUDPAddr)
	if err != nil {
		logger.Errorf("failed to dial remote UDP address %s: %v", remoteAddr, err)
		return
	}
	defer remoteConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		tcpToUDP(tcp, remoteConn, logger, usage, remotePort, sniffer)
		remoteConn.Close()
	}()

	udpToTCP(tcp, remoteConn, logger, usage, remotePort, sniffer)
	tcp.Close()
	remoteConn.Close()
	<-done
}

func tcpToUDP(tcp net.Conn, udp *net.UDPConn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	buf := make([]byte, BufferSize)
	lenBuf := make([]byte, 2)

	for {
		_, err := io.ReadFull(tcp, lenBuf)
		if err != nil {
			return
		}

		packetSize := binary.BigEndian.Uint16(lenBuf)
		if int(packetSize) > len(buf) {
			logger.Errorf("packet size %d exceeds buffer size %d", packetSize, len(buf))
			return
		}

		_, err = io.ReadFull(tcp, buf[:packetSize])
		if err != nil {
			return
		}

		totalWritten := 0
		for totalWritten < int(packetSize) {
			w, err := udp.Write(buf[totalWritten:packetSize])
			if err != nil {
				return
			}
			totalWritten += w
		}

		if sniffer {
			usage.AddOrUpdatePort(remotePort, uint64(totalWritten))
		}
	}
}

func udpToTCP(tcp net.Conn, udp *net.UDPConn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	buf := make([]byte, BufferSize-6)
	header := make([]byte, 2)
	timestampHeader := make([]byte, 4)
	packetBuffer := bytes.NewBuffer(make([]byte, 0, BufferSize))

	for {
		_ = udp.SetReadDeadline(time.Now().Add(65 * time.Second))
		r, err := udp.Read(buf)
		if err != nil {
			return
		}
		if r > 65535 {
			continue
		}

		timestamp := time.Now().UnixMilli()
		lastMillis := timestamp % (10 * 60 * 1000)
		binary.BigEndian.PutUint32(timestampHeader, uint32(lastMillis))
		binary.BigEndian.PutUint16(header, uint16(r))

		packetBuffer.Reset()
		packetBuffer.Write(timestampHeader)
		packetBuffer.Write(header)
		packetBuffer.Write(buf[:r])

		totalWritten := 0
		packet := packetBuffer.Bytes()
		for totalWritten < len(packet) {
			w, err := tcp.Write(packet[totalWritten:])
			if err != nil {
				return
			}
			totalWritten += w
		}

		if sniffer {
			usage.AddOrUpdatePort(remotePort, uint64(totalWritten))
		}
	}
}
