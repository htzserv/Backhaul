package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

const BufferSize = 16 * 1024

// startGenericUDPListener accepts local UDP packets and relays them over any raw net.Conn pool
// (used by tcp, tls, kcp, and parallax servers when accept_udp = true).
func startGenericUDPListener(
	ctx context.Context,
	localAddr string,
	remoteAddr string,
	channelSize int,
	rawChan <-chan net.Conn,
	reqNewConnChan chan<- struct{},
	logger *logrus.Logger,
	usage *web.Usage,
	sniffer bool,
	rttPtr *atomic.Int64,
) {
	localUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		logger.Errorf("failed to resolve local UDP address %s: %v", localAddr, err)
		return
	}

	var listener *net.UDPConn
	for attempt := 0; attempt < 6; attempt++ {
		listener, err = net.ListenUDP("udp", localUDPAddr)
		if err == nil {
			break
		}
		timer := time.NewTimer(400 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	if err != nil {
		logger.Errorf("failed to listen on local UDP port %s: %v", localAddr, err)
		return
	}
	defer listener.Close()

	logger.Infof("UDP listener started successfully on %s", listener.LocalAddr().String())

	activeConnections := map[string]*LocalAcceptUDPConn{}
	buf := make([]byte, BufferSize-2)
	udpChan := make(chan *LocalAcceptUDPConn, channelSize)
	mu := &sync.Mutex{}

	// Relay loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case localConn := <-udpChan:
			loop:
				for {
					select {
					case <-ctx.Done():
						return
					case tunnelConn := <-rawChan:
						if err := utils.SendBinaryTransportString(tunnelConn, localConn.remoteAddr, utils.SG_UDP); err != nil {
							logger.Debugf("failed to send UDP target addr: %v", err)
							tunnelConn.Close()
							continue loop
						}
						var rtt int64 = 100
						if rttPtr != nil {
							if v := rttPtr.Load(); v > 0 {
								rtt = v
							}
						}
						go UDPConnectionHandler(localConn, tunnelConn, logger, usage, handlers.LocalPortOf(localConn.listener), sniffer, rtt, &activeConnections, mu)
						break loop
					}
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, addr, err := listener.ReadFromUDP(buf)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					if ctx.Err() != nil {
						return
					}
					logger.Debugf("UDP listener read error: %v", err)
					continue
				}

				key := addr.String()
				mu.Lock()
				if existingConn, exists := activeConnections[key]; exists {
					if !existingConn.IsCongested {
						select {
						case existingConn.payload <- append([]byte(nil), buf[:n]...):
						default:
							logger.Debugf("UDP payload channel full for %s, dropping packet", key)
						}
						mu.Unlock()
						continue
					}
				}
				payloadChan := make(chan []byte, 4096)
				newUDPConn := LocalAcceptUDPConn{
					timeCreated: time.Now().UnixNano(),
					payload:     payloadChan,
					remoteAddr:  remoteAddr,
					listener:    listener,
					clientAddr:  addr,
					IsCongested: false,
				}
				activeConnections[key] = &newUDPConn
				mu.Unlock()

				select {
				case udpChan <- &newUDPConn:
					payloadChan <- append([]byte(nil), buf[:n]...)
					select {
					case reqNewConnChan <- struct{}{}:
					default:
					}
				default:
					mu.Lock()
					delete(activeConnections, key)
					mu.Unlock()
					logger.Warn("UDP channel is full, dropping packet.")
				}
			}
		}
	}()

	<-ctx.Done()
}

func (s *TcpTransport) udpListener(localAddr string, remoteAddr string) {
	var rtt atomic.Int64
	rtt.Store(s.rtt)
	startGenericUDPListener(s.ctx, localAddr, remoteAddr, s.config.ChannelSize, s.tunnelChannel, s.reqNewConnChan, s.logger, s.usageMonitor, s.config.Sniffer, &rtt)
}

func UDPConnectionHandler(udp *LocalAcceptUDPConn, tcp net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool, rtt int64, activeConnections *map[string]*LocalAcceptUDPConn, mu *sync.Mutex) {
	done := make(chan struct{})
	if rtt <= 0 {
		rtt = 100
	}

	go func() {
		udpToTCP(tcp, udp, logger, usage, remotePort, sniffer)
		tcp.Close()
		close(done)
	}()

	tcpToUDP(tcp, udp, logger, usage, remotePort, sniffer, rtt)
	tcp.Close()
	<-done

	mu.Lock()
	if cur, ok := (*activeConnections)[udp.clientAddr.String()]; ok && cur == udp {
		delete(*activeConnections, udp.clientAddr.String())
	}
	mu.Unlock()
}

func udpToTCP(tcp net.Conn, udp *LocalAcceptUDPConn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	header := make([]byte, 2)
	const inactivityTimeout = 60 * time.Second
	idleTimer := time.NewTimer(inactivityTimeout)
	defer idleTimer.Stop()

	for {
		select {
		case data, ok := <-udp.payload:
			if !ok {
				return
			}
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(inactivityTimeout)

			packetSize := len(data)
			if packetSize > 65535 {
				continue
			}
			binary.BigEndian.PutUint16(header, uint16(packetSize))
			packet := make([]byte, 2+packetSize)
			copy(packet[:2], header)
			copy(packet[2:], data)

			totalWritten := 0
			for totalWritten < len(packet) {
				w, err := tcp.Write(packet[totalWritten:])
				if err != nil {
					return
				}
				totalWritten += w
			}
			if sniffer && usage != nil {
				usage.AddOrUpdatePort(remotePort, uint64(totalWritten))
			}

		case <-idleTimer.C:
			return
		}
	}
}

func tcpToUDP(tcp net.Conn, udp *LocalAcceptUDPConn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool, rtt int64) {
	buf := make([]byte, BufferSize)
	lenBuf := make([]byte, 2)
	timestampBuf := make([]byte, 4)

	for {
		if _, err := io.ReadFull(tcp, timestampBuf); err != nil {
			return
		}
		packetTimestamp := int64(binary.BigEndian.Uint32(timestampBuf))
		lastMillis := time.Now().UnixMilli() % (10 * 60 * 1000)
		if lastMillis-packetTimestamp > 3*rtt {
			udp.IsCongested = true
		}

		if _, err := io.ReadFull(tcp, lenBuf); err != nil {
			return
		}
		packetSize := int(binary.BigEndian.Uint16(lenBuf))
		if packetSize > len(buf) {
			return
		}
		if _, err := io.ReadFull(tcp, buf[:packetSize]); err != nil {
			return
		}

		if udp.clientAddr != nil {
			totalWritten := 0
			for totalWritten < packetSize {
				w, err := udp.listener.WriteToUDP(buf[totalWritten:packetSize], udp.clientAddr)
				if err != nil {
					return
				}
				totalWritten += w
			}
			if sniffer && usage != nil {
				usage.AddOrUpdatePort(remotePort, uint64(totalWritten))
			}
		}
	}
}
