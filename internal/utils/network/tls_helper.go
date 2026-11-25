package network

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func LoadOrGenerateTLSConfig(certFile, keyFile, commonName string, nextProtos []string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
	} else {
		if commonName == "" {
			commonName = "www.cloudflare.com"
		}
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialLimit)
		if err != nil {
			return nil, err
		}
		tmpl := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:   commonName,
				Organization: []string{"Web Services"},
			},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{commonName},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
		if err != nil {
			return nil, err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		keyBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if len(nextProtos) > 0 {
		cfg.NextProtos = nextProtos
	}
	return cfg, nil
}

func BuildClientTLSConfig(sni string, nextProtos []string) *tls.Config {
	if host, _, err := net.SplitHostPort(sni); err == nil {
		sni = host
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
	}
	if len(nextProtos) > 0 {
		cfg.NextProtos = nextProtos
	}
	return cfg
}

func DialUTLS(ctx context.Context, rawConn net.Conn, sni, fingerprint string, nextProtos []string) (net.Conn, error) {
	if host, _, err := net.SplitHostPort(sni); err == nil {
		sni = host
	}
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	if fp == "none" || fp == "go" || fp == "stdlib" {
		tlsConn := tls.Client(rawConn, BuildClientTLSConfig(sni, nextProtos))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	uCfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         nextProtos,
	}

	var uConn *utls.UConn
	if fp == "random" || fp == "randomized" {
		uConn = utls.UClient(rawConn, uCfg, utls.HelloRandomizedALPN)
	} else {
		helloID := utls.HelloChrome_Auto
		switch fp {
		case "firefox":
			helloID = utls.HelloFirefox_Auto
		case "safari":
			helloID = utls.HelloSafari_Auto
		case "ios":
			helloID = utls.HelloIOS_Auto
		case "edge":
			helloID = utls.HelloEdge_Auto
		}
		spec, err := utls.UTLSIdToSpec(helloID)
		if err == nil {
			if len(nextProtos) > 0 {
				hasH2 := false
				for _, p := range nextProtos {
					if p == "h2" {
						hasH2 = true
						break
					}
				}
				alpnSet := false
				filtered := make([]utls.TLSExtension, 0, len(spec.Extensions))
				for _, ext := range spec.Extensions {
					if !hasH2 {
						if _, isALPS := ext.(*utls.ApplicationSettingsExtension); isALPS {
							continue
						}
					}
					if alpn, ok := ext.(*utls.ALPNExtension); ok {
						alpn.AlpnProtocols = nextProtos
						alpnSet = true
					}
					filtered = append(filtered, ext)
				}
				if !alpnSet {
					filtered = append(filtered, &utls.ALPNExtension{AlpnProtocols: nextProtos})
				}
				spec.Extensions = filtered
			}
			uConn = utls.UClient(rawConn, uCfg, utls.HelloCustom)
			if err := uConn.ApplyPreset(&spec); err != nil {
				uConn = utls.UClient(rawConn, uCfg, utls.HelloRandomizedALPN)
			}
		} else {
			uConn = utls.UClient(rawConn, uCfg, utls.HelloRandomizedALPN)
		}
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}
	return uConn, nil
}

// tlsRecordFragmentConn splits the initial TLS ClientHello handshake record
// into multiple standard RFC-5246/8446 TLS handshake records sent in separate
// TCP segments with small random delays so SNI-reading DPIs cannot parse it,
// while every standard TLS server transparently reassembles it.
type tlsRecordFragmentConn struct {
	net.Conn
	firstWriteDone bool
}

func (f *tlsRecordFragmentConn) Write(p []byte) (int, error) {
	if f.firstWriteDone || len(p) <= 40 {
		f.firstWriteDone = true
		return f.Conn.Write(p)
	}
	f.firstWriteDone = true

	// Check if p begins with a complete TLS Handshake record (0x16, major, minor, lenHi, lenLo)
	if p[0] == 0x16 && len(p) >= 5 {
		recLen := int(binary.BigEndian.Uint16(p[3:5]))
		if recLen > 0 && 5+recLen <= len(p) {
			major, minor := p[1], p[2]
			payload := p[5 : 5+recLen]
			tail := p[5+recLen:]

			offset := 0
			for offset < len(payload) {
				chunkSize := 16 + mrand.Intn(33) // 16..48 bytes per TLS record
				if offset+chunkSize > len(payload) {
					chunkSize = len(payload) - offset
				}
				rec := make([]byte, 5+chunkSize)
				rec[0] = 0x16
				rec[1] = major
				rec[2] = minor
				binary.BigEndian.PutUint16(rec[3:5], uint16(chunkSize))
				copy(rec[5:], payload[offset:offset+chunkSize])

				if _, err := f.Conn.Write(rec); err != nil {
					return offset, err
				}
				offset += chunkSize
				if offset < len(payload) {
					time.Sleep(time.Duration(1+mrand.Intn(4)) * time.Millisecond)
				}
			}
			if len(tail) > 0 {
				if _, err := f.Conn.Write(tail); err != nil {
					return 5 + recLen, err
				}
			}
			return len(p), nil
		}
	}

	// Fallback TCP-level split if not a single TLS handshake record
	splitAt := 16 + mrand.Intn(24)
	if splitAt >= len(p) {
		splitAt = len(p) / 2
	}
	n1, err := f.Conn.Write(p[:splitAt])
	if err != nil {
		return n1, err
	}
	time.Sleep(2 * time.Millisecond)
	n2, err := f.Conn.Write(p[splitAt:])
	return n1 + n2, err
}

func DialUTLSFragmented(ctx context.Context, rawConn net.Conn, sni, fingerprint string, nextProtos []string, fragment bool) (net.Conn, error) {
	if !fragment {
		return DialUTLS(ctx, rawConn, sni, fingerprint, nextProtos)
	}
	return DialUTLS(ctx, &tlsRecordFragmentConn{Conn: rawConn}, sni, fingerprint, nextProtos)
}
