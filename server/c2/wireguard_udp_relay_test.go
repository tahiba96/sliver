//go:build server && go_sqlite

package c2

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const wgUDPDatagramMaxLen = 2048

// TestWGNetstackUDPDialReceivesReply - The WGUDPRelay RPC dials out of
// the server wireguard netstack with DialUDP. That dial opens a flow
// through the stack, but the server netstack's Input chain drops
// every locally delivered packet unconditionally (gVisor runs the
// Input check in deliverPacketLocally before transport delivery, even
// for return traffic on flows the stack itself opened), so the
// implant's reply is swallowed unless the relay's local port is
// allowed. This test dials out of the live server netstack toward an
// implant-side UDP listener (through a real wg-over-https tunnel) and
// reads the reply - but only after calling AllowUDPPort on the local
// port, which is exactly what WP6.S2 concluded is required.
func TestWGNetstackUDPDialReceivesReply(t *testing.T) {
	clientNet := startWGHTTPEndToEnd(t)

	// Warm the tunnel: the client initiates once so the server's
	// wireguard peer learns the endpoint (otherwise the server has
	// "no known endpoint" and cannot route the relay's datagram).
	warmConn, err := clientNet.DialTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 8888})
	if err != nil {
		t.Fatalf("tunnel warm-up dial: %v", err)
	}
	warmConn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := warmConn.Write([]byte("warm")); err != nil {
		t.Fatalf("tunnel warm-up write: %v", err)
	}
	warm := make([]byte, 4)
	if _, err := io.ReadFull(warmConn, warm); err != nil {
		t.Fatalf("tunnel warm-up read: %v", err)
	}
	warmConn.Close()

	// Implant side: the UDP "forwarder" is a plain echo listener on
	// the implant's tun IP, served out of the implant netstack (which
	// installs no inbound filter).
	forwarderAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 5353}
	forwarder, err := clientNet.ListenUDP(forwarderAddr)
	if err != nil {
		t.Fatalf("implant ListenUDP: %v", err)
	}
	defer forwarder.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, readErr := forwarder.ReadFrom(buf)
			if readErr != nil {
				return
			}
			if _, writeErr := forwarder.WriteTo(buf[:n], from); writeErr != nil {
				return
			}
		}
	}()

	// Server side: dial exactly like WGUDPRelay does, out of the live
	// server netstack (published by the e2e helper), toward the
	// implant forwarder's tun address. The Input chain drops the echo
	// reply unless this local port is allowed - see WP6.S2.
	if err := WGNetstack().AllowUDPPort(netip.MustParseAddr("100.64.0.1"), 5353); err != nil {
		t.Fatalf("AllowUDPPort: %v", err)
	}
	relayConn, err := dialWGNetstackUDP("100.64.0.1", 5353, forwarderAddr.String())
	if err != nil {
		t.Fatalf("server DialUDP: %v", err)
	}
	defer relayConn.Close()

	payload := []byte("relay probe datagram")
	relayConn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := relayConn.Write(payload); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(relayConn, reply); err != nil {
		t.Fatalf("read reply with no allow rule: %v", err)
	}
	if !bytes.Equal(payload, reply) {
		t.Fatalf("reply mismatch: sent %q got %q", payload, reply)
	}
}

// dialWGNetstackUDP - Dial UDP out of the server wireguard netstack
// toward an implant tun address, mirroring what WGUDPRelay does.
func dialWGNetstackUDP(localIP string, localPort int, targetAddress string) (*gonet.UDPConn, error) {
	tNet := WGNetstack()
	if tNet == nil {
		return nil, &wgNetstackNilError{}
	}
	localAddr := &net.UDPAddr{IP: net.ParseIP(localIP), Port: localPort}
	target, err := net.ResolveUDPAddr("udp", targetAddress)
	if err != nil {
		return nil, err
	}
	return tNet.DialUDP(localAddr, target)
}

type wgNetstackNilError struct{}

func (e *wgNetstackNilError) Error() string { return "wireguard netstack is not running" }

// TestWGUDPRelayEndToEnd - The full WP6 path: the wg-over-https
// handler (WP2), an implant device with the composite bind (WP3), an
// implant-side UDP forwarder listening on the tun (WP6.S4 semantics:
// one upstream socket per tun flow, reply written back to the tun
// sender), and the server relay (the WGUDPRelay dial half: DialUDP
// out of the server netstack toward the forwarder's tun address with
// AllowUDPPort on the local port). One datagram goes each way.
func TestWGUDPRelayEndToEnd(t *testing.T) {
	clientNet := startWGHTTPEndToEnd(t)

	// Implant side: run the forwarder's datagram exchange against the
	// implant netstack, exactly as the forwarder does per flow.
	forwarderAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 5353}
	forwarder, err := clientNet.ListenUDP(forwarderAddr)
	if err != nil {
		t.Fatalf("implant ListenUDP: %v", err)
	}
	defer forwarder.Close()

	// A stand-in "target" UDP service on the loopback interface of
	// the test process; the forwarder bridges tun datagrams to it.
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("target ListenUDP: %v", err)
	}
	defer target.Close()

	go func() {
		buf := make([]byte, wgUDPDatagramMaxLen)
		for {
			n, from, readErr := forwarder.ReadFrom(buf)
			if readErr != nil {
				return
			}
			flow, flowErr := net.DialUDP("udp", nil, target.LocalAddr().(*net.UDPAddr))
			if flowErr != nil {
				return
			}
			flow.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, writeErr := flow.Write(buf[:n]); writeErr != nil {
				flow.Close()
				return
			}
			flow.SetReadDeadline(time.Now().Add(30 * time.Second))
			reply := make([]byte, wgUDPDatagramMaxLen)
			replyN, readErr := flow.Read(reply)
			flow.Close()
			if readErr != nil {
				return
			}
			forwarder.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, writeErr := forwarder.WriteTo(reply[:replyN], from); writeErr != nil {
				return
			}
		}
	}()

	// Target side: the "DNS server" echoes one datagram per flow.
	go func() {
		buf := make([]byte, wgUDPDatagramMaxLen)
		for {
			n, from, readErr := target.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			if _, writeErr := target.WriteToUDP(buf[:n], from); writeErr != nil {
				return
			}
		}
	}()

	// Server side: warm the tunnel (the server's wireguard peer must
	// learn the endpoint from a client-initiated exchange), then dial
	// the relay half toward the forwarder's tun address.
	warmConn, err := clientNet.DialTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 8888})
	if err != nil {
		t.Fatalf("tunnel warm-up dial: %v", err)
	}
	warmConn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := warmConn.Write([]byte("warm")); err != nil {
		t.Fatalf("tunnel warm-up write: %v", err)
	}
	warm := make([]byte, 4)
	if _, err := io.ReadFull(warmConn, warm); err != nil {
		t.Fatalf("tunnel warm-up read: %v", err)
	}
	warmConn.Close()

	local, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("resolve local: %v", err)
	}
	conn, err := WGNetstack().DialUDP(local, forwarderAddr)
	if err != nil {
		t.Fatalf("relay DialUDP: %v", err)
	}
	defer conn.Close()
	localPort := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	if err := WGNetstack().AllowUDPPort(netip.MustParseAddr("100.64.0.1"), localPort); err != nil {
		t.Fatalf("AllowUDPPort: %v", err)
	}

	payload := []byte("end-to-end udp probe")
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if !bytes.Equal(payload, reply) {
		t.Fatalf("relay reply mismatch: sent %q got %q", payload, reply)
	}
}
