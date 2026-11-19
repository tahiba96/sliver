package rpc

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/generate"
	"github.com/bishopfox/sliver/server/netstack"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// GenerateWGClientConfig - Generate a client config for a WG interface
func (rpc *Server) GenerateWGClientConfig(ctx context.Context, _ *commonpb.Empty) (*clientpb.WGClientConfig, error) {
	clientIP, privkey, pubkey, err := generate.GenerateUniqueWGPeerKeys()
	if err != nil {
		rpcLog.Errorf("Could not generate WG keys: %v", err)
		return nil, status.Error(codes.Internal, err.Error())
	}
	_, serverPubKey, err := certs.GetWGServerKeys()
	if err != nil {
		rpcLog.Errorf("Could not get WG server keys: %v", err)
		return nil, status.Error(codes.Internal, err.Error())
	}
	resp := &clientpb.WGClientConfig{
		ClientPrivateKey: privkey,
		ClientIP:         clientIP,
		ClientPubKey:     pubkey,
		ServerPubKey:     serverPubKey,
	}

	return resp, nil
}

// WGStartPortForward - Start a port forward
func (rpc *Server) WGStartPortForward(ctx context.Context, req *sliverpb.WGPortForwardStartReq) (*sliverpb.WGPortForward, error) {
	resp := &sliverpb.WGPortForward{}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// WGStopPortForward - Stop a port forward
func (rpc *Server) WGStopPortForward(ctx context.Context, req *sliverpb.WGPortForwardStopReq) (*sliverpb.WGPortForward, error) {
	resp := &sliverpb.WGPortForward{}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// WGAddForwarder - Add a TCP forwarder
func (rpc *Server) WGStartSocks(ctx context.Context, req *sliverpb.WGSocksStartReq) (*sliverpb.WGSocks, error) {
	resp := &sliverpb.WGSocks{}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// WGStopForwarder - Stop a TCP forwarder
func (rpc *Server) WGStopSocks(ctx context.Context, req *sliverpb.WGSocksStopReq) (*sliverpb.WGSocks, error) {
	resp := &sliverpb.WGSocks{}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (rpc *Server) WGListSocksServers(ctx context.Context, req *sliverpb.WGSocksServersReq) (*sliverpb.WGSocksServers, error) {
	resp := &sliverpb.WGSocksServers{}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// WGAddForwarder - List wireguard forwarders
func (rpc *Server) WGListForwarders(ctx context.Context, req *sliverpb.WGTCPForwardersReq) (*sliverpb.WGTCPForwarders, error) {
	resp := &sliverpb.WGTCPForwarders{}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// wgUDPRelayTimeouts bounds each step of one relay exchange. The
// dial to the implant forwarder and the reply wait are both much
// shorter than the gRPC call deadline, so the client sees a proper
// error instead of hanging when the implant is unreachable.
const (
	wgUDPRelayDialTimeout  = 3 * time.Second
	wgUDPRelayReplyTimeout = 3 * time.Second
)

// wgUDPRelayMaxPayload caps the datagram size the relay accepts,
// matching the implant forwarder's limit.
const wgUDPRelayMaxPayload = 2048

// errWGUDPRelayNoNetstack - The wireguard netstack only exists while
// a wireguard listener job is running.
var errWGUDPRelayNoNetstack = status.Error(codes.FailedPrecondition, "no wireguard listener is running")

// WGUDPRelay - Relay one datagram each way through the wireguard
// tunnel. The server dials out of the wireguard netstack toward the
// implant-side UDP forwarder at req.TargetAddress, sends req.Payload
// as a single datagram, waits for the forwarder's reply datagram, and
// returns it. Unlike the other WG RPCs this does not reach the
// implant over the message bus: the implant's UDP forwarder just
// bridges tun datagrams to the operator's target, and the relay is
// the server-side half of that bridge.
func (rpc *Server) WGUDPRelay(ctx context.Context, req *sliverpb.WGUDPRelayReq) (*sliverpb.WGUDPRelay, error) {
	tNet := c2.WGNetstack()
	if tNet == nil {
		return nil, errWGUDPRelayNoNetstack
	}
	if len(req.Payload) > wgUDPRelayMaxPayload {
		return nil, status.Errorf(codes.InvalidArgument, "payload exceeds %d bytes", wgUDPRelayMaxPayload)
	}
	target, err := net.ResolveUDPAddr("udp", req.TargetAddress)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target address: %v", err)
	}

	conn, err := wgUDPDial(tNet, target)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "dial implant forwarder: %v", err)
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(wgUDPRelayDialTimeout))
	if _, err := conn.Write(req.Payload); err != nil {
		return nil, status.Errorf(codes.Unavailable, "send datagram to implant: %v", err)
	}

	reply := make([]byte, wgUDPRelayMaxPayload)
	conn.SetReadDeadline(time.Now().Add(wgUDPRelayReplyTimeout))
	n, err := conn.Read(reply)
	if err != nil {
		return nil, status.Errorf(codes.DeadlineExceeded, "no reply from implant within %v: %v", wgUDPRelayReplyTimeout, err)
	}
	return &sliverpb.WGUDPRelay{Data: reply[:n]}, nil
}

// wgUDPDial - Dial UDP out of the wireguard netstack toward the
// implant forwarder, allowing return traffic on the relay's local
// port: the stack's Input chain drops every locally delivered packet
// (including replies to flows it opened itself), so without the rule
// the reply never reaches the dialer.
func wgUDPDial(tNet *netstack.Net, target *net.UDPAddr) (*gonet.UDPConn, error) {
	local, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	conn, err := tNet.DialUDP(local, target)
	if err != nil {
		return nil, err
	}
	localPort := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	// Return packets are destined to this stack's tun address, not the
	// implant forwarder we dialed. Allowing the target IP never matches.
	tunAddr, err := netip.ParseAddr(certs.C2WireGuardServerIP)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := tNet.AllowUDPPort(tunAddr, localPort); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
