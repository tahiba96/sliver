package wireguard

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/spf13/cobra"
)

const (
	// wgUDPDatagramMaxLen is the largest datagram the client relay
	// accepts, matching the implant forwarder's limit.
	wgUDPDatagramMaxLen = 2048

	// wgUDPRelayTimeout bounds one RPC datagram exchange through the
	// tunnel; DNS-style traffic needs a bounded wait per datagram.
	wgUDPRelayTimeout = 10 * time.Second
)

// WGPortFwdAddCmd - Add a new WireGuard port forward.
func WGPortFwdAddCmd(cmd *cobra.Command, con *console.SliverClient, args []string) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}
	if session.Transport != "wg" {
		con.PrintErrorf("This command is only supported for WireGuard implants")
		return
	}

	localPort, _ := cmd.Flags().GetInt32("bind")
	remoteAddr, _ := cmd.Flags().GetString("remote")
	protocol, _ := cmd.Flags().GetString("protocol")
	protocol = strings.ToLower(protocol)
	if remoteAddr == "" {
		con.PrintErrorf("Must specify a remote target host:port")
		return
	}
	remoteHost, remotePort, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		con.PrintErrorf("Failed to parse remote target %s\n", err)
		return
	}

	portfwdAdd, err := con.Rpc.WGStartPortForward(context.Background(), &sliverpb.WGPortForwardStartReq{
		LocalPort:     localPort,
		RemoteAddress: remoteAddr,
		Protocol:      protocol,
		Request:       con.ActiveTarget.Request(cmd),
	})
	if err != nil {
		con.PrintErrorf("Error: %v", err)
		return
	}

	if portfwdAdd.Response != nil && portfwdAdd.Response.Err != "" {
		con.PrintErrorf("Error: %s\n", portfwdAdd.Response.Err)
		return
	}
	if portfwdAdd.Forwarder == nil {
		con.PrintErrorf("Error: implant did not return a forwarder\n")
		return
	}
	con.PrintInfof("Port forwarding %s -> %s:%s\n", portfwdAdd.Forwarder.LocalAddr, remoteHost, remotePort)

	if protocol == "udp" {
		startWGUDPClientRelay(con, portfwdAdd.Forwarder.ID, portfwdAdd.Forwarder.LocalAddr)
	}
}

// wgUDPClientRelays tracks the local sockets started for UDP
// forwarders so rm can close them. The relay goroutine otherwise
// lives until the client process exits.
var wgUDPClientRelays = struct {
	sync.Mutex
	conns map[int32]*net.UDPConn
}{conns: map[int32]*net.UDPConn{}}

func stopWGUDPClientRelay(id int32) {
	wgUDPClientRelays.Lock()
	defer wgUDPClientRelays.Unlock()
	if listener := wgUDPClientRelays.conns[id]; listener != nil {
		listener.Close()
		delete(wgUDPClientRelays.conns, id)
	}
}

// startWGUDPClientRelay - Bind a local UDP socket and relay each
// datagram through the WGUDPRelay RPC toward the implant-side
// forwarder. The implant RPC only reaches the implant; the relay is
// what actually bridges the operator's local socket to the tunnel.
func startWGUDPClientRelay(con *console.SliverClient, id int32, forwarderAddr string) {
	local, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		con.PrintErrorf("Failed to resolve local relay address: %v\n", err)
		return
	}
	listener, err := net.ListenUDP("udp", local)
	if err != nil {
		con.PrintErrorf("Failed to bind local UDP relay socket: %v\n", err)
		return
	}
	con.PrintInfof("Local UDP relay listening on %s\n", listener.LocalAddr())
	wgUDPClientRelays.Lock()
	if old := wgUDPClientRelays.conns[id]; old != nil {
		old.Close()
	}
	wgUDPClientRelays.conns[id] = listener
	wgUDPClientRelays.Unlock()

	go func() {
		defer func() {
			listener.Close()
			wgUDPClientRelays.Lock()
			if wgUDPClientRelays.conns[id] == listener {
				delete(wgUDPClientRelays.conns, id)
			}
			wgUDPClientRelays.Unlock()
		}()
		buf := make([]byte, wgUDPDatagramMaxLen)
		for {
			n, from, err := listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply, err := relayWGUDPDatagram(con, forwarderAddr, buf[:n])
			if err != nil {
				continue
			}
			if _, err := listener.WriteToUDP(reply, from); err != nil {
				continue
			}
		}
	}()
}

// relayWGUDPDatagram - Send one datagram through the WGUDPRelay RPC
// and return the implant forwarder's reply.
func relayWGUDPDatagram(con *console.SliverClient, forwarderAddr string, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wgUDPRelayTimeout)
	defer cancel()
	resp, err := con.Rpc.WGUDPRelay(ctx, &sliverpb.WGUDPRelayReq{
		TargetAddress: forwarderAddr,
		Payload:       payload,
	})
	if err != nil {
		con.PrintWarnf("wg udp relay: %v\n", err)
		return nil, err
	}
	return resp.Data, nil
}
