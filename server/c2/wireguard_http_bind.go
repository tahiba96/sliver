package c2

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
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// wgHTTPSessionEndpoint - A conn.Endpoint for one wg-over-https session:
// the device sends downlink packets to it, and they are queued for
// delivery in the next HTTP response for that session.
type wgHTTPSessionEndpoint struct {
	// scratchAddrBytes is the marshaled 4-byte scratch address
	// assigned from 100.70.0.0/16. It is what the device sees via
	// DstToBytes, which is all mac2 needs since CheckMAC2 only runs
	// under load. scratchOffset is the /16 host part, so expiry can
	// release the address without parsing the bytes.
	scratchAddrBytes []byte
	scratchOffset    uint16

	// mutex and peerAddr hold the most recent HTTP peer address of the
	// session, updated on each request. The device reads it through
	// DstIP so the handshake rate limiter keys on the actual source.
	mutex    sync.RWMutex
	peerAddr netip.Addr

	// downlink holds packets the device wants to send to this
	// session's implant. The HTTP handler drains it on each poll.
	downlink chan []byte
}

func (endpoint *wgHTTPSessionEndpoint) ClearSrc() {}

func (endpoint *wgHTTPSessionEndpoint) SrcToString() string {
	return ""
}

func (endpoint *wgHTTPSessionEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (endpoint *wgHTTPSessionEndpoint) DstIP() netip.Addr {
	endpoint.mutex.RLock()
	defer endpoint.mutex.RUnlock()
	return endpoint.peerAddr
}

func (endpoint *wgHTTPSessionEndpoint) DstToString() string {
	scratch, ok := netip.AddrFromSlice(endpoint.scratchAddrBytes)
	if !ok {
		return "invalid-scratch-address"
	}
	addrPort := netip.AddrPortFrom(scratch, 0)
	return addrPort.String()
}

func (endpoint *wgHTTPSessionEndpoint) DstToBytes() []byte {
	return endpoint.scratchAddrBytes
}

// wgHTTPBind - A composite conn.Bind: the UDP half handles the classic
// UDP transport unchanged, and one extra ReceiveFunc drains an internal
// packet channel fed by the wg-over-https handler. HTTP sessions are
// addressed by *wgHTTPSessionEndpoint endpoints, which Send routes into
// the owning session's downlink queue instead of the UDP half.
type wgHTTPBind struct {
	udpBind conn.Bind

	udpOpen    bool
	packetChan chan *incomingWGPacket
	closeChan  chan struct{}

	mutex sync.Mutex
}

// incomingWGPacket - A wireguard packet received over HTTPS, together
// with the session endpoint it arrived from.
type incomingWGPacket struct {
	packet   []byte
	endpoint *wgHTTPSessionEndpoint
}

func newWGHTTPBind() conn.Bind {
	return &wgHTTPBind{
		udpBind:    newWGUDPBind(),
		packetChan: make(chan *incomingWGPacket, wgHTTPPacketChanSize),
	}
}

// WGHTTPBind - The composite wg-over-https bind of the most recently
// started wireguard listener, or nil when no listener is running.
func WGHTTPBind() conn.Bind {
	wgHTTPBindMutex.Lock()
	defer wgHTTPBindMutex.Unlock()
	return wgHTTPBindCurrent
}

// setWGHTTPBind - Publish the bind for wgOverHTTPSHandler to use.
func setWGHTTPBind(bind conn.Bind) {
	wgHTTPBindMutex.Lock()
	defer wgHTTPBindMutex.Unlock()
	wgHTTPBindCurrent = bind
}

// clearWGHTTPBind - Unpublish the bind when the listener job stops
// and drop session state so scratch addresses are reusable.
func clearWGHTTPBind() {
	setWGHTTPBind(nil)
	clearWGHTTPSessions()
}

// clearWGHTTPSessions - Drop every live session and its scratch address.
func clearWGHTTPSessions() {
	wgHTTPSessions.mutex.Lock()
	defer wgHTTPSessions.mutex.Unlock()
	wgHTTPSessions.active = map[[16]byte]*wgHTTPSession{}
	wgHTTPSessions.scratchIPs = map[uint16]struct{}{}
	wgHTTPSessions.nextScratch = 1
}

// releaseWGHTTPScratchLocked - Return a session's scratch offset to the
// pool. Caller holds wgHTTPSessions.mutex.
func releaseWGHTTPScratchLocked(endpoint *wgHTTPSessionEndpoint) {
	if endpoint == nil {
		return
	}
	if endpoint.scratchOffset != 0 {
		delete(wgHTTPSessions.scratchIPs, endpoint.scratchOffset)
		return
	}
	scratch, ok := netip.AddrFromSlice(endpoint.scratchAddrBytes)
	if !ok || !scratch.Is4() {
		return
	}
	octets := scratch.As4()
	offset := uint16(octets[2])<<8 | uint16(octets[3])
	delete(wgHTTPSessions.scratchIPs, offset)
}

func (bind *wgHTTPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.udpOpen {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	bind.udpOpen = true

	// The device closes and reopens the bind on up-state changes
	// (BindUpdate), so each Open gets a fresh closed-signal channel.
	closeChan := make(chan struct{})
	bind.closeChan = closeChan

	udpFuncs, actualPort, err := bind.udpBind.Open(port)
	if err != nil {
		bind.udpOpen = false
		return nil, 0, err
	}

	httpFunc := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n := 0
		for {
			if n >= len(packets) {
				return n, nil
			}
			if n > 0 {
				// Have packets for the device already: drain any
				// remaining queued packets without blocking, then
				// return so the device can process the batch.
				select {
				case <-closeChan:
					return n, net.ErrClosed
				case incoming := <-bind.packetChan:
					copied, ok := copyWGPacket(packets[n], incoming.packet)
					if !ok {
						continue
					}
					sizes[n] = copied
					endpoints[n] = incoming.endpoint
					n++
				default:
					return n, nil
				}
				continue
			}
			// Nothing yet: block until the first packet arrives.
			select {
			case <-closeChan:
				return n, net.ErrClosed
			case incoming := <-bind.packetChan:
				copied, ok := copyWGPacket(packets[0], incoming.packet)
				if !ok {
					continue
				}
				sizes[0] = copied
				endpoints[0] = incoming.endpoint
				n++
			}
		}
	}

	return append(udpFuncs, httpFunc), actualPort, nil
}

func (bind *wgHTTPBind) Close() error {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.udpOpen {
		close(bind.closeChan)
	}
	bind.udpOpen = false
	return bind.udpBind.Close()
}

func (bind *wgHTTPBind) SetMark(value uint32) error {
	return bind.udpBind.SetMark(value)
}

func (bind *wgHTTPBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	if sessionEndpoint, ok := endpoint.(*wgHTTPSessionEndpoint); ok {
		bind.mutex.Lock()
		closeChan := bind.closeChan
		bind.mutex.Unlock()
		for _, buf := range bufs {
			packet := make([]byte, len(buf))
			copy(packet, buf)
			if err := enqueueWGHTTPDownlink(sessionEndpoint.downlink, packet, closeChan); err != nil {
				return err
			}
		}
		return nil
	}
	return bind.udpBind.Send(bufs, endpoint)
}

func (bind *wgHTTPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return bind.udpBind.ParseEndpoint(s)
}

func (bind *wgHTTPBind) BatchSize() int {
	return bind.udpBind.BatchSize()
}

// enqueueWGHTTPPacket - Feed a packet received over HTTPS into the
// device's receive path with the session's endpoint. Called by
// wgOverHTTPSHandler; errors only when the bind is closed.
func (bind *wgHTTPBind) enqueueWGHTTPPacket(packet []byte, endpoint *wgHTTPSessionEndpoint) error {
	bind.mutex.Lock()
	closeChan := bind.closeChan
	open := bind.udpOpen
	bind.mutex.Unlock()
	// Open is what creates closeChan. A bind published by a failed
	// StartWGListener has a nil channel; receiving on it blocks forever.
	if !open || closeChan == nil {
		return net.ErrClosed
	}
	select {
	case bind.packetChan <- &incomingWGPacket{packet: packet, endpoint: endpoint}:
		return nil
	case <-closeChan:
		return net.ErrClosed
	}
}

// enqueueWGHTTPDownlink - Queue a downlink packet, dropping the oldest
// queued packet when the session queue is full. A nil closeChan means
// the bind was never opened.
func enqueueWGHTTPDownlink(queue chan []byte, packet []byte, closeChan <-chan struct{}) error {
	if closeChan == nil {
		return net.ErrClosed
	}
	select {
	case <-closeChan:
		return net.ErrClosed
	default:
	}
	select {
	case queue <- packet:
		return nil
	default:
	}
	select {
	case <-queue:
	default:
	}
	select {
	case queue <- packet:
	default:
	}
	return nil
}

// copyWGPacket - Copy src into the device buffer. The device buffer is
// MaxSegmentSize, which is 2016 on Windows and 1700 on iOS, while the
// frame codec accepts 2048. Reporting the uncopied length makes the
// device read past the buffer.
func copyWGPacket(dst []byte, src []byte) (int, bool) {
	if len(dst) == 0 || len(src) > len(dst) {
		return 0, false
	}
	return copy(dst, src), true
}
