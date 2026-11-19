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
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/bishopfox/sliver/util/wghttp"
)

const (
	// wgHTTPHeader is the marker header the implant sets on every
	// wg-over-https poll.
	wgHTTPHeader = "Sliver-WG"

	// wgHTTPDefaultValue is the required value of wgHTTPHeader.
	wgHTTPHeaderValue = "1"

	// wgHTTPMaxBodyLen is the maximum request body the handler reads,
	// equal to the frame codec limit.
	wgHTTPMaxBodyLen = wghttp.MaxFrameLen

	// wgHTTPDefaultPollIntervalSeconds is the idle poll interval for
	// sessions that declare 0 ("server default").
	wgHTTPDefaultPollIntervalSeconds = 10

	// wgHTTPMaxHoldSeconds caps how long the handler holds a poll
	// open. 50s stays under the server's 60s WriteTimeout.
	wgHTTPMaxHoldSeconds = 50

	// wgHTTPMaxSessions is the maximum number of live wg-over-https
	// sessions; the newest session is rejected with 429 beyond it.
	wgHTTPMaxSessions = 512

	// wgHTTPDownlinkQueueLen is the per-session downlink packet queue
	// depth; packets are dropped (never blocking the device) beyond it.
	wgHTTPDownlinkQueueLen = 128

	// wgHTTPScratchPrefix is the network the server assigns per-session
	// scratch addresses from. Chosen to not overlap the wg tunnel
	// (100.64.0.0/16) or the multiplayer subnet (100.65.0.0/16).
	wgHTTPScratchPrefix = "100.70.0.0/16"

	// wgHTTPPacketChanSize is the bind's internal packet channel depth.
	wgHTTPPacketChanSize = 256

	// wgHTTPMaxScratchOffset is the largest scratch offset usable
	// within 100.70.0.0/16 (the /16 holds 65,536 addresses, one is
	// reserved for the network address).
	wgHTTPMaxScratchOffset = 0xffff

	// wgHTTPDownlinkGrace is how long the handler keeps a poll open
	// after the first downlink packet, to batch a burst into one
	// response.
	wgHTTPDownlinkGrace = 100 * time.Millisecond
)

// wgHTTPSession - Server-side state for one wg-over-https session.
type wgHTTPSession struct {
	id       [16]byte
	endpoint *wgHTTPSessionEndpoint

	// declaredInterval is the poll interval (seconds) the implant last
	// declared in its frame; 0 means server default.
	declaredInterval uint16

	// lastSeen is when the implant last polled; sessions expire after
	// 3 x max(declaredInterval, default) without a request.
	lastSeen time.Time
}

// wgHTTPSessionTable - All live wg-over-https sessions.
type wgHTTPSessionTable struct {
	active      map[[16]byte]*wgHTTPSession
	scratchIPs  map[uint16]struct{} // last octet pairs of live scratch addrs
	nextScratch uint16

	mutex sync.Mutex
}

var wgHTTPSessions = &wgHTTPSessionTable{
	active:      map[[16]byte]*wgHTTPSession{},
	scratchIPs:  map[uint16]struct{}{},
	nextScratch: 1,
}

var wgHTTPScratchPrefixAddr = net.ParseIP(wgHTTPScratchPrefixBase).To4()

// wgHTTPScratchPrefixBase is the base address of wgHTTPScratchPrefix.
const wgHTTPScratchPrefixBase = "100.70.0.0"

// wgOverHTTPSHandler - Handle a wg-over-https poll request: decode the
// frame, feed uplink packets into the wireguard device, then hold the
// request open for downlink packets. Returns true if the request was
// handled; false means fall through to the normal HTTP C2 handling.
func wgOverHTTPSHandler(resp http.ResponseWriter, req *http.Request) bool {
	if req.Method != http.MethodPost {
		return false
	}
	if req.Header.Get(wgHTTPHeader) != wgHTTPHeaderValue {
		return false
	}
	if req.Header.Get("Content-Type") != "application/octet-stream" {
		return false
	}
	wgBind, ok := WGHTTPBind().(*wgHTTPBind)
	if !ok || wgBind == nil {
		return false
	}

	body := http.MaxBytesReader(resp, req.Body, int64(wgHTTPMaxBodyLen))
	frame, err := wghttp.Decode(body)
	if err != nil {
		// The implant did claim to be a wg-over-https client, so reject
		// rather than falling through to the regular HTTP C2 handling.
		wgLog.Errorf("[wg/https] invalid frame: %v", err)
		http.Error(resp, "invalid frame", http.StatusBadRequest)
		return true
	}

	expireWGHTTPSessions()
	session := getOrCreateWGHTTPSession(frame)
	if session == nil {
		// Session table full: reject the newest session.
		http.Error(resp, "session limit reached", http.StatusTooManyRequests)
		return true
	}

	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if peerAddr, parseErr := netip.ParseAddr(host); parseErr == nil {
			session.endpoint.mutex.Lock()
			session.endpoint.peerAddr = peerAddr.Unmap()
			session.endpoint.mutex.Unlock()
		}
	}
	// Feed uplink packets to the device.
	for _, packet := range frame.Packets {
		if err := wgBind.enqueueWGHTTPPacket(packet, session.endpoint); err != nil {
			httpLog.Errorf("[wg/https] device unavailable: %v", err)
			http.Error(resp, "wireguard device unavailable", http.StatusServiceUnavailable)
			return true
		}
	}

	// Hold the request for downlink packets.
	hold := wgHTTPHoldDuration(frame.PollIntervalSeconds)
	drainAndWriteDownlink(resp, req, wgBind, session, hold)
	return true
}

// wgHTTPHoldDuration - How long to hold a poll open: min(declared
// interval + 2s, 50s).
func wgHTTPHoldDuration(declaredInterval uint16) time.Duration {
	interval := int(declaredInterval)
	if interval <= 0 {
		interval = wgHTTPDefaultPollIntervalSeconds
	}
	hold := time.Duration(interval)*time.Second + 2*time.Second
	if hold > wgHTTPMaxHoldSeconds*time.Second {
		hold = wgHTTPMaxHoldSeconds * time.Second
	}
	return hold
}

// drainAndWriteDownlink - Wait up to hold for downlink packets queued
// by the device's Send, then write them back with the same framing.
// Once the first packet arrives, a short grace window batches the rest
// of a burst so polls return promptly instead of always waiting out
// the full hold.
func drainAndWriteDownlink(resp http.ResponseWriter, req *http.Request, wgBind *wgHTTPBind, session *wgHTTPSession, hold time.Duration) {
	deadline := time.NewTimer(hold)
	defer deadline.Stop()

	var packets [][]byte
	for {
		select {
		case <-req.Context().Done():
			return
		case packet := <-session.endpoint.downlink:
			packets = append(packets, packet)
			if len(packets) >= wghttp.MaxPackets {
				writeWGHTTPResponse(resp, wgBind, session, packets)
				return
			}
			// First packet: give a burst a moment to accumulate.
			deadline.Reset(wgHTTPDownlinkGrace)
		case <-deadline.C:
			writeWGHTTPResponse(resp, wgBind, session, packets)
			return
		}
	}
}

// writeWGHTTPResponse - Frame packets for the session and write them;
// an empty packet list is a count-0 poll response.
func writeWGHTTPResponse(resp http.ResponseWriter, wgBind *wgHTTPBind, session *wgHTTPSession, packets [][]byte) {
	frame := &wghttp.Frame{
		SessionID:           session.id,
		PollIntervalSeconds: session.declaredInterval,
		Packets:             packets,
	}
	encoded, err := frame.Encode(nil)
	if err != nil {
		wgLog.Errorf("[wg/https] encode response frame: %v", err)
		http.Error(resp, "frame encode failed", http.StatusInternalServerError)
		return
	}
	resp.Header().Set("Content-Type", "application/octet-stream")
	resp.WriteHeader(http.StatusOK)
	resp.Write(encoded)
}

// getOrCreateWGHTTPSession - Look up the session by frame session ID,
// creating it (with a fresh scratch address) if needed. Returns nil
// when the session table is full.
func getOrCreateWGHTTPSession(frame *wghttp.Frame) *wgHTTPSession {
	wgHTTPSessions.mutex.Lock()
	defer wgHTTPSessions.mutex.Unlock()

	if session, ok := wgHTTPSessions.active[frame.SessionID]; ok {
		session.declaredInterval = frame.PollIntervalSeconds
		session.lastSeen = time.Now()
		return session
	}
	if len(wgHTTPSessions.active) >= wgHTTPMaxSessions {
		return nil
	}

	scratchAddrBytes, scratchOffset, ok := nextWGHTTPScratchAddrLocked()
	if !ok {
		return nil
	}
	endpoint := &wgHTTPSessionEndpoint{
		scratchAddrBytes: scratchAddrBytes,
		scratchOffset:    scratchOffset,
		peerAddr:         netip.Addr{},
		downlink:         make(chan []byte, wgHTTPDownlinkQueueLen),
	}
	session := &wgHTTPSession{
		id:               frame.SessionID,
		endpoint:         endpoint,
		declaredInterval: frame.PollIntervalSeconds,
		lastSeen:         time.Now(),
	}
	wgHTTPSessions.active[frame.SessionID] = session
	return session
}

// nextWGHTTPScratchAddrLocked - Allocate the next scratch address from
// 100.70.0.0/16. Caller holds wgHTTPSessions.mutex. Returns the
// marshaled 4-byte address and its offset. ok is false when every
// offset is still live; the caller must not create a session then.
func nextWGHTTPScratchAddrLocked() (addr []byte, offset uint16, ok bool) {
	for tries := 0; tries <= wgHTTPMaxScratchOffset; tries++ {
		// nextScratch is a uint16, so the old "> 0xffff" wrap never
		// fired and a full table spun forever on this mutex.
		if wgHTTPSessions.nextScratch == 0 {
			wgHTTPSessions.nextScratch = 1
		}
		offset = wgHTTPSessions.nextScratch
		wgHTTPSessions.nextScratch++
		if _, taken := wgHTTPSessions.scratchIPs[offset]; taken {
			continue
		}
		wgHTTPSessions.scratchIPs[offset] = struct{}{}
		return wgHTTPScratchAddr(offset), offset, true
	}
	return nil, 0, false
}

// wgHTTPScratchAddr - 100.70.x.y for offset. The prefix is a 4-byte
// net.IP with cap 4, so appending the offset would produce a 6-byte
// slice that netip.AddrFromSlice cannot parse and expiry could never
// release.
func wgHTTPScratchAddr(offset uint16) []byte {
	addr := make([]byte, net.IPv4len)
	copy(addr, wgHTTPScratchPrefixAddr)
	addr[2] = byte(offset >> 8)
	addr[3] = byte(offset)
	return addr
}

// expireWGHTTPSessions - Drop sessions that haven't polled within
// 3 x max(declaredInterval, 10s). Called on each request.
func expireWGHTTPSessions() {
	now := time.Now()
	wgHTTPSessions.mutex.Lock()
	defer wgHTTPSessions.mutex.Unlock()
	for id, session := range wgHTTPSessions.active {
		interval := int(session.declaredInterval)
		if interval < wgHTTPDefaultPollIntervalSeconds {
			interval = wgHTTPDefaultPollIntervalSeconds
		}
		if now.Sub(session.lastSeen) > 3*time.Duration(interval)*time.Second {
			delete(wgHTTPSessions.active, id)
			releaseWGHTTPScratchLocked(session.endpoint)
		}
	}
}
