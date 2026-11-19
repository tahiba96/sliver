//go:build server && go_sqlite

package c2

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	implantnetstack "github.com/bishopfox/sliver/implant/sliver/netstack"
	"github.com/bishopfox/sliver/server/netstack"
	"github.com/bishopfox/sliver/util/wghttp"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestWGHTTPBindUsesUDPBindHalf - The composite bind must be built on
// newWGUDPBind(), never conn.NewDefaultBind directly, so the Windows
// ARM64 override (conn.NewStdNetBind) is honored by construction.
func TestWGHTTPBindUsesUDPBindHalf(t *testing.T) {
	composite := newWGHTTPBind().(*wgHTTPBind)
	want := newWGUDPBind()
	if reflect.TypeOf(composite.udpBind) != reflect.TypeOf(want) {
		t.Fatalf("composite UDP half is %T, want %T", composite.udpBind, want)
	}
}

// wgHTTPTestClientBind - A conn.Bind that tunnels wireguard packets
// over the wg-over-https handler using net/http, standing in for the
// implant's transport. All packets share one fixed session ID and a
// single endpoint.
type wgHTTPTestClientBind struct {
	url    string
	client *http.Client

	sessionID [16]byte

	incoming  chan []byte
	closeChan chan struct{}
	mutex     sync.Mutex
	opened    bool
}

func (bind *wgHTTPTestClientBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.opened {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	bind.opened = true

	// The device closes and reopens the bind on up-state changes
	// (BindUpdate), so each Open gets a fresh closed-signal channel.
	closeChan := make(chan struct{})
	bind.closeChan = closeChan

	recv := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		select {
		case <-closeChan:
			return 0, net.ErrClosed
		case packet := <-bind.incoming:
			copy(packets[0], packet)
			sizes[0] = len(packet)
			endpoints[0] = &wgHTTPTestClientEndpoint{}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (bind *wgHTTPTestClientBind) Close() error {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.opened {
		close(bind.closeChan)
		bind.opened = false
	}
	return nil
}

func (bind *wgHTTPTestClientBind) SetMark(value uint32) error { return nil }

func (bind *wgHTTPTestClientBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	bind.mutex.Lock()
	closeChan := bind.closeChan
	bind.mutex.Unlock()
	select {
	case <-closeChan:
		return net.ErrClosed
	default:
	}
	frame := &wghttp.Frame{
		SessionID: bind.sessionID,
		Packets:   bufs,
	}
	encoded, err := frame.Encode(nil)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, bind.url, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set(wgHTTPHeader, wgHTTPHeaderValue)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := bind.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wg-over-https poll returned %d", resp.StatusCode)
	}
	frame, err = wghttp.Decode(io.LimitReader(resp.Body, int64(wghttp.MaxFrameLen)))
	if err != nil {
		return fmt.Errorf("decode response frame: %w", err)
	}
	for _, packet := range frame.Packets {
		select {
		case bind.incoming <- packet:
		case <-closeChan:
			return net.ErrClosed
		}
	}
	return nil
}

func (bind *wgHTTPTestClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &wgHTTPTestClientEndpoint{}, nil
}

func (bind *wgHTTPTestClientBind) BatchSize() int { return 1 }

// wgHTTPTestClientEndpoint - A conn.Endpoint that the client device's
// Send always uses; the test bind has a single fixed session.
type wgHTTPTestClientEndpoint struct{}

func (endpoint *wgHTTPTestClientEndpoint) ClearSrc()           {}
func (endpoint *wgHTTPTestClientEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (endpoint *wgHTTPTestClientEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (endpoint *wgHTTPTestClientEndpoint) DstToBytes() []byte  { return make([]byte, 4) }
func (endpoint *wgHTTPTestClientEndpoint) DstToString() string { return "wg-over-https" }
func (endpoint *wgHTTPTestClientEndpoint) SrcToString() string { return "" }

// hexKey - Encode a wgtypes.Key as the hex string IpcSetOperation
// expects.
func hexKey(key wgtypes.Key) string {
	return hex.EncodeToString(key[:])
}

// resetWGHTTPTestState - Give each test a pristine session table and
// no registered bind.
func resetWGHTTPTestState(t *testing.T) {
	t.Helper()
	resetWGHTTPState()
	t.Cleanup(resetWGHTTPState)
}

// resetWGHTTPState - Clear the bind registry and session table.
func resetWGHTTPState() {
	wgHTTPBindMutex.Lock()
	wgHTTPBindCurrent = nil
	wgHTTPBindMutex.Unlock()
	wgHTTPSessions.mutex.Lock()
	wgHTTPSessions.active = map[[16]byte]*wgHTTPSession{}
	wgHTTPSessions.scratchIPs = map[uint16]struct{}{}
	wgHTTPSessions.nextScratch = 1
	wgHTTPSessions.mutex.Unlock()
}

// wgHTTPTestTunnelPort is the tunnel-internal TCP port the end-to-end
// test listens and dials on.
const wgHTTPTestTunnelPort = 8888

// startWGHTTPEndToEnd - Wire up a full server device (composite bind +
// netstack TUN) and a client device (netstack TUN + HTTP bind) talking
// over an httptest TLS server that serves wgOverHTTPSHandler, plus an
// echo TCP server inside the server's tunnel. Returns the client
// netstack for dialing into the tunnel.
func startWGHTTPEndToEnd(t *testing.T) *implantnetstack.Net {
	t.Helper()

	resetWGHTTPTestState(t)

	serverPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	clientPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	// --- HTTP transport (needed before the client device dials) ---
	handler := http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if wgOverHTTPSHandler(resp, req) {
			return
		}
		http.NotFound(resp, req)
	})
	httpServer := httptest.NewTLSServer(handler)
	t.Cleanup(httpServer.Close)
	client := httpServer.Client()
	client.Timeout = 30 * time.Second

	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		t.Fatalf("session id: %v", err)
	}

	// --- Server device ---
	serverTun, serverNet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("100.64.0.1")},
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
		1420,
	)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	if err := serverNet.AllowTCPPort(netip.MustParseAddr("100.64.0.1"), wgHTTPTestTunnelPort); err != nil {
		t.Fatalf("AllowTCPPort: %v", err)
	}

	// Publish the live server netstack the way StartWGListener does,
	// so WGNetstack()-based relays and tests dial into the real
	// tunnel instead of a stack no device drains.
	setWGNetstack(serverNet)
	t.Cleanup(clearWGNetstack)

	wgBind := newWGHTTPBind()
	setWGHTTPBind(wgBind)
	serverDev := device.NewDevice(serverTun, wgBind, device.NewLogger(device.LogLevelError, "[test/server] "))
	t.Cleanup(serverDev.Close)

	wgConf := bytes.NewBuffer(nil)
	fmt.Fprintf(wgConf, "private_key=%s\n", hexKey(serverPriv))
	fmt.Fprintf(wgConf, "listen_port=0\n")
	fmt.Fprintf(wgConf, "public_key=%s\n", hexKey(clientPriv.PublicKey()))
	fmt.Fprintf(wgConf, "allowed_ip=100.64.0.2/32\n")
	if err := serverDev.IpcSetOperation(bufio.NewReader(wgConf)); err != nil {
		t.Fatalf("server IpcSetOperation: %v", err)
	}
	if err := serverDev.Up(); err != nil {
		t.Fatalf("server dev.Up: %v", err)
	}

	serverListener, err := serverNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: wgHTTPTestTunnelPort})
	if err != nil {
		t.Fatalf("server ListenTCP: %v", err)
	}
	t.Cleanup(func() { serverListener.Close() })
	go func() {
		for {
			tunnelConn, acceptErr := serverListener.Accept()
			if acceptErr != nil {
				return
			}
			go io.Copy(tunnelConn, tunnelConn) // Echo inside the tunnel.
		}
	}()

	// --- Client device ---
	// The implant's netstack has no inbound filter (the server's
	// drops non-listener ports), so the client uses it, exactly like
	// the real implant does.
	clientTun, clientNet, err := implantnetstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("100.64.0.2")},
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
		1420,
	)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	httpBind := &wgHTTPTestClientBind{
		url:       httpServer.URL,
		client:    client,
		sessionID: sessionID,
		incoming:  make(chan []byte, 256),
		closeChan: make(chan struct{}),
	}
	clientDev := device.NewDevice(clientTun, httpBind, device.NewLogger(device.LogLevelError, "[test/client] "))
	t.Cleanup(clientDev.Close)

	wgConf = bytes.NewBuffer(nil)
	fmt.Fprintf(wgConf, "private_key=%s\n", hexKey(clientPriv))
	fmt.Fprintf(wgConf, "public_key=%s\n", hexKey(serverPriv.PublicKey()))
	fmt.Fprintf(wgConf, "endpoint=127.0.0.1:1\n")
	fmt.Fprintf(wgConf, "allowed_ip=100.64.0.1/32\n")
	if err := clientDev.IpcSetOperation(bufio.NewReader(wgConf)); err != nil {
		t.Fatalf("client IpcSetOperation: %v", err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatalf("client dev.Up: %v", err)
	}

	return clientNet
}

// TestWGOverHTTPSEndToEndHandshakeAndDial - Two wireguard-go devices
// with netstack TUNs, the server using the composite bind and the
// client tunneling over the wg-over-https handler: the handshake must
// complete and a tun-to-tun TCP dial with echo must succeed.
func TestWGOverHTTPSEndToEndHandshakeAndDial(t *testing.T) {
	clientNet := startWGHTTPEndToEnd(t)

	conn, err := clientNet.DialTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: wgHTTPTestTunnelPort})
	if err != nil {
		t.Fatalf("tun-to-tun TCP dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	payload := []byte("ping over wg-over-https")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("tun write: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("tun read: %v", err)
	}
	if !bytes.Equal(payload, echo) {
		t.Fatalf("echo mismatch: sent %q got %q", payload, echo)
	}
}

// TestWGOverHTTPSHandlerNoBind - Without a registered bind the handler
// must fall through (the caller 404s); a framable POST must not be
// treated as an HTTP C2 session.
func TestWGOverHTTPSHandlerNoBind(t *testing.T) {
	resetWGHTTPTestState(t)

	srv := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if wgOverHTTPSHandler(resp, req) {
			return
		}
		http.NotFound(resp, req)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(makeTestFrame(t, 0)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set(wgHTTPHeader, wgHTTPHeaderValue)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 404 with no bind registered, got %d (%s)", resp.StatusCode, body)
	}
}

// makeTestFrame - Encode a frame with n empty packets.
func makeTestFrame(t *testing.T, n int) []byte {
	t.Helper()
	frame := &wghttp.Frame{Packets: make([][]byte, n)}
	encoded, err := frame.Encode(nil)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	return encoded
}

// TestWGOverHTTPSSessionLimit - 512 live sessions is the cap; the next
// new session must get HTTP 429.
func TestWGOverHTTPSSessionLimit(t *testing.T) {
	resetWGHTTPTestState(t)

	wgBind := newWGHTTPBind()
	setWGHTTPBind(wgBind)
	defer clearWGHTTPBind()

	wgHTTPSessions.mutex.Lock()
	for i := 0; i < wgHTTPMaxSessions; i++ {
		// Keep the all-zero session ID free: the probe POST below
		// uses it and must be rejected as a NEW session.
		var id [16]byte
		id[0], id[1], id[2] = 1, byte(i>>8), byte(i)
		wgHTTPSessions.active[id] = &wgHTTPSession{
			endpoint: &wgHTTPSessionEndpoint{
				scratchAddrBytes: func() []byte {
					addr, _, _ := nextWGHTTPScratchAddrLocked()
					return addr
				}(),
				downlink: make(chan []byte, 1),
			},
			lastSeen: time.Now(),
		}
	}
	wgHTTPSessions.mutex.Unlock()

	srv := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		wgOverHTTPSHandler(resp, req)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(makeTestFrame(t, 0)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set(wgHTTPHeader, wgHTTPHeaderValue)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 429 at session cap, got %d (%s)", resp.StatusCode, body)
	}
}

// TestWGOverHTTPSSessionNotExpiredAt30s - A session that declares a
// 600s poll interval must not be expired at 30 seconds of silence
// (expiry is 3 x max(declared, 10s)).
func TestWGOverHTTPSSessionNotExpiredAt30s(t *testing.T) {
	resetWGHTTPTestState(t)

	frame := &wghttp.Frame{
		PollIntervalSeconds: 600,
		Packets:             [][]byte{make([]byte, 32)},
	}
	session := getOrCreateWGHTTPSession(frame)
	if session == nil {
		t.Fatal("session creation failed with an empty table")
	}
	session.declaredInterval = 600
	session.lastSeen = time.Now().Add(-30 * time.Second)

	expireWGHTTPSessions()

	wgHTTPSessions.mutex.Lock()
	_, alive := wgHTTPSessions.active[session.id]
	wgHTTPSessions.mutex.Unlock()
	if !alive {
		t.Fatal("session with 600s declared interval was expired after only 30 seconds")
	}
}

// TestWGHTTPScratchAddressIsIPv4AndReleased - Scratch addresses are
// 4-byte 100.70.0.0/16 hosts, and expiry returns the offset to the
// pool. A 6-byte address cannot be parsed, so the pool never drains
// and the allocator eventually spins on the session mutex.
func TestWGHTTPScratchAddressIsIPv4AndReleased(t *testing.T) {
	resetWGHTTPTestState(t)

	session := getOrCreateWGHTTPSession(&wghttp.Frame{PollIntervalSeconds: 1})
	if session == nil {
		t.Fatal("session creation failed with an empty table")
	}
	addr, ok := netip.AddrFromSlice(session.endpoint.scratchAddrBytes)
	if !ok || !addr.Is4() || addr.String() != "100.70.0.1" {
		t.Fatalf("scratch = %v, ok=%v", session.endpoint.scratchAddrBytes, ok)
	}

	session.lastSeen = time.Now().Add(-time.Hour)
	expireWGHTTPSessions()

	wgHTTPSessions.mutex.Lock()
	left := len(wgHTTPSessions.scratchIPs)
	wgHTTPSessions.mutex.Unlock()
	if left != 0 {
		t.Fatalf("%d scratch addresses still taken after expiry", left)
	}
}
