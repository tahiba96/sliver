//go:build windows || darwin || linux

package wireguard

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	implantnetstack "github.com/bishopfox/sliver/implant/sliver/netstack"
	"github.com/bishopfox/sliver/implant/sliver/transports/wireguard/wghttpframe"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The server side of these tests is a spec-compliant wg-over-https
// endpoint built inside the implant test package: the real handler
// lives in server/c2, which the implant tree must never import. The
// endpoint decodes frames, feeds packets into a server wireguard
// device through a test bind, and holds each poll for downlink
// packets with the same hold rule (min(declared + 2s, 50s)). The
// server-side composite and handler themselves are covered by
// server/c2/wireguard_http_bind_test.go.

// wgHTTPTestServerBind - A conn.Bind that receives packets POSTed by
// the implant bind and queues the server device's downlink packets for
// the next response.
type wgHTTPTestServerBind struct {
	incoming  chan *wgHTTPTestServerPacket
	closeChan chan struct{}

	mutex sync.Mutex
	open  bool
}

type wgHTTPTestServerPacket struct {
	packet   []byte
	endpoint *wgHTTPTestServerEndpoint
}

// wgHTTPTestSessionID - Alias for the wireguard session key type;
// an alias instead of a literal keeps the canary template delimiters
// out of the source text.
type wgHTTPTestSessionID = [16]byte

// wgHTTPTestServerEndpoint - The endpoint the server device sends
// downlink packets to; responses are queued per session.
type wgHTTPTestServerEndpoint struct {
	sessionID wgHTTPTestSessionID

	downlink chan []byte
}

func (endpoint *wgHTTPTestServerEndpoint) ClearSrc()           {}
func (endpoint *wgHTTPTestServerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (endpoint *wgHTTPTestServerEndpoint) SrcToString() string { return "" }
func (endpoint *wgHTTPTestServerEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (endpoint *wgHTTPTestServerEndpoint) DstToString() string { return "wg-over-https-test" }
func (endpoint *wgHTTPTestServerEndpoint) DstToBytes() []byte  { return make([]byte, 4) }

func (bind *wgHTTPTestServerBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	bind.open = true
	closeChan := make(chan struct{})
	bind.closeChan = closeChan

	recv := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		select {
		case <-closeChan:
			return 0, net.ErrClosed
		case incoming := <-bind.incoming:
			copy(packets[0], incoming.packet)
			sizes[0] = len(incoming.packet)
			endpoints[0] = incoming.endpoint
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (bind *wgHTTPTestServerBind) Close() error {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.open {
		close(bind.closeChan)
		bind.open = false
	}
	return nil
}

func (bind *wgHTTPTestServerBind) SetMark(value uint32) error { return nil }

func (bind *wgHTTPTestServerBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	sessionEndpoint, ok := endpoint.(*wgHTTPTestServerEndpoint)
	if !ok {
		return fmt.Errorf("unexpected endpoint type %T", endpoint)
	}
	for _, buf := range bufs {
		packet := make([]byte, len(buf))
		copy(packet, buf)
		select {
		case sessionEndpoint.downlink <- packet:
		default:
			// Queue full: drop, the peer retransmits.
		}
	}
	return nil
}

func (bind *wgHTTPTestServerBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &wgHTTPTestServerEndpoint{downlink: make(chan []byte, 128)}, nil
}

func (bind *wgHTTPTestServerBind) BatchSize() int { return 1 }

func (bind *wgHTTPTestServerBind) enqueue(packet []byte, endpoint *wgHTTPTestServerEndpoint) error {
	select {
	case bind.incoming <- &wgHTTPTestServerPacket{packet: packet, endpoint: endpoint}:
		return nil
	case <-bind.closeChan:
		return net.ErrClosed
	}
}

// hexKey - Encode a wgtypes.Key as the hex string IpcSetOperation
// expects.
func hexKey(key wgtypes.Key) string {
	return hex.EncodeToString(key[:])
}

// wgHTTPTestTunnelPort is the tunnel-internal TCP port the end-to-end
// test listens and dials on.
const wgHTTPTestTunnelPort = 8888

// startWGHTTPBindEndToEnd - Wire up a server wireguard device (server
// netstack TUN + wgHTTPTestServerBind) behind an httptest TLS server
// that speaks the wg-over-https framing, and an implant device
// (implant netstack TUN + NewHTTPBind). Returns the implant netstack
// for dialing into the tunnel.
func startWGHTTPBindEndToEnd(t *testing.T) *implantnetstack.Net {
	t.Helper()

	serverPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	clientPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	// --- Server device ---
	serverBind := &wgHTTPTestServerBind{
		incoming:  make(chan *wgHTTPTestServerPacket, 256),
		closeChan: make(chan struct{}),
	}
	serverTun, serverNet, err := implantnetstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("100.64.0.1")},
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
		1420,
	)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	serverDev := device.NewDevice(serverTun, serverBind, device.NewLogger(device.LogLevelError, "[test/server] "))
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

	// --- wg-over-https endpoint (test double of the server handler) ---
	endpoints := map[wgHTTPTestSessionID]*wgHTTPTestServerEndpoint{}
	var endpointsMutex sync.Mutex
	handler := http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.Header.Get("Sliver-WG") != "1" ||
			req.Header.Get("Content-Type") != "application/octet-stream" {
			http.NotFound(resp, req)
			return
		}
		frame, err := wghttpframe.Decode(io.LimitReader(req.Body, int64(wghttpframe.MaxFrameLen)))
		if err != nil {
			http.Error(resp, "invalid frame", http.StatusBadRequest)
			return
		}
		endpointsMutex.Lock()
		endpoint, ok := endpoints[frame.SessionID]
		if !ok {
			endpoint = &wgHTTPTestServerEndpoint{
				sessionID: frame.SessionID,
				downlink:  make(chan []byte, 128),
			}
			endpoints[frame.SessionID] = endpoint
		}
		endpointsMutex.Unlock()

		for _, packet := range frame.Packets {
			if err := serverBind.enqueue(packet, endpoint); err != nil {
				http.Error(resp, "device unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		hold := time.Duration(frame.PollIntervalSeconds)*time.Second + 2*time.Second
		if frame.PollIntervalSeconds == 0 || hold > 50*time.Second {
			hold = 50 * time.Second
		}
		var downlink [][]byte
		deadline := time.NewTimer(hold)
		defer deadline.Stop()
	accumulate:
		for {
			select {
			case packet := <-endpoint.downlink:
				downlink = append(downlink, packet)
				if len(downlink) >= wghttpframe.MaxPackets {
					break accumulate
				}
				// First packet: give a burst a moment to accumulate,
				// like the real handler's downlink grace window.
				deadline.Reset(100 * time.Millisecond)
			case <-deadline.C:
				break accumulate
			case <-req.Context().Done():
				return
			}
		}
		response := &wghttpframe.Frame{SessionID: frame.SessionID, Packets: downlink}
		encoded, err := response.Encode(nil)
		if err != nil {
			http.Error(resp, "encode failed", http.StatusInternalServerError)
			return
		}
		resp.Header().Set("Content-Type", "application/octet-stream")
		resp.WriteHeader(http.StatusOK)
		resp.Write(encoded)
	})
	httpServer := httptest.NewTLSServer(handler)
	t.Cleanup(httpServer.Close)

	// --- Implant device with the real NewHTTPBind bind ---
	clientTun, clientNet, err := implantnetstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("100.64.0.2")},
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
		1420,
	)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	httpBind := NewHTTPBind(httpServer.URL, 100*time.Millisecond, 30*time.Second)
	// The httptest server uses a self-signed certificate that the
	// bind's InsecureSkipVerify TLS config already accepts; point the
	// client at the test server's own transport so the test TLS setup
	// is reused without weakening anything else.
	bind := httpBind.(*wgHTTPBind)
	bind.client = httpServer.Client()
	bind.client.Timeout = 30 * time.Second

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

// TestWGHTTPBindEndToEndHandshakeAndDial - The implant NewHTTPBind
// against a spec-compliant wg-over-https endpoint: the handshake must
// complete and a tun-to-tun TCP dial with echo must succeed.
func TestWGHTTPBindEndToEndHandshakeAndDial(t *testing.T) {
	clientNet := startWGHTTPBindEndToEnd(t)

	conn, err := clientNet.DialTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: wgHTTPTestTunnelPort})
	if err != nil {
		t.Fatalf("tun-to-tun TCP dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	payload := []byte("ping over the implant http bind")
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

// TestWGHTTPBindSendAfterFailedPost - A failed POST must not close
// the device or the bind: the poster must keep polling and the bind
// must keep accepting Send.
func TestWGHTTPBindSendAfterFailedPost(t *testing.T) {
	clientPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	serverPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	var requests int32
	var requestsMutex sync.Mutex
	healthy := false
	handler := http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		requestsMutex.Lock()
		requests++
		isHealthy := healthy
		requestsMutex.Unlock()
		if !isHealthy {
			http.Error(resp, "unavailable", http.StatusServiceUnavailable)
			return
		}
		frame, err := wghttpframe.Decode(io.LimitReader(req.Body, int64(wghttpframe.MaxFrameLen)))
		if err != nil {
			http.Error(resp, "invalid frame", http.StatusBadRequest)
			return
		}
		response := &wghttpframe.Frame{SessionID: frame.SessionID}
		encoded, err := response.Encode(nil)
		if err != nil {
			http.Error(resp, "encode failed", http.StatusInternalServerError)
			return
		}
		resp.Header().Set("Content-Type", "application/octet-stream")
		resp.Write(encoded)
	})
	httpServer := httptest.NewTLSServer(handler)
	defer httpServer.Close()

	clientTun, _, err := implantnetstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("100.64.0.2")},
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
		1420,
	)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	httpBind := NewHTTPBind(httpServer.URL, 100*time.Millisecond, 5*time.Second)
	bind := httpBind.(*wgHTTPBind)
	bind.client = httpServer.Client()
	bind.client.Timeout = 5 * time.Second

	clientDev := device.NewDevice(clientTun, httpBind, device.NewLogger(device.LogLevelError, "[test/client] "))
	defer clientDev.Close()

	wgConf := bytes.NewBuffer(nil)
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

	// Wait until the server has rejected at least one poll (503), then
	// let it recover: the bind must keep polling and the device must
	// still be up.
	deadline := time.Now().Add(10 * time.Second)
	for {
		requestsMutex.Lock()
		current := requests
		requestsMutex.Unlock()
		if current >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected rejected polls, got %d requests", current)
		}
		time.Sleep(20 * time.Millisecond)
	}
	requestsMutex.Lock()
	healthy = true
	requestsMutex.Unlock()

	// Give the poster one interval to poll successfully.
	time.Sleep(500 * time.Millisecond)

	// The bind must still accept sends, i.e. it must not be closed.
	if err := bind.Send([][]byte{make([]byte, 32)}, &wgHTTPEndpoint{}); err != nil {
		t.Fatalf("bind closed after failed POST: %v", err)
	}

	requestsMutex.Lock()
	requestsBefore := requests
	requestsMutex.Unlock()
	deadline = time.Now().Add(10 * time.Second)
	for {
		requestsMutex.Lock()
		now := requests
		requestsMutex.Unlock()
		if now > requestsBefore {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bind stopped polling after a failed POST")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestWGHTTPBindNormalizesSliverScheme - The implant c2 URL carries the
// "wg+https" transport marker scheme; the bind must POST to the plain
// https origin. A wg+https origin used verbatim produces
// "unsupported protocol scheme" POST errors and a silent dead tunnel.
func TestWGHTTPBindNormalizesSliverScheme(t *testing.T) {
	var mu sync.Mutex
	seenURLs := []string{}
	handler := http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		mu.Lock()
		seenURLs = append(seenURLs, req.Host+req.URL.Path)
		mu.Unlock()
		resp.WriteHeader(http.StatusOK)
	})
	httpServer := httptest.NewTLSServer(handler)
	defer httpServer.Close()

	// httpServer.URL is https://127.0.0.1:port; re-mark it the way the
	// implant transports layer hands origins to NewHTTPBind.
	markedOrigin := strings.Replace(httpServer.URL, "https://", "wg+https://", 1)
	bind := NewHTTPBind(markedOrigin, 50*time.Millisecond, 2*time.Second).(*wgHTTPBind)
	bind.client = httpServer.Client()
	bind.client.Timeout = 2 * time.Second

	if got := bind.pollURL(); !strings.HasPrefix(got, "https://") {
		t.Fatalf("pollURL %q must use the https scheme", got)
	}

	closeChan := make(chan struct{})
	defer close(closeChan)
	go bind.posterLoop(closeChan)
	bind.Send([][]byte{[]byte("probe")}, &wgHTTPEndpoint{})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(seenURLs)
		mu.Unlock()
		if count > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seenURLs) == 0 {
		t.Fatalf("no POST reached the server within 5s")
	}
}
