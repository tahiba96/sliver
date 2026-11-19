package wghttpframe

import (
	"bytes"
	"crypto/rand"
	"testing"

	serverwghttp "github.com/bishopfox/sliver/util/wghttp"
)

// TestFrameFormatMatchesServerCopy pins the implant-tree codec to the
// server-side codec in util/wghttp: the implant build renames only the
// implant/sliver import prefix, so the two copies cannot share code, but
// the server handler (server/c2/http_wireguard.go) must be able to parse
// every frame the implant posts and vice versa. If this test fails, one
// copy drifted from the other.
func TestFrameFormatMatchesServerCopy(t *testing.T) {
	for _, count := range []int{0, 1, 3, 64} {
		packets := make([][]byte, count)
		for i := range packets {
			pkt := make([]byte, 40+i*7)
			rand.Read(pkt)
			packets[i] = pkt
		}
		sessionID := make([]byte, 16)
		rand.Read(sessionID)

		var sid [16]byte
		copy(sid[:], sessionID)
		implantFrame := &Frame{
			SessionID:           sid,
			PollIntervalSeconds: 42,
			Flags:               0,
			Packets:             packets,
		}
		implantEncoded, err := implantFrame.Encode(nil)
		if err != nil {
			t.Fatalf("implant encode: %v", err)
		}

		serverDecoded, err := serverwghttp.Decode(bytes.NewReader(implantEncoded))
		if err != nil {
			t.Fatalf("server decode of implant-encoded frame (%d packets): %v", count, err)
		}
		serverReEncoded, err := serverDecoded.Encode(nil)
		if err != nil {
			t.Fatalf("server re-encode: %v", err)
		}
		if !bytes.Equal(implantEncoded, serverReEncoded) {
			t.Fatalf("re-encode mismatch for %d packets", count)
		}

		serverFrame := &serverwghttp.Frame{
			SessionID:           sid,
			PollIntervalSeconds: 42,
			Flags:               0,
			Packets:             packets,
		}
		serverEncoded, err := serverFrame.Encode(nil)
		if err != nil {
			t.Fatalf("server encode: %v", err)
		}
		implantDecoded, err := Decode(bytes.NewReader(serverEncoded))
		if err != nil {
			t.Fatalf("implant decode of server-encoded frame (%d packets): %v", count, err)
		}
		if implantDecoded.PollIntervalSeconds != 42 || len(implantDecoded.Packets) != count {
			t.Fatalf("implant decode mismatch for %d packets", count)
		}
		for i := range packets {
			if !bytes.Equal(implantDecoded.Packets[i], packets[i]) {
				t.Fatalf("packet %d differs after round trip", i)
			}
		}
	}
}
