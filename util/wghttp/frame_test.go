package wghttp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// frameBytes encodes frame, but only applies Encode's own limit checks
// when strict is set; malformed frames that Encode rejects are built by
// hand so their rejection can be asserted against Decode instead.
func frameBytes(t *testing.T, frame *Frame, strict bool) []byte {
	t.Helper()
	encoded, err := frame.Encode(nil)
	if strict && err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return encoded
}

func TestFrameRoundTripZeroOneAnd64Packets(t *testing.T) {
	for _, count := range []int{0, 1, MaxPackets} {
		t.Run("", func(t *testing.T) {
			original := &Frame{PollIntervalSeconds: 42}
			for i := 0; i < count; i++ {
				packet := make([]byte, i+1)
				for j := range packet {
					packet[j] = byte(i + j)
				}
				original.Packets = append(original.Packets, packet)
			}
			decoded, err := Decode(bytes.NewReader(frameBytes(t, original, true)))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if decoded.PollIntervalSeconds != original.PollIntervalSeconds {
				t.Errorf("PollIntervalSeconds = %d, want %d", decoded.PollIntervalSeconds, original.PollIntervalSeconds)
			}
			if decoded.Flags != 0 {
				t.Errorf("Flags = %#x, want 0", decoded.Flags)
			}
			if len(decoded.Packets) != count {
				t.Fatalf("got %d packets, want %d", len(decoded.Packets), count)
			}
			for i := range original.Packets {
				if !bytes.Equal(decoded.Packets[i], original.Packets[i]) {
					t.Errorf("packet %d = %x, want %x", i, decoded.Packets[i], original.Packets[i])
				}
			}
		})
	}
}

func TestFrameRejectsCount65(t *testing.T) {
	// Build a frame that declares 65 packets by hand: Encode refuses
	// to produce one.
	encoded := make([]byte, headerLen)
	binary.BigEndian.PutUint16(encoded[20:22], MaxPackets+1)
	_, err := Decode(bytes.NewReader(encoded))
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("Decode error = %v, want ErrInvalidFrame", err)
	}
}

func TestFrameRejectsPacketOf2049Bytes(t *testing.T) {
	// Build a frame whose single packet claims 2049 bytes by hand:
	// Encode refuses to produce one.
	encoded := make([]byte, headerLen)
	binary.BigEndian.PutUint16(encoded[20:22], 1)
	// Length prefix 2049 = 0x0801, then the oversized packet.
	encoded = append(encoded, 0x08, 0x01)
	encoded = append(encoded, make([]byte, MaxPacketLen+1)...)
	_, err := Decode(bytes.NewReader(encoded))
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("Decode error = %v, want ErrInvalidFrame", err)
	}
}

func TestFrameRejectsBodyTruncatedMidPacket(t *testing.T) {
	full := frameBytes(t, &Frame{Packets: [][]byte{make([]byte, 128), make([]byte, 64)}}, true)
	decoded, err := Decode(bytes.NewReader(full))
	if err != nil {
		t.Fatalf("Decode(full): %v", err)
	}
	truncated := full[:len(full)-1]
	if _, err := Decode(bytes.NewReader(truncated)); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("Decode(truncated) error = %v, want ErrInvalidFrame", err)
	}
	if decoded == nil || len(decoded.Packets) != 2 {
		t.Errorf("sanity: full frame should decode to 2 packets")
	}
}

func TestFrameRejectsVersion2(t *testing.T) {
	encoded := frameBytes(t, &Frame{}, true)
	encoded[0] = Version + 1
	_, err := Decode(bytes.NewReader(encoded))
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("Decode error = %v, want ErrInvalidFrame", err)
	}
}

func TestFramePollIntervalRoundTrip(t *testing.T) {
	for _, interval := range []uint16{0, 600, 1, 65535} {
		encoded := frameBytes(t, &Frame{PollIntervalSeconds: interval}, true)
		decoded, err := Decode(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("Decode(%d): %v", interval, err)
		}
		if decoded.PollIntervalSeconds != interval {
			t.Errorf("PollIntervalSeconds = %d, want %d", decoded.PollIntervalSeconds, interval)
		}
	}
}

func TestFrameRejectsBodyOf128KiBPlusOne(t *testing.T) {
	// MaxFrameLen is 128 KiB (131,072), so a 131,073-byte body is
	// rejected. Build it as one maximal packet followed by trailing
	// garbage.
	encoded := frameBytes(t, &Frame{Packets: [][]byte{make([]byte, MaxPacketLen)}}, true)
	oversized := append(encoded, make([]byte, 131073-len(encoded))...)
	if len(oversized) != 131073 {
		t.Fatalf("built %d bytes, want 131073", len(oversized))
	}
	if _, err := Decode(bytes.NewReader(oversized)); err == nil {
		t.Fatal("Decode(131073-byte body) succeeded, want error")
	}

	// The limit itself must still be accepted: a frame whose encoded
	// body is exactly MaxFrameLen bytes (63 x 2048-byte packets plus one
	// 1898-byte packet) decodes cleanly.
	maximal := &Frame{}
	for i := 0; i < MaxPackets-1; i++ {
		maximal.Packets = append(maximal.Packets, bytes.Repeat([]byte{byte(i)}, MaxPacketLen))
	}
	maximal.Packets = append(maximal.Packets, make([]byte, MaxPacketLen-150))
	encoded = frameBytes(t, maximal, true)
	if len(encoded) != MaxFrameLen {
		t.Fatalf("maximal frame is %d bytes, want %d", len(encoded), MaxFrameLen)
	}
	decoded, err := Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("Decode(maximal frame): %v", err)
	}
	if len(decoded.Packets) != MaxPackets {
		t.Errorf("got %d packets, want %d", len(decoded.Packets), MaxPackets)
	}
}

func TestFrameRejectsDeclaredSizeOverMaxFrameLen(t *testing.T) {
	// 64 packets of MaxPacketLen are each legal and together exceed
	// MaxFrameLen. Encode refuses this; Decode must too, before it
	// reads the packet bodies.
	var buf bytes.Buffer
	header := make([]byte, headerLen)
	header[0] = Version
	binary.BigEndian.PutUint16(header[20:22], MaxPackets)
	buf.Write(header)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], MaxPacketLen)
	for i := 0; i < MaxPackets; i++ {
		buf.Write(length[:])
	}
	if _, err := Decode(&buf); err == nil {
		t.Fatal("Decode accepted a frame whose declared size exceeds MaxFrameLen")
	}
}

func TestFrameRejectsTruncatedHeader(t *testing.T) {
	_, err := Decode(strings.NewReader("short"))
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("Decode error = %v, want ErrInvalidFrame", err)
	}
}
