// Package wghttpframe implements the framing used to carry WireGuard UDP
// datagrams over HTTPS request/response bodies.
//
// This is the implant-tree copy of the codec: the implant build renames
// only the `implant/sliver` import prefix, so implant files cannot import
// repo-external shared packages (see server/generate/binaries.go). The
// server-side copy lives in util/wghttp; frame_format_test.go pins the
// two copies to identical wire behavior.
package wghttpframe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Version is the only frame version understood by this codec.
	Version = 1

	// FlagIP6 is reserved for a future version that carries the peer
	// address in the frame. Version 1 has no address field, so encoders
	// always clear it and decoders ignore it.
	FlagIP6 = 0x01

	// MaxPackets is the maximum number of packets a single frame may
	// carry. 0 is valid and means a poll with nothing to send.
	MaxPackets = 64

	// MaxPacketLen is the maximum wireguard packet size (a full-size
	// transport packet), in bytes.
	MaxPacketLen = 2048

	// MaxFrameLen is the maximum encoded frame size, i.e. the maximum
	// HTTP request/response body this codec accepts: 128 KiB. A body of
	// 64 maximum-size packets plus their length prefixes would need
	// 131,200 bytes, so a full-size frame carries at most 63 such
	// packets plus one smaller one.
	MaxFrameLen = 128 * 1024 // 131,072

	// headerLen is version(1) + flags(1) + sessionID(16) +
	// pollIntervalSeconds(2) + count(2).
	headerLen = 22
)

// ErrInvalidFrame is returned for any body that is not a valid frame.
var ErrInvalidFrame = errors.New("wghttpframe: invalid frame")

// Frame is a decoded frame. Packets own their backing arrays; callers
// may keep them without copying.
type Frame struct {
	// SessionID identifies the wireguard-over-https session: opaque
	// random 16 bytes assigned by the implant.
	SessionID [16]byte

	// PollIntervalSeconds is the implant's idle poll interval in
	// seconds. 0 means "server default" (10).
	PollIntervalSeconds uint16

	// Flags: bit 0 is ip6, reserved. Version 1 carries no address
	// field, so encoders must set Flags to 0 and decoders ignore it.
	Flags byte

	// Packets are the wireguard datagrams carried by this frame, in
	// order. len(Packets) <= MaxPackets, each packet <= MaxPacketLen.
	Packets [][]byte
}

// Encode appends the wire representation of f to dst and returns it.
func (f *Frame) Encode(dst []byte) ([]byte, error) {
	if len(f.Packets) > MaxPackets {
		return nil, fmt.Errorf("%w: %d packets exceeds limit of %d", ErrInvalidFrame, len(f.Packets), MaxPackets)
	}
	for i, pkt := range f.Packets {
		if len(pkt) > MaxPacketLen {
			return nil, fmt.Errorf("%w: packet %d is %d bytes, limit is %d", ErrInvalidFrame, i, len(pkt), MaxPacketLen)
		}
	}
	bodyLen := 0
	for _, pkt := range f.Packets {
		bodyLen += 2 + len(pkt)
	}
	if headerLen+bodyLen > MaxFrameLen {
		return nil, fmt.Errorf("%w: encoded frame of %d bytes exceeds limit of %d", ErrInvalidFrame, headerLen+bodyLen, MaxFrameLen)
	}

	if cap(dst)-len(dst) < headerLen+bodyLen {
		buf := make([]byte, len(dst), len(dst)+headerLen+bodyLen)
		copy(buf, dst)
		dst = buf
	}
	start := len(dst)
	dst = dst[:start+headerLen+bodyLen]

	dst[start] = Version
	dst[start+1] = f.Flags
	copy(dst[start+2:start+18], f.SessionID[:])
	binary.BigEndian.PutUint16(dst[start+18:start+20], f.PollIntervalSeconds)
	binary.BigEndian.PutUint16(dst[start+20:start+22], uint16(len(f.Packets)))

	offset := start + headerLen
	for _, pkt := range f.Packets {
		binary.BigEndian.PutUint16(dst[offset:offset+2], uint16(len(pkt)))
		offset += 2
		offset += copy(dst[offset:], pkt)
	}
	return dst, nil
}

// Decode parses a frame from r and returns it. A frame is rejected when
// its version is not Version, it declares more than MaxPackets packets,
// any packet claims more than MaxPacketLen bytes, the body exceeds
// MaxFrameLen bytes, it ends before the last declared packet completes,
// or it carries trailing bytes after the last packet.
func Decode(r io.Reader) (*Frame, error) {
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: truncated header: %w", ErrInvalidFrame, err)
	}
	if header[0] != Version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidFrame, header[0])
	}
	frame := &Frame{
		Flags:               header[1],
		PollIntervalSeconds: binary.BigEndian.Uint16(header[18:20]),
	}
	copy(frame.SessionID[:], header[2:18])

	count := int(binary.BigEndian.Uint16(header[20:22]))
	if count > MaxPackets {
		return nil, fmt.Errorf("%w: %d packets exceeds limit of %d", ErrInvalidFrame, count, MaxPackets)
	}
	if count > 0 && headerLen+count > MaxFrameLen {
		// Unreachable: MaxPackets packets never exceed MaxFrameLen, but
		// keep the body bound explicit.
		return nil, fmt.Errorf("%w: body exceeds limit of %d bytes", ErrInvalidFrame, MaxFrameLen)
	}

	prefix := make([]byte, 2)
	frame.Packets = make([][]byte, 0, count)
	consumed := headerLen
	for i := 0; i < count; i++ {
		if _, err := io.ReadFull(r, prefix); err != nil {
			return nil, fmt.Errorf("%w: truncated packet length: %w", ErrInvalidFrame, err)
		}
		length := int(binary.BigEndian.Uint16(prefix))
		if length > MaxPacketLen {
			return nil, fmt.Errorf("%w: packet %d is %d bytes, limit is %d", ErrInvalidFrame, i, length, MaxPacketLen)
		}
		consumed += 2 + length
		if consumed > MaxFrameLen {
			return nil, fmt.Errorf("%w: body exceeds limit of %d bytes", ErrInvalidFrame, MaxFrameLen)
		}
		packet := make([]byte, length)
		if _, err := io.ReadFull(r, packet); err != nil {
			return nil, fmt.Errorf("%w: truncated packet %d: %w", ErrInvalidFrame, i, err)
		}
		frame.Packets = append(frame.Packets, packet)
	}
	if extra, err := io.ReadAll(io.LimitReader(r, MaxFrameLen+1)); err != nil || len(extra) > 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after last packet", ErrInvalidFrame, len(extra))
	}
	return frame, nil
}
