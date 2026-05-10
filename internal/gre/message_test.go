package gre

import (
	"testing"
)

func TestGREPacketUnmarshalShortBuffer(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
	}{
		{name: "empty", buf: []byte{}},
		{name: "one byte", buf: []byte{0x00}},
		{name: "two bytes", buf: []byte{0x20, 0x00}},
		{name: "three bytes", buf: []byte{0x20, 0x00, 0x08}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Unmarshal panicked on short buffer: %v", r)
				}
			}()
			var p GREPacket
			if err := p.Unmarshal(tc.buf); err == nil {
				t.Fatalf("expected error for %d-byte buffer, got nil", len(tc.buf))
			}
		})
	}
}

func TestGREPacketUnmarshalKeyFlagTruncated(t *testing.T) {
	// flags byte 0x20 sets the Key flag.
	buf := []byte{0x20, 0x00, 0x08, 0x00}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Unmarshal panicked with Key flag + no Key field: %v", r)
		}
	}()
	var p GREPacket
	if err := p.Unmarshal(buf); err == nil {
		t.Fatal("expected error for Key-flag buffer with no Key field, got nil")
	}
}

func TestGREPacketUnmarshalValid(t *testing.T) {
	buf := []byte{0x00, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03}
	var p GREPacket
	if err := p.Unmarshal(buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.protocolType != IPv4 {
		t.Fatalf("protocolType = %d, want %d", p.protocolType, IPv4)
	}
	if string(p.payload) != string([]byte{0x01, 0x02, 0x03}) {
		t.Fatalf("payload mismatch: got %v", p.payload)
	}
}
