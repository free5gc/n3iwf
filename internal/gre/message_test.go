package gre

import (
	"testing"
)

// TestGREPacketUnmarshalShortBuffer pins the fix for free5gc/free5gc#987.
// Before the bounds check, a 2-byte GRE payload arriving through the NWu
// tunnel panicked with runtime out-of-range in b[2:4]; the nwuup recover
// path then called Fatalf and killed the n3iwf process, DoSing every UE.
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

// TestGREPacketUnmarshalKeyFlagTruncated covers the secondary panic site
// at b[offset:offset+GREHeaderKeyFieldLength]: the Key flag is set but
// the buffer stops at the 4-byte base header.
func TestGREPacketUnmarshalKeyFlagTruncated(t *testing.T) {
	// flags byte 0x20 sets the Key flag (GetKeyFlag reads bit 5 of flags).
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

// TestGREPacketUnmarshalValid ensures the happy path still works.
func TestGREPacketUnmarshalValid(t *testing.T) {
	// flags=0 (no Key), protocolType=IPv4, 3 payload bytes.
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
