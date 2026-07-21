package nas_security

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoldenEncapNasMsgToEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		nasPDU  []byte
		wantHex string
	}{
		{
			name:    "EmptyNASPDU",
			nasPDU:  []byte{},
			wantHex: "0000",
		},
		{
			name:    "NASPDU",
			nasPDU:  []byte{0x7e, 0x00, 0x41, 0x01, 0x02, 0x03},
			wantHex: "00067e0041010203",
		},
		{
			name:    "BinaryPayload",
			nasPDU:  []byte{0x00, 0xff, 0x80},
			wantHex: "000300ff80",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputBeforeBuild := bytes.Clone(test.nasPDU)

			got := EncapNasMsgToEnvelope(test.nasPDU)
			gotAgain := EncapNasMsgToEnvelope(test.nasPDU)

			require.Equal(t, test.wantHex, hex.EncodeToString(got))
			require.Equal(t, got, gotAgain, "envelope output is not deterministic")
			require.Equal(t, uint16(len(test.nasPDU)), binary.BigEndian.Uint16(got[:2]))
			require.True(t, bytes.Equal(test.nasPDU, got[2:]), "NAS payload changed during encapsulation")
			require.Equal(t, inputBeforeBuild, test.nasPDU, "input NAS PDU was modified")
		})
	}
}

func TestEncapNasMsgToEnvelopeMaximumLength(t *testing.T) {
	const maxNASPDUSize = int(^uint16(0))

	nasPDU := make([]byte, maxNASPDUSize)
	for i := range nasPDU {
		nasPDU[i] = byte(i)
	}

	got := EncapNasMsgToEnvelope(nasPDU)

	require.Len(t, got, maxNASPDUSize+2)
	require.Equal(t, uint16(maxNASPDUSize), binary.BigEndian.Uint16(got[:2]))
	require.True(t, bytes.Equal(nasPDU, got[2:]))
}
