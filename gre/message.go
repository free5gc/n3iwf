package message

import "encoding/binary"

// [TS 24.502] 9.3.3 GRE encapsulated user data packet
const (
	GREHeaderFieldLength = 8
)

type GREPacket struct {
	flags        uint8
	version      uint8
	protocolType uint16
	key          uint32
	payload      []byte
}

func (p *GREPacket) Marshal(payload []byte) []byte {
	packet := make([]byte, GREHeaderFieldLength+len(payload))

	packet[0] = p.flags
	packet[1] = p.version
	binary.BigEndian.PutUint16(packet[2:4], p.protocolType)
	binary.BigEndian.PutUint32(packet[4:8], p.key)
	copy(packet[GREHeaderFieldLength:], payload)
	return packet
}

func (p *GREPacket) setPayload(payload []byte, protocolType uint16) {
	p.payload = payload
	p.protocolType = protocolType
}

func (p *GREPacket) setChecksumFlag() {
	p.flags |= 0x80
}

func (p *GREPacket) setKeyFlag() {
	p.flags |= 0x20
}

func (p *GREPacket) setSequenceNumberFlag() {
	p.flags |= 0x10
}

func (p *GREPacket) setQFI(qfi uint8) {
	b := make([]byte, 4)
	b[0] = qfi & 0x3F
	p.key |= binary.LittleEndian.Uint32(b)
}

func (p *GREPacket) setRQI(rqi bool) {
	if rqi {
		p.key |= uint32(0x80)
	}
}

func (p *GREPacket) SetQoS(qfi uint8, rqi bool) {
	p.setQFI(qfi)
	p.setRQI(rqi)
	p.setKeyFlag()
}
