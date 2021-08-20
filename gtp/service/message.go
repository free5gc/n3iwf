package service

import (
	"encoding/hex"

	gtpMessage "github.com/wmnsk/go-gtp/gtpv1/message"
)

type ExtensionHeader struct {
	Type           uint8
	Length         uint8
	Content        []byte
	NextHeaderType uint8
}

// [29.281 5.2.1-3] Next Extension Header Field Value
const (
	NoMoreExtensionHeaders uint8 = 0x0
	PDUSessionContainer    uint8 = 0x85
)

const (
	SQNLength            int = 2
	PNLength             int = 1
	NextHeaderTypeLength int = 1
)

type TPDUPacket struct {
	staticHeader    *gtpMessage.TPDU
	extensionHeader []ExtensionHeader
	payload         []byte
	qos             bool
	rqi             bool
	qfi             uint8
}

func (p *TPDUPacket) HasExtensionHeader() bool {
	return ((int(p.staticHeader.Header.Flags) >> 2) & 0x1) == 1
}

func (p *TPDUPacket) GetPayload() []byte {
	return p.payload
}

func (p *TPDUPacket) SetPayload(payload []byte) {
	p.payload = payload
}

func (p *TPDUPacket) GetTEID() uint32 {
	return p.staticHeader.TEID()
}

func (p *TPDUPacket) GetExtensionHeader() []ExtensionHeader {
	return p.extensionHeader
}

func (p *TPDUPacket) HasQoS() bool {
	return p.qos
}

func (p *TPDUPacket) GetQoSParameters() (bool, uint8) {
	return p.rqi, p.qfi
}

func (p *TPDUPacket) Unmarshal(pdu *gtpMessage.TPDU) error {
	p.staticHeader = pdu
	p.payload = pdu.Payload
	if p.staticHeader.HasExtensionHeader() {
		if err := p.unmarshalExtensionHeader(); err != nil {
			return err
		}
	}

	return nil
}

// [TS 29.281] [TS 38.415]
// Define GTP extension header
func (p *TPDUPacket) unmarshalExtensionHeader() error {
	payload := p.GetPayload()

	if len(payload) < 1 {
		return gtpMessage.ErrTooShortToParse
	}

	NextExtensionHeaderFieldValue := p.staticHeader.NextExtensionHeaderType

	for {
		switch NextExtensionHeaderFieldValue {
		case PDUSessionContainer:
			var exh ExtensionHeader

			exh.Type = NextExtensionHeaderFieldValue
			exh.Length = payload[0]

			// [TS 29.281 5.2.1] Extension Header Length field specifies
			// the length of the particular Extension header in 4 octets units
			if int(exh.Length)*4 >= len(payload) {
				return gtpMessage.ErrTooShortToParse
			}

			exh.Content = payload[1 : exh.Length*4-1]

			p.qos = true
			p.rqi = ((int(exh.Content[1]) >> 6) & 0x1) == 1
			p.qfi = exh.Content[1] & 0x3F

			exh.NextHeaderType = payload[exh.Length*4-1]
			NextExtensionHeaderFieldValue = exh.NextHeaderType

			p.extensionHeader = append(p.extensionHeader, exh)
			p.SetPayload(payload[exh.Length*4:])

			gtpLog.Tracef("Parsed Extension Header: Len=%d, Next Type=%d, Content Dump:\n%s",
				exh.Length, exh.NextHeaderType, hex.Dump(exh.Content))
		case NoMoreExtensionHeaders:
			return nil
		default:
			gtpLog.Warningf("Unsupported Extension Header Field Value: %x", NextExtensionHeaderFieldValue)
		}
		// TODO: Support the other header field values
	}
}
