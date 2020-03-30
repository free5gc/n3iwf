package n3iwf_context

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"gofree5gc/lib/ngap/ngapType"
	"gofree5gc/src/n3iwf/n3iwf_ike/ike_message"
	"net"

	gtpv1 "github.com/wmnsk/go-gtp/v1"
)

const (
	AmfUeNgapIdUnspecified int64 = 0xffffffffff
)

const (
	UsePDUSessionID = iota
	UseDLGTPTNLInfo
)

type N3IWFUe struct {
	/* UE identity*/
	RanUeNgapId           int64
	AmfUeNgapId           int64
	IPAddrv4              string
	IPAddrv6              string
	PortNumber            int32
	MaskedIMEISV          *ngapType.MaskedIMEISV // TS 38.413 9.3.1.54
	Guti                  string
	RRCEstablishmentCause int16
	IPSecInnerIP          string

	/* Relative Context */
	AMF *N3IWFAMF

	/* PDU Session */
	PduSessionList map[int64]*PDUSession // pduSessionId as key
	GTPConnection  []*GTPConnectionInfo

	/* Security */
	Kn3iwf               []uint8                          // 32 bytes (256 bits), value is from NGAP IE "Security Key"
	SecurityCapabilities *ngapType.UESecurityCapabilities // TS 38.413 9.3.1.86

	/* IKE Security Association */
	N3IWFIKESecurityAssociation   *IKESecurityAssociation
	N3IWFChildSecurityAssociation *ChildSecurityAssociation

	/* NAS TCP Connection */
	TCPConnection net.Conn

	/* Others */
	Guami                            *ngapType.GUAMI
	IndexToRfsp                      int64
	Ambr                             *ngapType.UEAggregateMaximumBitRate
	AllowedNssai                     *ngapType.AllowedNSSAI
	RadioCapability                  *ngapType.UERadioCapability                // TODO: This is for RRC, can be deleted
	CoreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformation // TS 38.413 9.3.1.15
	IMSVoiceSupported                int32
}

type PDUSession struct {
	Id              int64 // PDU Session ID
	Type            ngapType.PDUSessionType
	Ambr            *ngapType.PDUSessionAggregateMaximumBitRate
	Snssai          ngapType.SNSSAI
	NetworkInstance *ngapType.NetworkInstance
	ULGTPTNLInfo    *ngapType.GTPTunnel
	DLGTPTNLInfo    *ngapType.GTPTunnel
	QosFlows        map[int64]*QosFlow // QosFlowIdentifier as key
}

type QosFlow struct {
	Identifier int64
	Parameters ngapType.QosFlowLevelQosParameters
}

type GTPConnectionInfo struct {
	RemoteAddr          net.Addr
	IncomingTEID        uint32
	OutgoingTEID        uint32
	UserPlaneConnection *gtpv1.UPlaneConn
}

type IKESecurityAssociation struct {
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Transforms for IKE SA
	EncryptionAlgorithm    *ike_message.Transform
	PseudorandomFunction   *ike_message.Transform
	IntegrityAlgorithm     *ike_message.Transform
	DiffieHellmanGroup     *ike_message.Transform
	ExpandedSequenceNumber *ike_message.Transform

	// Keys
	SK_d  []byte // used for child SA key deriving
	SK_ai []byte // used by initiator for integrity checking
	SK_ar []byte // used by responder for integrity checking
	SK_ei []byte // used by initiator for encrypting
	SK_er []byte // used by responder for encrypting
	SK_pi []byte // used by initiator for IKE authentication
	SK_pr []byte // used by responder for IKE authentication

	// State for IKE_AUTH
	State uint8

	// Temporary data stored for the use in later exchange
	InitiatorID              *ike_message.IdentificationInitiator
	InitiatorCertificate     *ike_message.Certificate
	IKEAuthResponseSA        *ike_message.SecurityAssociation
	TrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	TrafficSelectorResponder *ike_message.TrafficSelectorResponder
	ConcatenatedNonce        []byte
	LastEAPIdentifier        uint8

	// Authentication data
	LocalUnsignedAuthentication  []byte
	RemoteUnsignedAuthentication []byte

	// UE context
	ThisUE *N3IWFUe
}

type ChildSecurityAssociation struct {
	SPI                      uint64
	PeerPublicIPAddr         net.IP
	LocalPublicIPAddr        net.IP
	TrafficSelectorInitiator net.IPNet
	TrafficSelectorResponder net.IPNet
	EncryptionAlgorithm      uint16
	IncomingEncryptionKey    []byte
	OutgoingEncryptionKey    []byte
	IntegrityAlgorithm       uint16
	IncomingIntegrityKey     []byte
	OutgoingIntegrityKey     []byte
	ESN                      bool
}

func (ue *N3IWFUe) init() {
	ue.PduSessionList = make(map[int64]*PDUSession)
}

func (ue *N3IWFUe) Remove() {
	n3iwfSelf := N3IWFSelf()
	ue.DetachAMF()
	delete(n3iwfSelf.UePool, ue.RanUeNgapId)
}

func (ue *N3IWFUe) FindPDUSession(matchType int, match interface{}) *PDUSession {
	switch matchType {
	case UsePDUSessionID:
		if entry, exists := ue.PduSessionList[match.(int64)]; exists {
			return entry
		} else {
			return nil
		}
	case UseDLGTPTNLInfo:
		for _, value := range ue.PduSessionList {
			if CompareGTPTNLInfo(value.DLGTPTNLInfo, match.(*ngapType.GTPTunnel)) {
				return value
			}
		}
		return nil
	default:
		return nil
	}
}

func CompareGTPTNLInfo(localAccess *ngapType.GTPTunnel, incoming *ngapType.GTPTunnel) bool {
	addrLocalAccess := localAccess.TransportLayerAddress.Value.Bytes
	teidLocalAccess := localAccess.GTPTEID.Value
	addrIncoming := incoming.TransportLayerAddress.Value.Bytes
	teidIncoming := incoming.GTPTEID.Value

	isAddrEqual := bytes.Equal(addrLocalAccess, addrIncoming)
	if !isAddrEqual {
		contextLog.Debugf("CompareGTPTNLInfo(): Two address are different")
	}

	isTEIDEqual := bytes.Equal(teidLocalAccess, teidIncoming)
	if !isTEIDEqual {
		contextLog.Debugf("CompareGTPTNLInfo(): Two TEID are different")
	}

	return isAddrEqual && isTEIDEqual
}

func (ue *N3IWFUe) CreatePDUSession(pduSessionID int64, snssai ngapType.SNSSAI) (*PDUSession, error) {
	if _, exists := ue.PduSessionList[pduSessionID]; exists {
		return nil, fmt.Errorf("PDU Session[ID:%d] is already exists", pduSessionID)
	}
	pduSession := PDUSession{}
	pduSession.Id = pduSessionID
	pduSession.Snssai = snssai
	pduSession.QosFlows = make(map[int64]*QosFlow)
	ue.PduSessionList[pduSessionID] = &pduSession
	return &pduSession, nil
}

func (ue *N3IWFUe) CreateIKEChildSecurityAssociation(chosenSecurityAssociation *ike_message.SecurityAssociation) (*ChildSecurityAssociation, error) {
	childSecurityAssociation := new(ChildSecurityAssociation)

	if len(chosenSecurityAssociation.Proposals[0].SPI) > 4 {
		return nil, errors.New("SPI size larger than 4")
	}

	if len(chosenSecurityAssociation.Proposals[0].SPI) <= 8 {
		spi := make([]byte, 8-len(chosenSecurityAssociation.Proposals[0].SPI))
		spi = append(spi, chosenSecurityAssociation.Proposals[0].SPI...)
		childSecurityAssociation.SPI = binary.BigEndian.Uint64(spi)
	}

	childSecurityAssociation.EncryptionAlgorithm = chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm[0].TransformID
	childSecurityAssociation.IntegrityAlgorithm = chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm[0].TransformID
	if chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers[0].TransformID == 0 {
		childSecurityAssociation.ESN = false
	} else {
		childSecurityAssociation.ESN = true
	}

	ue.N3IWFChildSecurityAssociation = childSecurityAssociation

	return childSecurityAssociation, nil
}

func (ue *N3IWFUe) AttachAMF(sctpAddr string) error {
	amf, err := N3IWFSelf().FindAMFBySCTPAddr(sctpAddr)
	if err != nil {
		return err
	}
	amf.N3iwfUeList[ue.RanUeNgapId] = ue
	ue.AMF = amf
	return nil
}
func (ue *N3IWFUe) DetachAMF() {
	amf := ue.AMF
	if amf == nil {
		return
	}
	delete(amf.N3iwfUeList, ue.RanUeNgapId)
}
