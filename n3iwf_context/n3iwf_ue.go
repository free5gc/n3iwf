package n3iwf_context

import (
	"bytes"
	"fmt"
	"gofree5gc/lib/ngap/ngapType"
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

	/* Relative Context */
	AMF *N3IWFAMF

	/* PDU Session */
	PduSessionList map[int64]*PDUSession // pduSessionId as key

	/* Security */
	Kn3iwf               []uint8                          // 32 bytes (256 bits), value is from NGAP IE "Security Key"
	SecurityCapabilities *ngapType.UESecurityCapabilities // TS 38.413 9.3.1.86

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

type GTPConnection struct {
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
