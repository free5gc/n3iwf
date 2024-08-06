package context

import (
	"fmt"
	"net"

	"github.com/pkg/errors"

	"github.com/free5gc/ngap/ngapType"
)

type N3IWFRanUe struct {
	/* UE identity */
	RanUeNgapId  int64
	AmfUeNgapId  int64
	IPAddrv4     string
	IPAddrv6     string
	PortNumber   int32
	MaskedIMEISV *ngapType.MaskedIMEISV // TS 38.413 9.3.1.54
	Guti         string

	/* Relative Context */
	N3iwfCtx *N3IWFContext
	AMF      *N3IWFAMF

	/* Security */
	SecurityCapabilities *ngapType.UESecurityCapabilities // TS 38.413 9.3.1.86

	/* PDU Session */
	PduSessionList map[int64]*PDUSession // pduSessionId as key

	/* PDU Session Setup Temporary Data */
	TemporaryPDUSessionSetupData *PDUSessionSetupTemporaryData

	/* Temporary cached NAS message */
	// Used when NAS registration accept arrived before
	// UE setup NAS TCP connection with N3IWF, and
	// Forward pduSessionEstablishmentAccept to UE after
	// UE send CREATE_CHILD_SA response
	TemporaryCachedNASMessage []byte

	/* NAS TCP Connection Established */
	IsNASTCPConnEstablished         bool
	IsNASTCPConnEstablishedComplete bool

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
	RRCEstablishmentCause            int16
	PduSessionReleaseList            ngapType.PDUSessionResourceReleasedListRelRes
}

type PDUSession struct {
	Id                               int64 // PDU Session ID
	Type                             *ngapType.PDUSessionType
	Ambr                             *ngapType.PDUSessionAggregateMaximumBitRate
	Snssai                           ngapType.SNSSAI
	NetworkInstance                  *ngapType.NetworkInstance
	SecurityCipher                   bool
	SecurityIntegrity                bool
	MaximumIntegrityDataRateUplink   *ngapType.MaximumIntegrityProtectedDataRate
	MaximumIntegrityDataRateDownlink *ngapType.MaximumIntegrityProtectedDataRate
	GTPConnection                    *GTPConnectionInfo
	QFIList                          []uint8
	QosFlows                         map[int64]*QosFlow // QosFlowIdentifier as key
}

type QosFlow struct {
	Identifier int64
	Parameters ngapType.QosFlowLevelQosParameters
}

type GTPConnectionInfo struct {
	UPFIPAddr    string
	UPFUDPAddr   net.Addr
	IncomingTEID uint32
	OutgoingTEID uint32
}

type PDUSessionSetupTemporaryData struct {
	// Slice of unactivated PDU session
	UnactivatedPDUSession []*PDUSession // PDUSession as content
	// NGAPProcedureCode is used to identify which type of
	// response shall be used
	NGAPProcedureCode ngapType.ProcedureCode
	// PDU session setup list response
	SetupListCxtRes  *ngapType.PDUSessionResourceSetupListCxtRes
	FailedListCxtRes *ngapType.PDUSessionResourceFailedToSetupListCxtRes
	SetupListSURes   *ngapType.PDUSessionResourceSetupListSURes
	FailedListSURes  *ngapType.PDUSessionResourceFailedToSetupListSURes
	// List of Error for failed setup PDUSessionID
	FailedErrStr []EvtError // Error string as content
	// Current Index of UnactivatedPDUSession
	Index int
}

func (ranUe *N3IWFRanUe) init(ranUeNgapId int64) {
	ranUe.RanUeNgapId = ranUeNgapId
	ranUe.AmfUeNgapId = AmfUeNgapIdUnspecified
	ranUe.PduSessionList = make(map[int64]*PDUSession)
	ranUe.IsNASTCPConnEstablished = false
	ranUe.IsNASTCPConnEstablishedComplete = false
}

func (ranUe *N3IWFRanUe) Remove() error {
	// remove from AMF context
	ranUe.DetachAMF()

	// remove from RAN UE context
	n3iwfCtx := ranUe.N3iwfCtx
	n3iwfCtx.DeleteRanUe(ranUe.RanUeNgapId)

	for _, pduSession := range ranUe.PduSessionList {
		n3iwfCtx.DeleteTEID(pduSession.GTPConnection.IncomingTEID)
	}

	if ranUe.TCPConnection != nil {
		if err := ranUe.TCPConnection.Close(); err != nil {
			return errors.Errorf("Close TCP conn error : %v", err)
		}
	}

	return nil
}

func (ranUe *N3IWFRanUe) FindPDUSession(pduSessionID int64) *PDUSession {
	if pduSession, ok := ranUe.PduSessionList[pduSessionID]; ok {
		return pduSession
	} else {
		return nil
	}
}

func (ranUe *N3IWFRanUe) CreatePDUSession(pduSessionID int64, snssai ngapType.SNSSAI) (*PDUSession, error) {
	if _, exists := ranUe.PduSessionList[pduSessionID]; exists {
		return nil, fmt.Errorf("PDU Session[ID:%d] is already exists", pduSessionID)
	}
	pduSession := &PDUSession{
		Id:       pduSessionID,
		Snssai:   snssai,
		QosFlows: make(map[int64]*QosFlow),
	}
	ranUe.PduSessionList[pduSessionID] = pduSession
	return pduSession, nil
}

func (ranUe *N3IWFRanUe) AttachAMF(sctpAddr string) bool {
	if amf, ok := ranUe.N3iwfCtx.AMFPoolLoad(sctpAddr); ok {
		amf.N3iwfRanUeList[ranUe.RanUeNgapId] = ranUe
		ranUe.AMF = amf
		return true
	} else {
		return false
	}
}

func (ranUe *N3IWFRanUe) DetachAMF() {
	if ranUe.AMF == nil {
		return
	}
	delete(ranUe.AMF.N3iwfRanUeList, ranUe.RanUeNgapId)
}
