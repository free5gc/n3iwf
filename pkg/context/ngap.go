package context

import (
	"git.cs.nctu.edu.tw/calee/sctp"
)

type NGAPServer struct {
	Conn         []*sctp.SCTPConn
	RcvNgapPktCh chan ReceiveNGAPPacket
	RcvEventCh   chan NgapEvt
}
type ReceiveNGAPPacket struct {
	Conn *sctp.SCTPConn
	Buf  []byte
}

type NgapEventType int64

// NGAP event type
const (
	UnmarshalEAP5GData NgapEventType = iota
	SendInitialUEMessage
	SendPDUSessionResourceSetupResponse
	SendNASMsg
	StartTCPSignalNASMsg
	NASTCPConnEstablishedComplete
	SendUEContextReleaseRequest
	SendUEContextReleaseComplete
	SendPDUSessionResourceReleaseResponse
	GetNGAPContext
)

type EvtError string

func (e EvtError) Error() string { return string(e) }

// NGAP IKE event error string
const (
	ErrNil                          = EvtError("Nil")
	ErrRadioConnWithUeLost          = EvtError("RadioConnectionWithUeLost")
	ErrTransportResourceUnavailable = EvtError("TransportResourceUnavailable")
	ErrAMFSelection                 = EvtError("No avalible AMF for this UE")
)

type NgapEvt interface {
	Type() NgapEventType
}

type UnmarshalEAP5GDataEvt struct {
	LocalSPI      uint64
	EAPVendorData []byte
	IsInitialUE   bool
	RanUeNgapId   int64
}

func (unmarshalEAP5GDataEvt *UnmarshalEAP5GDataEvt) Type() NgapEventType {
	return UnmarshalEAP5GData
}

func NewUnmarshalEAP5GDataEvt(localSPI uint64, eapVendorData []byte, isInitialUE bool,
	ranUeNgapId int64,
) *UnmarshalEAP5GDataEvt {
	return &UnmarshalEAP5GDataEvt{
		LocalSPI:      localSPI,
		EAPVendorData: eapVendorData,
		IsInitialUE:   isInitialUE,
		RanUeNgapId:   ranUeNgapId,
	}
}

type SendInitialUEMessageEvt struct {
	RanUeNgapId int64
	IPv4Addr    string
	IPv4Port    int
	NasPDU      []byte
}

func (sendInitialUEMessageEvt *SendInitialUEMessageEvt) Type() NgapEventType {
	return SendInitialUEMessage
}

func NewSendInitialUEMessageEvt(ranUeNgapId int64, ipv4Addr string, ipv4Port int,
	nasPDU []byte,
) *SendInitialUEMessageEvt {
	return &SendInitialUEMessageEvt{
		RanUeNgapId: ranUeNgapId,
		IPv4Addr:    ipv4Addr,
		IPv4Port:    ipv4Port,
		NasPDU:      nasPDU,
	}
}

type SendPDUSessionResourceSetupResEvt struct {
	RanUeNgapId int64
}

func (sendPDUSessionResourceSetupResEvt *SendPDUSessionResourceSetupResEvt) Type() NgapEventType {
	return SendPDUSessionResourceSetupResponse
}

func NewSendPDUSessionResourceSetupResEvt(ranUeNgapId int64) *SendPDUSessionResourceSetupResEvt {
	return &SendPDUSessionResourceSetupResEvt{
		RanUeNgapId: ranUeNgapId,
	}
}

type SendNASMsgEvt struct {
	RanUeNgapId int64
}

func (sendNASMsgEvt *SendNASMsgEvt) Type() NgapEventType {
	return SendNASMsg
}

func NewSendNASMsgEvt(ranUeNgapId int64) *SendNASMsgEvt {
	return &SendNASMsgEvt{
		RanUeNgapId: ranUeNgapId,
	}
}

type StartTCPSignalNASMsgEvt struct {
	RanUeNgapId int64
}

func (startTCPSignalNASMsgEvt *StartTCPSignalNASMsgEvt) Type() NgapEventType {
	return StartTCPSignalNASMsg
}

func NewStartTCPSignalNASMsgEvt(ranUeNgapId int64) *StartTCPSignalNASMsgEvt {
	return &StartTCPSignalNASMsgEvt{
		RanUeNgapId: ranUeNgapId,
	}
}

type NASTCPConnEstablishedCompleteEvt struct {
	RanUeNgapId int64
}

func (nasTCPConnEstablishedCompleteEvt *NASTCPConnEstablishedCompleteEvt) Type() NgapEventType {
	return NASTCPConnEstablishedComplete
}

func NewNASTCPConnEstablishedCompleteEvt(ranUeNgapId int64) *NASTCPConnEstablishedCompleteEvt {
	return &NASTCPConnEstablishedCompleteEvt{
		RanUeNgapId: ranUeNgapId,
	}
}

type SendUEContextReleaseRequestEvt struct {
	RanUeNgapId int64
	ErrMsg      EvtError
}

func (sendUEContextReleaseRequestEvt *SendUEContextReleaseRequestEvt) Type() NgapEventType {
	return SendUEContextReleaseRequest
}

func NewSendUEContextReleaseRequestEvt(ranUeNgapId int64, errMsg EvtError,
) *SendUEContextReleaseRequestEvt {
	return &SendUEContextReleaseRequestEvt{
		RanUeNgapId: ranUeNgapId,
		ErrMsg:      errMsg,
	}
}

type SendUEContextReleaseCompleteEvt struct {
	RanUeNgapId int64
}

func (sendUEContextReleaseCompleteEvt *SendUEContextReleaseCompleteEvt) Type() NgapEventType {
	return SendUEContextReleaseComplete
}

func NewSendUEContextReleaseCompleteEvt(ranUeNgapId int64) *SendUEContextReleaseCompleteEvt {
	return &SendUEContextReleaseCompleteEvt{
		RanUeNgapId: ranUeNgapId,
	}
}

type SendPDUSessionResourceReleaseResEvt struct {
	RanUeNgapId int64
}

func (sendPDUSessionResourceReleaseResEvt *SendPDUSessionResourceReleaseResEvt) Type() NgapEventType {
	return SendPDUSessionResourceReleaseResponse
}

func NewSendPDUSessionResourceReleaseResEvt(ranUeNgapId int64) *SendPDUSessionResourceReleaseResEvt {
	return &SendPDUSessionResourceReleaseResEvt{
		RanUeNgapId: ranUeNgapId,
	}
}

// Ngap context
const (
	CxtTempPDUSessionSetupData int64 = iota
)

type GetNGAPContextEvt struct {
	RanUeNgapId       int64
	NgapCxtReqNumlist []int64
}

func (getNGAPContextEvt *GetNGAPContextEvt) Type() NgapEventType {
	return GetNGAPContext
}

func NewGetNGAPContextEvt(ranUeNgapId int64, ngapCxtReqNumlist []int64) *GetNGAPContextEvt {
	return &GetNGAPContextEvt{
		RanUeNgapId:       ranUeNgapId,
		NgapCxtReqNumlist: ngapCxtReqNumlist,
	}
}
