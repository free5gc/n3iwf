package message

import (
	"runtime/debug"

	"github.com/free5gc/n3iwf/internal/logger"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/sctp"
)

func SendToAmf(amf *n3iwf_context.N3IWFAMF, pkt []byte) {
	ngapLog := logger.NgapLog
	if amf == nil {
		ngapLog.Errorf("[N3IWF] AMF Context is nil ")
	} else {
		if n, err := amf.SCTPConn.Write(pkt); err != nil {
			ngapLog.Errorf("Write to SCTP socket failed: %+v", err)
		} else {
			ngapLog.Tracef("Wrote %d bytes", n)
		}
	}
}

func SendNGSetupRequest(
	conn *sctp.SCTPConn,
	n3iwfCtx *n3iwf_context.N3IWFContext,
) {
	ngapLog := logger.NgapLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ngapLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	ngapLog.Infoln("[N3IWF] Send NG Setup Request")

	cfg := n3iwfCtx.Config()
	sctpAddr := conn.RemoteAddr().String()

	if available, _ := n3iwfCtx.AMFReInitAvailableListLoad(sctpAddr); !available {
		ngapLog.Warnf(
			"[N3IWF] Please Wait at least for the indicated time before reinitiating toward same AMF[%s]",
			sctpAddr)
		return
	}
	pkt, err := BuildNGSetupRequest(
		cfg.GetGlobalN3iwfId(),
		cfg.GetRanNodeName(),
		cfg.GetSupportedTAList(),
	)
	if err != nil {
		ngapLog.Errorf("Build NGSetup Request failed: %+v\n", err)
		return
	}

	if n, err := conn.Write(pkt); err != nil {
		ngapLog.Errorf("Write to SCTP socket failed: %+v", err)
	} else {
		ngapLog.Tracef("Wrote %d bytes", n)
	}
}

// partOfNGInterface: if reset type is "reset all", set it to nil TS 38.413 9.2.6.11
func SendNGReset(
	amf *n3iwf_context.N3IWFAMF,
	cause ngapType.Cause,
	partOfNGInterface *ngapType.UEAssociatedLogicalNGConnectionList,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send NG Reset")

	pkt, err := BuildNGReset(cause, partOfNGInterface)
	if err != nil {
		ngapLog.Errorf("Build NGReset failed : %s", err.Error())
		return
	}

	SendToAmf(amf, pkt)
}

func SendNGResetAcknowledge(
	amf *n3iwf_context.N3IWFAMF,
	partOfNGInterface *ngapType.UEAssociatedLogicalNGConnectionList,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send NG Reset Acknowledge")

	if partOfNGInterface != nil && len(partOfNGInterface.List) == 0 {
		ngapLog.Error("length of partOfNGInterface is 0")
		return
	}

	pkt, err := BuildNGResetAcknowledge(partOfNGInterface, diagnostics)
	if err != nil {
		ngapLog.Errorf("Build NGReset Acknowledge failed : %s", err.Error())
		return
	}

	SendToAmf(amf, pkt)
}

func SendInitialContextSetupResponse(
	ranUe *n3iwf_context.N3IWFRanUe,
	responseList *ngapType.PDUSessionResourceSetupListCxtRes,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Initial Context Setup Response")

	if responseList != nil && len(responseList.List) > n3iwf_context.MaxNumOfPDUSessions {
		ngapLog.Errorln("Pdu List out of range")
		return
	}

	if failedList != nil && len(failedList.List) > n3iwf_context.MaxNumOfPDUSessions {
		ngapLog.Errorln("Pdu List out of range")
		return
	}

	pkt, err := BuildInitialContextSetupResponse(ranUe, responseList, failedList, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build Initial Context Setup Response failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendInitialContextSetupFailure(
	ranUe *n3iwf_context.N3IWFRanUe,
	cause ngapType.Cause,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtFail,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Initial Context Setup Failure")

	if failedList != nil && len(failedList.List) > n3iwf_context.MaxNumOfPDUSessions {
		ngapLog.Errorln("Pdu List out of range")
		return
	}

	pkt, err := BuildInitialContextSetupFailure(ranUe, cause, failedList, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build Initial Context Setup Failure failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUEContextModificationResponse(
	ranUe *n3iwf_context.N3IWFRanUe,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send UE Context Modification Response")

	pkt, err := BuildUEContextModificationResponse(ranUe, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build UE Context Modification Response failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUEContextModificationFailure(
	ranUe *n3iwf_context.N3IWFRanUe,
	cause ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send UE Context Modification Failure")

	pkt, err := BuildUEContextModificationFailure(ranUe, cause, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build UE Context Modification Failure failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUEContextReleaseComplete(
	ranUe *n3iwf_context.N3IWFRanUe,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send UE Context Release Complete")

	pkt, err := BuildUEContextReleaseComplete(ranUe, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build UE Context Release Complete failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUEContextReleaseRequest(
	ranUe *n3iwf_context.N3IWFRanUe, cause ngapType.Cause,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send UE Context Release Request")

	pkt, err := BuildUEContextReleaseRequest(ranUe, cause)
	if err != nil {
		ngapLog.Errorf("Build UE Context Release Request failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendInitialUEMessage(amf *n3iwf_context.N3IWFAMF,
	ranUe *n3iwf_context.N3IWFRanUe, nasPdu []byte,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Initial UE Message")
	// Attach To AMF

	pkt, err := BuildInitialUEMessage(ranUe, nasPdu, nil)
	if err != nil {
		ngapLog.Errorf("Build Initial UE Message failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
	// ranUe.AttachAMF()
}

func SendUplinkNASTransport(
	ranUe *n3iwf_context.N3IWFRanUe,
	nasPdu []byte,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Uplink NAS Transport")

	if len(nasPdu) == 0 {
		ngapLog.Errorln("NAS Pdu is nil")
		return
	}

	pkt, err := BuildUplinkNASTransport(ranUe, nasPdu)
	if err != nil {
		ngapLog.Errorf("Build Uplink NAS Transport failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendNASNonDeliveryIndication(
	ranUe *n3iwf_context.N3IWFRanUe,
	nasPdu []byte,
	cause ngapType.Cause,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send NAS NonDelivery Indication")

	if len(nasPdu) == 0 {
		ngapLog.Errorln("NAS Pdu is nil")
		return
	}

	pkt, err := BuildNASNonDeliveryIndication(ranUe, nasPdu, cause)
	if err != nil {
		ngapLog.Errorf("Build Uplink NAS Transport failed : %+v\n", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendRerouteNASRequest() {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Reroute NAS Request")
}

func SendPDUSessionResourceSetupResponse(
	ranUe *n3iwf_context.N3IWFRanUe,
	responseList *ngapType.PDUSessionResourceSetupListSURes,
	failedListSURes *ngapType.PDUSessionResourceFailedToSetupListSURes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send PDU Session Resource Setup Response")

	if ranUe == nil {
		ngapLog.Error("UE context is nil, this information is mandatory.")
		return
	}

	pkt, err := BuildPDUSessionResourceSetupResponse(ranUe, responseList, failedListSURes, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build PDU Session Resource Setup Response failed : %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendPDUSessionResourceModifyResponse(
	ranUe *n3iwf_context.N3IWFRanUe,
	responseList *ngapType.PDUSessionResourceModifyListModRes,
	failedList *ngapType.PDUSessionResourceFailedToModifyListModRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send PDU Session Resource Modify Response")

	if ranUe == nil && criticalityDiagnostics == nil {
		ngapLog.Error("UE context is nil, this information is mandatory")
		return
	}

	pkt, err := BuildPDUSessionResourceModifyResponse(ranUe, responseList, failedList, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build PDU Session Resource Modify Response failed : %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendPDUSessionResourceModifyIndication(
	ranUe *n3iwf_context.N3IWFRanUe,
	modifyList []ngapType.PDUSessionResourceModifyItemModInd,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send PDU Session Resource Modify Indication")

	if ranUe == nil {
		ngapLog.Error("UE context is nil, this information is mandatory")
		return
	}
	if modifyList == nil {
		ngapLog.Errorln(
			"PDU Session Resource Modify Indication List is nil. This message shall contain at least one Item")
		return
	}

	pkt, err := BuildPDUSessionResourceModifyIndication(ranUe, modifyList)
	if err != nil {
		ngapLog.Errorf("Build PDU Session Resource Modify Indication failed : %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendPDUSessionResourceNotify(
	ranUe *n3iwf_context.N3IWFRanUe,
	notiList *ngapType.PDUSessionResourceNotifyList,
	relList *ngapType.PDUSessionResourceReleasedListNot,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send PDU Session Resource Notify")

	if ranUe == nil {
		ngapLog.Error("UE context is nil, this information is mandatory")
		return
	}

	pkt, err := BuildPDUSessionResourceNotify(ranUe, notiList, relList)
	if err != nil {
		ngapLog.Errorf("Build PDUSession Resource Notify failed : %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendPDUSessionResourceReleaseResponse(
	ranUe *n3iwf_context.N3IWFRanUe,
	relList ngapType.PDUSessionResourceReleasedListRelRes,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send PDU Session Resource Release Response")

	if ranUe == nil {
		ngapLog.Error("UE context is nil, this information is mandatory")
		return
	}
	if len(relList.List) < 1 {
		ngapLog.Errorln(
			"PDUSessionResourceReleasedListRelRes is nil. This message shall contain at least one Item")
		return
	}

	pkt, err := BuildPDUSessionResourceReleaseResponse(ranUe, relList, diagnostics)
	if err != nil {
		ngapLog.Errorf("Build PDU Session Resource Release Response failed : %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendErrorIndication(
	amf *n3iwf_context.N3IWFAMF,
	amfUENGAPID *int64,
	ranUENGAPID *int64,
	cause *ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Error Indication")

	if (cause == nil) && (criticalityDiagnostics == nil) {
		ngapLog.Errorln("Both cause and criticality is nil. This message shall contain at least one of them.")
		return
	}

	pkt, err := BuildErrorIndication(amfUENGAPID, ranUENGAPID, cause, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build Error Indication failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendErrorIndicationWithSctpConn(
	sctpConn *sctp.SCTPConn,
	amfUENGAPID *int64,
	ranUENGAPID *int64,
	cause *ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Error Indication")

	if (cause == nil) && (criticalityDiagnostics == nil) {
		ngapLog.Errorln("Both cause and criticality is nil. This message shall contain at least one of them.")
		return
	}

	pkt, err := BuildErrorIndication(amfUENGAPID, ranUENGAPID, cause, criticalityDiagnostics)
	if err != nil {
		ngapLog.Errorf("Build Error Indication failed : %+v\n", err)
		return
	}

	if n, err := sctpConn.Write(pkt); err != nil {
		ngapLog.Errorf("Write to SCTP socket failed: %+v", err)
	} else {
		ngapLog.Tracef("Wrote %d bytes", n)
	}
}

func SendUERadioCapabilityInfoIndication() {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send UE Radio Capability Info Indication")
}

func SendUERadioCapabilityCheckResponse(
	amf *n3iwf_context.N3IWFAMF,
	ranUe *n3iwf_context.N3IWFRanUe,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send UE Radio Capability Check Response")

	pkt, err := BuildUERadioCapabilityCheckResponse(ranUe, diagnostics)
	if err != nil {
		ngapLog.Errorf("Build UERadio Capability Check Response failed : %+v\n", err)
		return
	}
	SendToAmf(ranUe.AMF, pkt)
}

func SendAMFConfigurationUpdateAcknowledge(
	amf *n3iwf_context.N3IWFAMF,
	setupList *ngapType.AMFTNLAssociationSetupList,
	failList *ngapType.TNLAssociationList,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send AMF Configuration Update Acknowledge")

	pkt, err := BuildAMFConfigurationUpdateAcknowledge(setupList, failList, diagnostics)
	if err != nil {
		ngapLog.Errorf("Build AMF Configuration Update Acknowledge failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendAMFConfigurationUpdateFailure(
	amf *n3iwf_context.N3IWFAMF,
	ngCause ngapType.Cause,
	time *ngapType.TimeToWait,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send AMF Configuration Update Failure")
	pkt, err := BuildAMFConfigurationUpdateFailure(ngCause, time, diagnostics)
	if err != nil {
		ngapLog.Errorf("Build AMF Configuration Update Failure failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendRANConfigurationUpdate(
	n3iwfCtx *n3iwf_context.N3IWFContext,
	amf *n3iwf_context.N3IWFAMF,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send RAN Configuration Update")

	available, _ := n3iwfCtx.AMFReInitAvailableListLoad(amf.SCTPAddr)
	if !available {
		ngapLog.Warnf(
			"[N3IWF] Please Wait at least for the indicated time before reinitiating toward same AMF[%s]",
			amf.SCTPAddr)
		return
	}

	cfg := n3iwfCtx.Config()
	pkt, err := BuildRANConfigurationUpdate(
		cfg.GetRanNodeName(),
		cfg.GetSupportedTAList())
	if err != nil {
		ngapLog.Errorf("Build AMF Configuration Update Failure failed : %+v\n", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendUplinkRANConfigurationTransfer() {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Uplink RAN Configuration Transfer")
}

func SendUplinkRANStatusTransfer() {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Uplink RAN Status Transfer")
}

func SendLocationReportingFailureIndication() {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Location Reporting Failure Indication")
}

func SendLocationReport() {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send Location Report")
}

func SendRRCInactiveTransitionReport() {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("[N3IWF] Send RRC Inactive Transition Report")
}
