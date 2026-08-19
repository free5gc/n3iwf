package ngap

import (
	"encoding/binary"
	"math"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-gtp/gtpv1"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/internal/nas/nas_security"
	"github.com/free5gc/n3iwf/internal/ngap/message"
	"github.com/free5gc/n3iwf/internal/util"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/sctp"
	ngap_metrics "github.com/free5gc/util/metrics/ngap"
)

func (s *Server) HandleNGSetupResponse(
	sctpAddr string,
	conn *sctp.SCTPConn,
	ngSetupResponse *ngapMessage.NGSetupResponse,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle NG Setup Response")

	if ngSetupResponse == nil {
		ngapLog.Error("NGSetupResponse is nil")
		return
	}

	amfName := ngSetupResponse.AMFName
	servedGUAMIList := ngSetupResponse.ServedGUAMIList
	relativeAMFCapacity := ngSetupResponse.RelativeAMFCapacity
	plmnSupportList := ngSetupResponse.PLMNSupportList
	criticalityDiagnostics := ngSetupResponse.CriticalityDiagnostics
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	var syntaxCause ngapType.Cause
	metricStatusOk := false

	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.NG_SETUP_RESPONSE, &metricStatusOk, &syntaxCause)

	n3iwfCtx := s.Context()

	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDAMFName, amfName == nil},
		{ngapType.ProtocolIEIDServedGUAMIList, servedGUAMIList == nil},
		{ngapType.ProtocolIEIDPLMNSupportList, plmnSupportList == nil},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	if len(iesCriticalityDiagnostics.List) != 0 {
		ngapLog.Traceln("[NGAP] Sending error indication to AMF, because some mandatory IEs were not included")

		cause := message.BuildCause(message.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)

		syntaxCause = *cause

		procedureCode := ngapMessage.ProcedureCodeNGSetup
		triggeringMessage := ngapType.TriggeringMessagePresentSuccessfulOutcome
		procedureCriticality := ngapType.CriticalityPresentReject

		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procedureCode, &triggeringMessage, &procedureCriticality, &iesCriticalityDiagnostics)

		message.SendErrorIndicationWithSctpConn(conn, nil, nil, cause, &criticalityDiagnostics)

		return
	}

	amfInfo := n3iwfCtx.NewN3iwfAmf(sctpAddr, conn)

	if amfName != nil {
		amfInfo.AMFName = amfName
	}

	if servedGUAMIList != nil {
		amfInfo.ServedGUAMIList = servedGUAMIList
	}

	if relativeAMFCapacity != nil {
		amfInfo.RelativeAMFCapacity = relativeAMFCapacity
	}

	if plmnSupportList != nil {
		amfInfo.PLMNSupportList = plmnSupportList
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}
	metricStatusOk = true
}

func (s *Server) HandleNGSetupFailure(
	sctpAddr string,
	conn *sctp.SCTPConn,
	ngSetupFailure *ngapMessage.NGSetupFailure,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle NG Setup Failure")

	if ngSetupFailure == nil {
		ngapLog.Error("NGSetupFailure is nil")
		return
	}

	cause := ngSetupFailure.Cause
	timeToWait := ngSetupFailure.TimeToWait
	criticalityDiagnostics := ngSetupFailure.CriticalityDiagnostics
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.NG_SETUP_FAILURE, &metricStatusOk, cause)

	n3iwfCtx := s.Context()

	if cause == nil {
		item := buildCriticalityDiagnosticsIEItem(
			ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDCause,
			ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		// TODO: Send error indication
		ngapLog.Traceln("[NGAP] Sending error indication to AMF, because some mandatory IEs were not included")

		cause = message.BuildCause(
			message.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)

		procedureCode := ngapMessage.ProcedureCodeNGSetup
		triggeringMessage := ngapType.TriggeringMessagePresentUnsuccessfulOutcome
		procedureCriticality := ngapType.CriticalityPresentReject

		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procedureCode, &triggeringMessage, &procedureCriticality, &iesCriticalityDiagnostics)

		message.SendErrorIndicationWithSctpConn(conn, nil, nil, cause, &criticalityDiagnostics)
		return
	}

	if cause != nil {
		printAndGetCause(cause)
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}

	var waitingTime int
	if timeToWait != nil {
		switch timeToWait.Value {
		case ngapType.TimeToWaitPresentV1s:
			waitingTime = 1
		case ngapType.TimeToWaitPresentV2s:
			waitingTime = 2
		case ngapType.TimeToWaitPresentV5s:
			waitingTime = 5
		case ngapType.TimeToWaitPresentV10s:
			waitingTime = 10
		case ngapType.TimeToWaitPresentV20s:
			waitingTime = 20
		case ngapType.TimeToWaitPresentV60s:
			waitingTime = 60
		}
	}

	if waitingTime != 0 {
		ngapLog.Infof("Wait at lease  %ds to reinitialize with same AMF[%s]", waitingTime, sctpAddr)
		n3iwfCtx.AMFReInitAvailableListStore(sctpAddr, false)
		time.AfterFunc(time.Duration(waitingTime)*time.Second, func() {
			n3iwfCtx.AMFReInitAvailableListStore(sctpAddr, true)
			message.SendNGSetupRequest(conn, n3iwfCtx)
		})
		return
	}
	metricStatusOk = true
}

func (s *Server) HandleNGReset(
	amf *n3iwf_context.N3IWFAMF,
	nGReset *ngapMessage.NGReset,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle NG Reset")

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if nGReset == nil {
		ngapLog.Error("nGReset is nil")
		return
	}

	cause := nGReset.Cause
	resetType := nGReset.ResetType
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.NG_RESET, &metricStatusOk, cause)

	n3iwfCtx := s.Context()

	if resetType == nil {
		item := buildCriticalityDiagnosticsIEItem(
			ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDResetType,
			ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		procudureCode := ngapMessage.ProcedureCodeNGReset
		trigger := ngapType.TriggeringMessagePresentInitiatingMessage
		criticality := ngapType.CriticalityPresentReject
		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procudureCode, &trigger, &criticality, &iesCriticalityDiagnostics)
		message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	printAndGetCause(cause)

	switch resetChoice := resetType.Choice.(type) {
	case *ngapType.ResetAll:
		ngapLog.Trace("ResetType Present: NG Interface")
		// TODO: Release Uu Interface related to this amf(IPSec)
		// Remove all Ue
		if err := amf.RemoveAllRelatedUe(); err != nil {
			ngapLog.Errorf("RemoveAllRelatedUe error : %v", err)
		}
		message.SendNGResetAcknowledge(amf, nil, nil)
	case *ngapType.UEAssociatedLogicalNGConnectionList:
		ngapLog.Trace("ResetType Present: Part of NG Interface")
		partOfNGInterface := resetChoice
		if partOfNGInterface == nil {
			ngapLog.Error("PartOfNGInterface is nil")
			return
		}

		var ranUe n3iwf_context.RanUe

		for _, ueAssociatedLogicalNGConnectionItem := range partOfNGInterface.List {
			if ueAssociatedLogicalNGConnectionItem.RANUENGAPID != nil {
				ngapLog.Tracef("RanUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
				ranUe, _ = n3iwfCtx.RanUePoolLoad(ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
			} else if ueAssociatedLogicalNGConnectionItem.AMFUENGAPID != nil {
				ngapLog.Tracef("AmfUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
				ranUe = amf.FindUeByAmfUeNgapID(ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
			}

			if ranUe == nil {
				ngapLog.Warn("Cannot not find RanUE Context")
				if ueAssociatedLogicalNGConnectionItem.AMFUENGAPID != nil {
					ngapLog.Warnf("AmfUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
				}
				if ueAssociatedLogicalNGConnectionItem.RANUENGAPID != nil {
					ngapLog.Warnf("RanUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
				}
				continue
			}
			// TODO: Release Uu Interface (IPSec)
			if err := ranUe.Remove(); err != nil {
				ngapLog.Errorf("Remove RanUE Context error : %v", err)
			}
		}
		message.SendNGResetAcknowledge(amf, partOfNGInterface, nil)
	default:
		ngapLog.Warnf("Invalid ResetType choice %T", resetType.Choice)
	}
	metricStatusOk = true
}

func (s *Server) HandleNGResetAcknowledge(
	amf *n3iwf_context.N3IWFAMF,
	nGResetAcknowledge *ngapMessage.NGResetAcknowledge,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle NG Reset Acknowledge")

	uEAssociatedLogicalNGConnectionList := nGResetAcknowledge.UEAssociatedLogicalNGConnectionList
	criticalityDiagnostics := nGResetAcknowledge.CriticalityDiagnostics

	var syntaxCause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.NG_RESET_ACKNOWLEDGE, &metricStatusOk, syntaxCause)

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if nGResetAcknowledge == nil {
		ngapLog.Error("nGResetAcknowledge is nil")
		return
	}

	if uEAssociatedLogicalNGConnectionList != nil {
		ngapLog.Tracef("%d RanUE association(s) has been reset", len(uEAssociatedLogicalNGConnectionList.List))
		for i, item := range uEAssociatedLogicalNGConnectionList.List {
			if item.AMFUENGAPID != nil && item.RANUENGAPID != nil {
				ngapLog.Tracef("%d: AmfUeNgapID[%d] RanUeNgapID[%d]",
					i+1, item.AMFUENGAPID.Value, item.RANUENGAPID.Value)
			} else if item.AMFUENGAPID != nil {
				ngapLog.Tracef("%d: AmfUeNgapID[%d] RanUeNgapID[unknown]", i+1, item.AMFUENGAPID.Value)
			} else if item.RANUENGAPID != nil {
				ngapLog.Tracef("%d: AmfUeNgapID[unknown] RanUeNgapID[%d]", i+1, item.RANUENGAPID.Value)
			}
		}
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}
	metricStatusOk = true
}

func (s *Server) HandleInitialContextSetupRequest(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.InitialContextSetupRequest,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle Initial Context Setup Request")

	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	amfUeNgapID := pdu.AMFUENGAPID
	ranUeNgapID := pdu.RANUENGAPID
	oldAMF := pdu.OldAMF
	ueAggregateMaximumBitRate := pdu.UEAggregateMaximumBitRate
	coreNetworkAssistanceInformation := pdu.CoreNetworkAssistanceInformationForInactive
	guami := pdu.GUAMI
	pduSessionResourceSetupListCxtReq := pdu.PDUSessionResourceSetupListCxtReq
	allowedNSSAI := pdu.AllowedNSSAI
	ueSecurityCapabilities := pdu.UESecurityCapabilities
	securityKey := pdu.SecurityKey
	traceActivation := pdu.TraceActivation
	ueRadioCapability := pdu.UERadioCapability
	indexToRFSP := pdu.IndexToRFSP
	maskedIMEISV := pdu.MaskedIMEISV
	emergencyFallbackIndicator := pdu.EmergencyFallbackIndicator
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	var ranUe n3iwf_context.RanUe
	var ranUeCtx *n3iwf_context.RanUeSharedCtx

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.INITIAL_CONTEXT_SETUP_REQUEST, &metricStatusOk, cause)

	n3iwfCtx := s.Context()

	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDAMFUENGAPID, amfUeNgapID == nil},
		{ngapType.ProtocolIEIDRANUENGAPID, ranUeNgapID == nil},
		{ngapType.ProtocolIEIDGUAMI, guami == nil},
		{ngapType.ProtocolIEIDAllowedNSSAI, allowedNSSAI == nil},
		{ngapType.ProtocolIEIDUESecurityCapabilities, ueSecurityCapabilities == nil},
		{ngapType.ProtocolIEIDSecurityKey, securityKey == nil},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}
	if traceActivation != nil {
		ngapLog.Warnln("Not Supported IE [TraceActivation]")
	}
	if emergencyFallbackIndicator != nil {
		ngapLog.Warnln("Not Supported IE [EmergencyFallbackIndicator]")
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		ngapLog.Traceln(
			"[NGAP] Sending unsuccessful outcome to AMF, because some mandatory IEs were not included")
		cause = message.BuildCause(message.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)

		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)

		failedListCxtFail := new(ngapType.PDUSessionResourceFailedToSetupListCxtFail)
		for _, item := range pduSessionResourceSetupListCxtReq.List {
			transfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", err)
			}
			message.AppendPDUSessionResourceFailedToSetupListCxtfail(
				failedListCxtFail, item.PDUSessionID.Value, transfer)
		}

		message.SendInitialContextSetupFailure(ranUe, *cause, failedListCxtFail, &criticalityDiagnostics)
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			ngapLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
		if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if ranUe == nil {
		ngapLog.Errorf("RAN UE context is nil")
		return
	}

	ranUeCtx.AmfUeNgapId = amfUeNgapID.Value
	ranUeCtx.RanUeNgapId = ranUeNgapID.Value

	if pduSessionResourceSetupListCxtReq != nil {
		if ueAggregateMaximumBitRate != nil {
			ranUeCtx.Ambr = ueAggregateMaximumBitRate
		} else {
			ngapLog.Errorln("IE[UEAggregateMaximumBitRate] is nil")
			cause = message.BuildCause(message.CausePresentProtocol,
				ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)

			criticalityDiagnosticsIEItem := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject,
				ngapType.ProtocolIEIDUEAggregateMaximumBitRate, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, criticalityDiagnosticsIEItem)
			criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)

			failedListCxtFail := new(ngapType.PDUSessionResourceFailedToSetupListCxtFail)
			for _, item := range pduSessionResourceSetupListCxtReq.List {
				transfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", err)
				}
				message.AppendPDUSessionResourceFailedToSetupListCxtfail(
					failedListCxtFail, item.PDUSessionID.Value, transfer)
			}

			message.SendInitialContextSetupFailure(ranUe, *cause, failedListCxtFail, &criticalityDiagnostics)
			return
		}

		setupListCxtRes := new(ngapType.PDUSessionResourceSetupListCxtRes)
		failedListCxtRes := new(ngapType.PDUSessionResourceFailedToSetupListCxtRes)

		// UE temporary data for PDU session setup response
		ranUeCtx.TemporaryPDUSessionSetupData.SetupListCxtRes = setupListCxtRes
		ranUeCtx.TemporaryPDUSessionSetupData.FailedListCxtRes = failedListCxtRes
		ranUeCtx.TemporaryPDUSessionSetupData.Index = 0
		ranUeCtx.TemporaryPDUSessionSetupData.UnactivatedPDUSession = nil
		ranUeCtx.TemporaryPDUSessionSetupData.NGAPProcedureCode.Value = ngapMessage.ProcedureCodeInitialContextSetup

		for _, item := range pduSessionResourceSetupListCxtReq.List {
			pduSessionID := item.PDUSessionID.Value
			// TODO: send NAS to UE
			// pduSessionNasPdu := item.NASPDU
			snssai := item.SNSSAI

			transfer := ngapType.PDUSessionResourceSetupRequestTransfer{}
			err := ngapType.UnmarshalBinary(*item.PDUSessionResourceSetupRequestTransfer, &transfer)
			if err != nil {
				ngapLog.Errorf("[PDUSessionID: %d] PDUSessionResourceSetupRequestTransfer Decode Error: %v\n",
					pduSessionID, err)
			}

			pduSession, err := ranUeCtx.CreatePDUSession(pduSessionID, *snssai)
			if err != nil {
				ngapLog.Errorf("Create PDU Session Error: %v\n", err)

				cause = message.BuildCause(message.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
				unsuccessfulTransfer, buildErr := message.
					BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", buildErr)
				}
				message.AppendPDUSessionResourceFailedToSetupListCxtRes(
					failedListCxtRes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := s.handlePDUSessionResourceSetupRequestTransfer(ranUe, pduSession, transfer)
			if success {
				// Append this PDU session to unactivated PDU session list
				ranUeCtx.TemporaryPDUSessionSetupData.UnactivatedPDUSession = append(
					ranUeCtx.TemporaryPDUSessionSetupData.UnactivatedPDUSession,
					pduSession)
			} else {
				// Delete the pdusession store in UE conext
				delete(ranUeCtx.PduSessionList, pduSessionID)
				message.
					AppendPDUSessionResourceFailedToSetupListCxtRes(failedListCxtRes, pduSessionID, resTransfer)
			}
		}
	}

	if oldAMF != nil {
		ngapLog.Debugf("Old AMF: %s\n", oldAMF.Value)
	}

	if guami != nil {
		ranUeCtx.Guami = guami
	}

	if allowedNSSAI != nil {
		ranUeCtx.AllowedNssai = allowedNSSAI
	}

	if maskedIMEISV != nil {
		ranUeCtx.MaskedIMEISV = maskedIMEISV
	}

	if ueRadioCapability != nil {
		ranUeCtx.RadioCapability = ueRadioCapability
	}

	if coreNetworkAssistanceInformation != nil {
		ranUeCtx.CoreNetworkAssistanceInformation = coreNetworkAssistanceInformation
	}

	if indexToRFSP != nil {
		ranUeCtx.IndexToRfsp = indexToRFSP.Value
	}

	if ueSecurityCapabilities != nil {
		ranUeCtx.SecurityCapabilities = ueSecurityCapabilities
	}

	// Send EAP Success to UE
	switch ue := ranUe.(type) {
	case *n3iwf_context.N3IWFRanUe:
		spi, ok := n3iwfCtx.IkeSpiLoad(ranUeCtx.RanUeNgapId)
		if !ok {
			ngapLog.Errorf("Cannot get spi from ngapid : %+v", ranUeCtx.RanUeNgapId)
			return
		}

		s.SendIkeEvt(n3iwf_context.NewSendEAPSuccessMsgEvt(
			spi, securityKey.Value.Bytes, len(ranUeCtx.PduSessionList),
		))
		metricStatusOk = true
	default:
		ngapLog.Errorf("Unknown UE type: %T", ue)
	}
}

// handlePDUSessionResourceSetupRequestTransfer parse and store needed information from NGAP
// and setup user plane connection for UE
// Parameters:
// UE context :: a pointer to the UE's pdusession data structure ::
// SMF PDU session resource setup request transfer
// Return value:
// a status value indicate whether the handlling is "success" ::
// if failed, an unsuccessfulTransfer is set, otherwise, set to nil
func (s *Server) handlePDUSessionResourceSetupRequestTransfer(
	ranUe n3iwf_context.RanUe,
	pduSession *n3iwf_context.PDUSession,
	transfer ngapType.PDUSessionResourceSetupRequestTransfer,
) (bool, []byte) {
	var pduSessionAMBR *ngapType.PDUSessionAggregateMaximumBitRate
	var ulNGUUPTNLInformation *ngapType.UPTransportLayerInformation
	var pduSessionType *ngapType.PDUSessionType
	var securityIndication *ngapType.SecurityIndication
	var networkInstance *ngapType.NetworkInstance
	var qosFlowSetupRequestList *ngapType.QosFlowSetupRequestList
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfCtx := s.Context()

	if transfer.ProtocolIEs != nil {
		for _, ie := range transfer.ProtocolIEs.List {
			if ie.PDUSessionAggregateMaximumBitRate != nil {
				pduSessionAMBR = ie.PDUSessionAggregateMaximumBitRate
			}
			if ie.ULNGUUPTNLInformation != nil {
				ulNGUUPTNLInformation = ie.ULNGUUPTNLInformation
			}
			if ie.PDUSessionType != nil {
				pduSessionType = ie.PDUSessionType
			}
			if ie.SecurityIndication != nil {
				securityIndication = ie.SecurityIndication
			}
			if ie.NetworkInstance != nil {
				networkInstance = ie.NetworkInstance
			}
			if ie.QosFlowSetupRequestList != nil {
				qosFlowSetupRequestList = ie.QosFlowSetupRequestList
			}
		}
	}
	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDULNGUUPTNLInformation, ulNGUUPTNLInformation == nil},
		{ngapType.ProtocolIEIDPDUSessionType, pduSessionType == nil},
		{ngapType.ProtocolIEIDQosFlowSetupRequestList, qosFlowSetupRequestList == nil},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	ngapLog := logger.NgapLog

	if len(iesCriticalityDiagnostics.List) > 0 {
		cause := message.BuildCause(message.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(
			*cause, &criticalityDiagnostics)
		if err != nil {
			ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", err)
		}
		return false, responseTransfer
	}

	pduSession.Ambr = pduSessionAMBR
	pduSession.Type = pduSessionType
	pduSession.NetworkInstance = networkInstance

	// Security Indication
	if securityIndication != nil {
		switch securityIndication.IntegrityProtectionIndication.Value {
		case ngapType.IntegrityProtectionIndicationPresentNotNeeded:
			pduSession.SecurityIntegrity = false
		case ngapType.IntegrityProtectionIndicationPresentPreferred:
			pduSession.SecurityIntegrity = true
		case ngapType.IntegrityProtectionIndicationPresentRequired:
			pduSession.SecurityIntegrity = true
		default:
			ngapLog.Error("Unknown security integrity indication")
			cause := message.BuildCause(message.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", err)
			}
			return false, responseTransfer
		}

		switch securityIndication.ConfidentialityProtectionIndication.Value {
		case ngapType.ConfidentialityProtectionIndicationPresentNotNeeded:
			pduSession.SecurityCipher = false
		case ngapType.ConfidentialityProtectionIndicationPresentPreferred:
			pduSession.SecurityCipher = true
		case ngapType.ConfidentialityProtectionIndicationPresentRequired:
			pduSession.SecurityCipher = true
		default:
			ngapLog.Error("Unknown security confidentiality indication")
			cause := message.BuildCause(message.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", err)
			}
			return false, responseTransfer
		}
	} else {
		pduSession.SecurityIntegrity = true
		pduSession.SecurityCipher = true
	}

	// TODO: apply qos rule
	for _, item := range qosFlowSetupRequestList.List {
		// QoS Flow
		qosFlow := new(n3iwf_context.QosFlow)
		qosFlow.Identifier = item.QosFlowIdentifier.Value
		qosFlow.Parameters = *item.QosFlowLevelQosParameters
		pduSession.QosFlows[item.QosFlowIdentifier.Value] = qosFlow

		value := item.QosFlowIdentifier.Value
		if value < 0 || value > math.MaxUint8 {
			ngapLog.Errorf("handlePDUSessionResourceSetupRequestTransfer() "+
				"item.QosFlowIdentifier.Value exceeds uint8 range: %d", value)
			return false, nil
		}
		// QFI List
		pduSession.QFIList = append(pduSession.QFIList, uint8(value))
	}

	// Setup GTP tunnel with UPF
	// TODO: Support IPv6
	gtpTunnel, ok := ulNGUUPTNLInformation.Choice.(*ngapType.GTPTunnel)
	if !ok || gtpTunnel == nil || gtpTunnel.TransportLayerAddress == nil || gtpTunnel.GTPTEID == nil {
		cause := message.BuildCause(message.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
		if err != nil {
			ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v", err)
		}
		return false, responseTransfer
	}
	upfIPv4, _ := util.IPAddressToString(*gtpTunnel.TransportLayerAddress)
	if upfIPv4 != "" {
		gtpConnInfo := &n3iwf_context.GTPConnectionInfo{
			UPFIPAddr:    upfIPv4,
			OutgoingTEID: binary.BigEndian.Uint32(gtpTunnel.GTPTEID.Value),
		}

		// UPF UDP address
		upfAddr := upfIPv4 + gtpv1.GTPUPort
		upfUDPAddr, err := net.ResolveUDPAddr("udp", upfAddr)
		if err != nil {
			var responseTransfer []byte

			ngapLog.Errorf("Resolve UPF addr [%s] failed: %v", upfAddr, err)
			cause := message.BuildCause(message.CausePresentTransport,
				ngapType.CauseTransportPresentTransportResourceUnavailable)
			responseTransfer, err = message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", err)
			}
			return false, responseTransfer
		}

		// UE TEID
		ueTEID := n3iwfCtx.NewTEID(ranUe)
		if ueTEID == 0 {
			var responseTransfer []byte

			ngapLog.Error("Invalid TEID (0).")
			cause := message.BuildCause(
				message.CausePresentProtocol,
				ngapType.CauseProtocolPresentUnspecified)
			responseTransfer, err = message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", err)
			}
			return false, responseTransfer
		}

		// Setup GTP connection with UPF
		gtpConnInfo.UPFUDPAddr = upfUDPAddr
		gtpConnInfo.IncomingTEID = ueTEID

		pduSession.GTPConnInfo = gtpConnInfo
	} else {
		ngapLog.Error(
			"Cannot parse \"PDU session resource setup request transfer\" message \"UL NG-U UP TNL Information\"")
		cause := message.BuildCause(message.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
		if err != nil {
			ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", err)
		}
		return false, responseTransfer
	}

	return true, nil
}

func (s *Server) HandleUEContextModificationRequest(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.UEContextModificationRequest,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle UE Context Modification Request")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.UE_CONTEXT_MODIFICATION_REQUEST, &metricStatusOk, cause)

	if amf == nil {
		ngapLog.Error("Corresponding AMF context not found")
		return
	}
	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	amfUeNgapID := pdu.AMFUENGAPID
	newAmfUeNgapID := pdu.NewAMFUENGAPID
	ranUeNgapID := pdu.RANUENGAPID
	ueAggregateMaximumBitRate := pdu.UEAggregateMaximumBitRate
	ueSecurityCapabilities := pdu.UESecurityCapabilities
	securityKey := pdu.SecurityKey
	indexToRFSP := pdu.IndexToRFSP
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	var ranUe n3iwf_context.RanUe
	var ranUeCtx *n3iwf_context.RanUeSharedCtx

	n3iwfCtx := s.Context()

	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDAMFUENGAPID, amfUeNgapID == nil},
		{ngapType.ProtocolIEIDRANUENGAPID, ranUeNgapID == nil},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		// TODO: send unsuccessful outcome or error indication
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			ngapLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
		if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if newAmfUeNgapID != nil {
		ngapLog.Debugf("New AmfUeNgapID[%d]\n", newAmfUeNgapID.Value)
		ranUeCtx.AmfUeNgapId = newAmfUeNgapID.Value
	}

	if ueAggregateMaximumBitRate != nil {
		ranUeCtx.Ambr = ueAggregateMaximumBitRate
		// TODO: use the received UE Aggregate Maximum Bit Rate for all non-GBR QoS flows
	}

	if ueSecurityCapabilities != nil {
		ranUeCtx.SecurityCapabilities = ueSecurityCapabilities
	}

	// TODO: use new security key to update security context

	if indexToRFSP != nil {
		ranUeCtx.IndexToRfsp = indexToRFSP.Value
	}

	message.SendUEContextModificationResponse(ranUe, nil)

	spi, ok := n3iwfCtx.IkeSpiLoad(ranUeCtx.RanUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get spi from ngapid : %+v", ranUeCtx.RanUeNgapId)
		return
	}

	s.SendIkeEvt(n3iwf_context.NewIKEContextUpdateEvt(spi, securityKey.Value.Bytes)) // Kn3iwf

	metricStatusOk = true
}

func (s *Server) HandleUEContextReleaseCommand(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.UEContextReleaseCommand,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle UE Context Release Command")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.UE_CONTEXT_RELEASE_COMMAND, &metricStatusOk, cause)

	if amf == nil {
		ngapLog.Error("Corresponding AMF context not found")
		return
	}
	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	ueNgapIDs := pdu.UENGAPIDs
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var ranUe n3iwf_context.RanUe

	n3iwfCtx := s.Context()

	cause = pdu.Cause
	if ueNgapIDs == nil {
		item := buildCriticalityDiagnosticsIEItem(
			ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDUENGAPIDs,
			ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		// TODO: send error indication
		return
	}

	switch ids := ueNgapIDs.Choice.(type) {
	case *ngapType.UENGAPIDPair:
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ids.RANUENGAPID.Value)
		if !ok {
			ranUe = amf.FindUeByAmfUeNgapID(ids.AMFUENGAPID.Value)
		}
	case *ngapType.AMFUENGAPID:
		// TODO: find UE according to specific AMF
		// The implementation here may have error when N3IWF need to
		// connect multiple AMFs.
		// Use UEpool in AMF context can solve this problem
		ranUe = amf.FindUeByAmfUeNgapID(ids.Value)
	}

	if ranUe == nil {
		// TODO: send error indication(unknown local ngap ue id)
		return
	}

	if cause != nil {
		printAndGetCause(cause)
	}

	ranUe.GetSharedCtx().UeCtxRelState = n3iwf_context.UeCtxRelStateOngoing

	message.SendUEContextReleaseComplete(ranUe, nil)

	err := s.releaseIkeUeAndRanUe(ranUe)
	if err != nil {
		ngapLog.Warnf("HandleUEContextReleaseCommand(): %v", err)
	}

	metricStatusOk = true
}

func (s *Server) releaseIkeUeAndRanUe(ranUe n3iwf_context.RanUe) error {
	n3iwfCtx := s.Context()
	ranUeNgapID := ranUe.GetSharedCtx().RanUeNgapId

	localSPI, ok := n3iwfCtx.IkeSpiLoad(ranUeNgapID)
	if ok {
		s.SendIkeEvt(n3iwf_context.NewIKEDeleteRequestEvt(localSPI))
	}

	if err := ranUe.Remove(); err != nil {
		return errors.Wrapf(err, "releaseIkeUeAndRanUe RanUeNgapId[%016x]", ranUeNgapID)
	}
	return nil
}

func (s *Server) HandleDownlinkNASTransport(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.DownlinkNASTransport,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle Downlink NAS Transport")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.DOWNLINK_NAS_TRANSPORT, &metricStatusOk, cause)

	if amf == nil {
		ngapLog.Error("Corresponding AMF context not found")
		return
	}
	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	amfUeNgapID := pdu.AMFUENGAPID
	ranUeNgapID := pdu.RANUENGAPID
	oldAMF := pdu.OldAMF
	nasPDU := pdu.NASPDU
	indexToRFSP := pdu.IndexToRFSP
	ueAggregateMaximumBitRate := pdu.UEAggregateMaximumBitRate
	allowedNSSAI := pdu.AllowedNSSAI
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var ranUe n3iwf_context.RanUe

	n3iwfCtx := s.Context()

	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDAMFUENGAPID, amfUeNgapID == nil},
		{ngapType.ProtocolIEIDRANUENGAPID, ranUeNgapID == nil},
		{ngapType.ProtocolIEIDNASPDU, nasPDU == nil},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	// if len(iesCriticalityDiagnostics.List) > 0 {
	// TODO: Send Error Indication
	// }

	if ranUeNgapID != nil {
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			ngapLog.Warnf("No UE Context[RanUeNgapID:%d]\n", ranUeNgapID.Value)
			return
		}
	}
	ranUeCtx := ranUe.GetSharedCtx()

	if amfUeNgapID != nil {
		if ranUeCtx.AmfUeNgapId == n3iwf_context.AmfUeNgapIdUnspecified {
			ngapLog.Tracef("Create new logical UE-associated NG-connection")
			ranUeCtx.AmfUeNgapId = amfUeNgapID.Value
		} else {
			if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
				ngapLog.Warn("AMFUENGAPID unmatched")
				return
			}
		}
	}

	if oldAMF != nil {
		ngapLog.Debugf("Old AMF: %s\n", oldAMF.Value)
	}

	if indexToRFSP != nil {
		ranUeCtx.IndexToRfsp = indexToRFSP.Value
	}

	if ueAggregateMaximumBitRate != nil {
		ranUeCtx.Ambr = ueAggregateMaximumBitRate
	}

	if allowedNSSAI != nil {
		ranUeCtx.AllowedNssai = allowedNSSAI
	}

	if nasPDU != nil {
		switch ue := ranUe.(type) {
		case *n3iwf_context.N3IWFRanUe:
			// Send EAP5G NAS to UE
			spi, ok := n3iwfCtx.IkeSpiLoad(ue.RanUeNgapId)
			if !ok {
				ngapLog.Errorf("Cannot get SPI from RanUeNGAPId : %+v", ue.RanUeNgapId)
				return
			}

			if !ue.IsNASTCPConnEstablished {
				s.SendIkeEvt(n3iwf_context.NewSendEAPNASMsgEvt(spi, []byte(nasPDU.Value)))
			} else {
				// Using a "NAS message envelope" to transport a NAS message
				// over the non-3GPP access between the UE and the N3IWF
				nasEnv := nas_security.EncapNasMsgToEnvelope([]byte(nasPDU.Value))

				if ue.IsNASTCPConnEstablishedComplete {
					// Send to UE
					if n, err := ue.TCPConnection.Write(nasEnv); err != nil {
						ngapLog.Errorf("Writing via IPSec signalling SA failed: %v", err)
					} else {
						ngapLog.Trace("Forward NWu <- N2")
						ngapLog.Tracef("Wrote %d bytes", n)
					}
				} else {
					ue.TemporaryCachedNASMessage = nasEnv
				}
			}
		default:
			ngapLog.Errorf("Unknown UE type: %T", ue)
		}
	}

	metricStatusOk = true
}

func (s *Server) HandlePDUSessionResourceSetupRequest(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.PDUSessionResourceSetupRequest,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle PDU Session Resource Setup Request")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.PDUSESSION_RESOURCE_SETUP_REQUEST, &metricStatusOk, cause)

	if amf == nil {
		ngapLog.Error("Corresponding AMF context not found")
		return
	}
	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	amfUeNgapID := pdu.AMFUENGAPID
	ranUeNgapID := pdu.RANUENGAPID
	nasPDU := pdu.NASPDU
	pduSessionResourceSetupListSUReq := pdu.PDUSessionResourceSetupListSUReq
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var pduSessionEstablishmentAccept *ngapType.NASPDU
	var ranUe n3iwf_context.RanUe
	var ranUeCtx *n3iwf_context.RanUeSharedCtx

	n3iwfCtx := s.Context()

	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDAMFUENGAPID, amfUeNgapID == nil},
		{ngapType.ProtocolIEIDRANUENGAPID, ranUeNgapID == nil},
		{ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq, pduSessionResourceSetupListSUReq == nil},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		// TODO: Send error indication to AMF
		ngapLog.Errorln("Sending error indication to AMF")
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			ngapLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
		if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if nasPDU != nil {
		n3iwfUe, ok := ranUe.(*n3iwf_context.N3IWFRanUe)
		if !ok {
			ngapLog.Errorln("HandlePDUSessionResourceSetupRequest(): [Type Assertion] RanUe -> N3iwfRanUe failed")
			return
		}
		if n3iwfUe.TCPConnection == nil {
			ngapLog.Error("No IPSec NAS signalling SA for this UE")
			return
		}

		// Using a "NAS message envelope" to transport a NAS message
		// over the non-3GPP access between the UE and the N3IWF
		nasEnv := nas_security.EncapNasMsgToEnvelope([]byte(nasPDU.Value))

		n, err := n3iwfUe.TCPConnection.Write(nasEnv)
		if err != nil {
			ngapLog.Errorf("Send NAS to UE failed: %v", err)
			return
		}
		ngapLog.Tracef("Wrote %d bytes", n)
	}

	tempPDUSessionSetupData := ranUeCtx.TemporaryPDUSessionSetupData
	tempPDUSessionSetupData.NGAPProcedureCode.Value = ngapMessage.ProcedureCodeInitialContextSetup

	if pduSessionResourceSetupListSUReq != nil {
		setupListSURes := new(ngapType.PDUSessionResourceSetupListSURes)
		failedListSURes := new(ngapType.PDUSessionResourceFailedToSetupListSURes)

		tempPDUSessionSetupData.SetupListSURes = setupListSURes
		tempPDUSessionSetupData.FailedListSURes = failedListSURes
		tempPDUSessionSetupData.Index = 0
		tempPDUSessionSetupData.UnactivatedPDUSession = nil
		tempPDUSessionSetupData.NGAPProcedureCode.Value = ngapMessage.ProcedureCodePDUSessionResourceSetup

		for _, item := range pduSessionResourceSetupListSUReq.List {
			pduSessionID := item.PDUSessionID.Value
			pduSessionEstablishmentAccept = item.PDUSessionNASPDU
			snssai := item.SNSSAI

			transfer := ngapType.PDUSessionResourceSetupRequestTransfer{}
			err := ngapType.UnmarshalBinary(*item.PDUSessionResourceSetupRequestTransfer, &transfer)
			if err != nil {
				ngapLog.Errorf("[PDUSessionID: %d] PDUSessionResourceSetupRequestTransfer Decode Error: %v\n",
					pduSessionID, err)
			}

			pduSession, err := ranUeCtx.CreatePDUSession(pduSessionID, *snssai)
			if err != nil {
				ngapLog.Errorf("Create PDU Session Error: %v\n", err)

				cause = message.BuildCause(message.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
				unsuccessfulTransfer, buildErr := message.
					BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					ngapLog.Errorf("Build PDUSessionResourceSetupUnsuccessfulTransfer Error: %v\n", buildErr)
				}
				message.AppendPDUSessionResourceFailedToSetupListSURes(
					failedListSURes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			// Process the message for AN
			success, resTransfer := s.handlePDUSessionResourceSetupRequestTransfer(
				ranUe, pduSession, transfer)
			if success {
				// Append this PDU session to unactivated PDU session list
				tempPDUSessionSetupData.UnactivatedPDUSession = append(
					tempPDUSessionSetupData.UnactivatedPDUSession,
					pduSession)
			} else {
				// Delete the pdusession store in UE conext
				delete(ranUeCtx.PduSessionList, pduSessionID)
				message.AppendPDUSessionResourceFailedToSetupListSURes(
					failedListSURes, pduSessionID, resTransfer)
			}
		}
	}

	if tempPDUSessionSetupData != nil && len(tempPDUSessionSetupData.UnactivatedPDUSession) != 0 {
		switch ue := ranUe.(type) {
		case *n3iwf_context.N3IWFRanUe:
			spi, ok := n3iwfCtx.IkeSpiLoad(ue.RanUeNgapId)
			if !ok {
				ngapLog.Errorf("Cannot get SPI from ranNgapID : %+v", ranUeNgapID)
				return
			}

			s.SendIkeEvt(n3iwf_context.NewCreatePDUSessionEvt(spi,
				len(ue.PduSessionList),
				ue.TemporaryPDUSessionSetupData),
			)

			// TS 23.501 4.12.5 Requested PDU Session Establishment via Untrusted non-3GPP Access
			// After all IPsec Child SAs are established, the N3IWF shall forward to UE via the signalling IPsec SA
			// the PDU Session Establishment Accept message
			nasEnv := nas_security.EncapNasMsgToEnvelope([]byte(pduSessionEstablishmentAccept.Value))

			// Cache the pduSessionEstablishmentAccept and forward to the UE after all CREATE_CHILD_SAs finish
			ue.TemporaryCachedNASMessage = nasEnv
		}
	}
	metricStatusOk = true
}

func (s *Server) HandlePDUSessionResourceModifyRequest(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.PDUSessionResourceModifyRequest,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle PDU Session Resource Modify Request")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.PDUSESSION_RESOURCE_MODIFY_REQUEST, &metricStatusOk, cause)

	if amf == nil {
		ngapLog.Error("Corresponding AMF context not found")
		return
	}
	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	amfUeNgapID := pdu.AMFUENGAPID
	ranUeNgapID := pdu.RANUENGAPID
	pduSessionResourceModifyListModReq := pdu.PDUSessionResourceModifyListModReq
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var ranUe n3iwf_context.RanUe
	var ranUeCtx *n3iwf_context.RanUeSharedCtx

	n3iwfCtx := s.Context()

	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDAMFUENGAPID, amfUeNgapID == nil},
		{ngapType.ProtocolIEIDRANUENGAPID, ranUeNgapID == nil},
		{ngapType.ProtocolIEIDPDUSessionResourceModifyListModReq, pduSessionResourceModifyListModReq == nil},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		message.SendPDUSessionResourceModifyResponse(nil, nil, nil, &criticalityDiagnostics)
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			ngapLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and send error indication
			// Cause: Unknown local UE NGAP ID
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
		if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and send error indication
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	responseList := new(ngapType.PDUSessionResourceModifyListModRes)
	failedListModRes := new(ngapType.PDUSessionResourceFailedToModifyListModRes)
	if pduSessionResourceModifyListModReq != nil {
		var pduSession *n3iwf_context.PDUSession
		for _, item := range pduSessionResourceModifyListModReq.List {
			pduSessionID := item.PDUSessionID.Value
			// TODO: send NAS to UE
			// pduSessionNasPdu := item.NASPDU
			transfer := ngapType.PDUSessionResourceModifyRequestTransfer{}
			err := ngapType.UnmarshalBinary(*item.PDUSessionResourceModifyRequestTransfer, &transfer)
			if err != nil {
				ngapLog.Errorf(
					"[PDUSessionID: %d] PDUSessionResourceModifyRequestTransfer Decode Error: %v\n",
					pduSessionID, err)
			}

			if pduSession = ranUeCtx.FindPDUSession(pduSessionID); pduSession == nil {
				ngapLog.Errorf("[PDUSessionID: %d] Unknown PDU session ID", pduSessionID)

				cause = message.BuildCause(message.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
				unsuccessfulTransfer, buildErr := message.
					BuildPDUSessionResourceModifyUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					ngapLog.Errorf("Build PDUSessionResourceModifyUnsuccessfulTransfer Error: %v\n", buildErr)
				}
				message.AppendPDUSessionResourceFailedToModifyListModRes(
					failedListModRes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := s.handlePDUSessionResourceModifyRequestTransfer(
				pduSession, transfer)
			if success {
				message.AppendPDUSessionResourceModifyListModRes(responseList, pduSessionID, resTransfer)
			} else {
				message.AppendPDUSessionResourceFailedToModifyListModRes(
					failedListModRes, pduSessionID, resTransfer)
			}
		}
	}

	message.SendPDUSessionResourceModifyResponse(ranUe, responseList, failedListModRes, nil)
	metricStatusOk = true
}

func (s *Server) handlePDUSessionResourceModifyRequestTransfer(
	pduSession *n3iwf_context.PDUSession,
	transfer ngapType.PDUSessionResourceModifyRequestTransfer,
) (
	success bool, responseTransfer []byte,
) {
	ngapLog := logger.NgapLog
	ngapLog.Trace("Handle PDU Session Resource Modify Request Transfer")

	var pduSessionAMBR *ngapType.PDUSessionAggregateMaximumBitRate
	var ulNGUUPTNLModifyList *ngapType.ULNGUUPTNLModifyList
	var networkInstance *ngapType.NetworkInstance
	var qosFlowAddOrModifyRequestList *ngapType.QosFlowAddOrModifyRequestList
	var qosFlowToReleaseList *ngapType.QosFlowListWithCause
	// var additionalULNGUUPTNLInformation *ngapType.UPTransportLayerInformation

	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	// used for building response transfer
	var resDLNGUUPTNLInfo *ngapType.UPTransportLayerInformation
	var resULNGUUPTNLInfo *ngapType.UPTransportLayerInformation
	var resQosFlowAddOrModifyRequestList ngapType.QosFlowAddOrModifyResponseList
	var resQosFlowFailedToAddOrModifyList ngapType.QosFlowListWithCause

	if transfer.ProtocolIEs != nil {
		for _, ie := range transfer.ProtocolIEs.List {
			if ie.PDUSessionAggregateMaximumBitRate != nil {
				pduSessionAMBR = ie.PDUSessionAggregateMaximumBitRate
			}
			if ie.ULNGUUPTNLModifyList != nil {
				ulNGUUPTNLModifyList = ie.ULNGUUPTNLModifyList
			}
			if ie.NetworkInstance != nil {
				networkInstance = ie.NetworkInstance
			}
			if ie.QosFlowAddOrModifyRequestList != nil {
				qosFlowAddOrModifyRequestList = ie.QosFlowAddOrModifyRequestList
			}
			if ie.QosFlowToReleaseList != nil {
				qosFlowToReleaseList = ie.QosFlowToReleaseList
			}
		}
	}
	for _, list := range []struct {
		id      int64
		invalid bool
	}{
		{
			ngapType.ProtocolIEIDULNGUUPTNLModifyList,
			ulNGUUPTNLModifyList != nil && len(ulNGUUPTNLModifyList.List) == 0,
		},
		{
			ngapType.ProtocolIEIDQosFlowAddOrModifyRequestList,
			qosFlowAddOrModifyRequestList != nil && len(qosFlowAddOrModifyRequestList.List) == 0,
		},
		{
			ngapType.ProtocolIEIDQosFlowToReleaseList,
			qosFlowToReleaseList != nil && len(qosFlowToReleaseList.List) == 0,
		},
	} {
		if list.invalid {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, list.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	if len(iesCriticalityDiagnostics.List) != 0 {
		// build unsuccessful transfer
		cause := message.BuildCause(message.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		unsuccessfulTransfer, err := message.BuildPDUSessionResourceModifyUnsuccessfulTransfer(
			*cause, &criticalityDiagnostics)
		if err != nil {
			ngapLog.Errorf("Build PDUSessionResourceModifyUnsuccessfulTransfer Error: %v\n", err)
		}

		responseTransfer = unsuccessfulTransfer
		return success, responseTransfer
	}

	if ulNGUUPTNLModifyList != nil {
		updateItem := ulNGUUPTNLModifyList.List[0]

		// TODO: update GTP tunnel

		ngapLog.Info("Update uplink NG-U user plane tunnel information")

		resULNGUUPTNLInfo = updateItem.ULNGUUPTNLInformation
		resDLNGUUPTNLInfo = updateItem.DLNGUUPTNLInformation
	}

	if qosFlowAddOrModifyRequestList != nil {
		for _, updateItem := range qosFlowAddOrModifyRequestList.List {
			target, ok := pduSession.QosFlows[updateItem.QosFlowIdentifier.Value]
			if ok {
				ngapLog.Trace("Update qos flow level qos parameters")

				target.Parameters = *updateItem.QosFlowLevelQosParameters

				item := ngapType.QosFlowAddOrModifyResponseItem{
					QosFlowIdentifier: updateItem.QosFlowIdentifier,
				}

				resQosFlowAddOrModifyRequestList.List = append(resQosFlowAddOrModifyRequestList.List, item)
			} else {
				ngapLog.Errorf("Requested Qos flow not found, QosFlowID: %d", updateItem.QosFlowIdentifier)

				cause := message.BuildCause(
					message.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnkownQosFlowID)

				item := ngapType.QosFlowWithCauseItem{
					QosFlowIdentifier: updateItem.QosFlowIdentifier,
					Cause:             cause,
				}

				resQosFlowFailedToAddOrModifyList.List = append(resQosFlowFailedToAddOrModifyList.List, item)
			}
		}
	}

	if pduSessionAMBR != nil {
		ngapLog.Trace("Store PDU session AMBR")
		pduSession.Ambr = pduSessionAMBR
	}

	if networkInstance != nil {
		// Used to select transport layer resource
		ngapLog.Trace("Store network instance")
		pduSession.NetworkInstance = networkInstance
	}

	if qosFlowToReleaseList != nil {
		for _, releaseItem := range qosFlowToReleaseList.List {
			_, ok := pduSession.QosFlows[releaseItem.QosFlowIdentifier.Value]
			if ok {
				ngapLog.Tracef("Delete QosFlow. ID: %d", releaseItem.QosFlowIdentifier.Value)
				printAndGetCause(releaseItem.Cause)
				delete(pduSession.QosFlows, releaseItem.QosFlowIdentifier.Value)
			}
		}
	}

	// if additionalULNGUUPTNLInformation != nil {
	// TODO: forward AdditionalULNGUUPTNLInfomation to S-NG-RAN
	// }

	encodeData, err := message.BuildPDUSessionResourceModifyResponseTransfer(
		resULNGUUPTNLInfo, resDLNGUUPTNLInfo, &resQosFlowAddOrModifyRequestList, &resQosFlowFailedToAddOrModifyList)
	if err != nil {
		ngapLog.Errorf("Build PDUSessionResourceModifyTransfer Error: %v\n", err)
	}

	success = true
	responseTransfer = encodeData

	return success, responseTransfer
}

func (s *Server) HandlePDUSessionResourceModifyConfirm(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.PDUSessionResourceModifyConfirm,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle PDU Session Resource Modify Confirm")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.PDUSESSION_RESOURCE_MODIFY_CONFIRM, &metricStatusOk, cause)

	aMFUENGAPID := pdu.AMFUENGAPID
	rANUENGAPID := pdu.RANUENGAPID
	pDUSessionResourceModifyListModCfm := pdu.PDUSessionResourceModifyListModCfm
	pDUSessionResourceFailedToModifyListModCfm := pdu.PDUSessionResourceFailedToModifyListModCfm
	criticalityDiagnostics := pdu.CriticalityDiagnostics
	// var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var ranUe n3iwf_context.RanUe
	var ranUeCtx *n3iwf_context.RanUeSharedCtx

	n3iwfCtx := s.Context()

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	if rANUENGAPID != nil {
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(rANUENGAPID.Value)
		if !ok {
			ngapLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
	}

	if aMFUENGAPID != nil {
		if ranUe != nil {
			if ranUeCtx.AmfUeNgapId != aMFUENGAPID.Value {
				ngapLog.Errorf("Inconsistent remote UE NGAP ID, AMFUENGAPID: %d, RanUe.AmfUeNgapId: %d",
					aMFUENGAPID.Value, ranUeCtx.AmfUeNgapId)
				return
			}
		} else {
			ranUe = amf.FindUeByAmfUeNgapID(aMFUENGAPID.Value)
			if ranUe == nil {
				ngapLog.Errorf("Inconsistent remote UE NGAP ID, AMFUENGAPID: %d",
					aMFUENGAPID.Value)
				return
			}
		}
	}

	if ranUe == nil {
		ngapLog.Warn("RANUENGAPID and  AMFUENGAPID are both nil")
		return
	}

	if pDUSessionResourceModifyListModCfm != nil {
		for _, item := range pDUSessionResourceModifyListModCfm.List {
			pduSessionId := item.PDUSessionID.Value
			ngapLog.Tracef("PDU Session Id[%d] in Pdu Session Resource Modification Confrim List", pduSessionId)
			sess, exist := ranUeCtx.PduSessionList[pduSessionId]
			if !exist {
				ngapLog.Warnf(
					"PDU Session Id[%d] is not exist in Ue[ranUeNgapId:%d]", pduSessionId, ranUeCtx.RanUeNgapId)
			} else {
				transfer := ngapType.PDUSessionResourceModifyConfirmTransfer{}
				err := ngapType.UnmarshalBinary(*item.PDUSessionResourceModifyConfirmTransfer, &transfer)
				if err != nil {
					ngapLog.Warnf(
						"[PDUSessionID: %d] PDUSessionResourceSetupRequestTransfer Decode Error: %v\n",
						pduSessionId, err)
				} else if transfer.QosFlowFailedToModifyList != nil {
					for _, flow := range transfer.QosFlowFailedToModifyList.List {
						ngapLog.Warnf(
							"Delete QFI[%d] due to Qos Flow Failure in Pdu Session Resource Modification Confrim List",
							flow.QosFlowIdentifier.Value)
						delete(sess.QosFlows, flow.QosFlowIdentifier.Value)
					}
				}
			}
		}
	}
	if pDUSessionResourceFailedToModifyListModCfm != nil {
		for _, item := range pDUSessionResourceFailedToModifyListModCfm.List {
			pduSessionId := item.PDUSessionID.Value
			transfer := ngapType.PDUSessionResourceModifyIndicationUnsuccessfulTransfer{}
			err := ngapType.UnmarshalBinary(
				*item.PDUSessionResourceModifyIndicationUnsuccessfulTransfer, &transfer)
			if err != nil {
				ngapLog.Warnf(
					"[PDUSessionID: %d] PDUSessionResourceModifyIndicationUnsuccessfulTransfer Decode Error: %v\n",
					pduSessionId, err)
			} else {
				printAndGetCause(transfer.Cause)
			}
			ngapLog.Tracef(
				"Release PDU Session Id[%d] due to PDU Session Resource Modify Indication Unsuccessful", pduSessionId)
			delete(ranUeCtx.PduSessionList, pduSessionId)
		}
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}

	metricStatusOk = true
}

func (s *Server) HandlePDUSessionResourceReleaseCommand(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.PDUSessionResourceReleaseCommand,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle PDU Session Resource Release Command")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.PDUSESSION_RESOURCE_RELEASE_COMMAND, &metricStatusOk, cause)

	aMFUENGAPID := pdu.AMFUENGAPID
	rANUENGAPID := pdu.RANUENGAPID
	// var rANPagingPriority *ngapType.RANPagingPriority
	// var nASPDU *ngapType.NASPDU
	pDUSessionResourceToReleaseListRelCmd := pdu.PDUSessionResourceToReleaseListRelCmd

	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfCtx := s.Context()

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDAMFUENGAPID, aMFUENGAPID == nil},
		{ngapType.ProtocolIEIDRANUENGAPID, rANUENGAPID == nil},
		{
			ngapType.ProtocolIEIDPDUSessionResourceToReleaseListRelCmd,
			pDUSessionResourceToReleaseListRelCmd == nil,
		},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		procudureCode := ngapMessage.ProcedureCodePDUSessionResourceRelease
		trigger := ngapType.TriggeringMessagePresentInitiatingMessage
		criticality := ngapType.CriticalityPresentReject
		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procudureCode, &trigger, &criticality, &iesCriticalityDiagnostics)
		message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	ranUe, ok := n3iwfCtx.RanUePoolLoad(rANUENGAPID.Value)
	if !ok {
		ngapLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
		cause = message.BuildCause(message.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)
		message.SendErrorIndication(amf, nil, nil, cause, nil)
		return
	}
	ranUeCtx := ranUe.GetSharedCtx()

	if ranUeCtx.AmfUeNgapId != aMFUENGAPID.Value {
		ngapLog.Errorf("Inconsistent remote UE NGAP ID, AMFUENGAPID: %d, RanUe.AmfUeNgapId: %d",
			aMFUENGAPID.Value, ranUeCtx.AmfUeNgapId)
		cause = message.BuildCause(message.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentInconsistentRemoteUENGAPID)
		message.SendErrorIndication(amf, nil, &rANUENGAPID.Value, cause, nil)
		return
	}

	// if rANPagingPriority != nil {
	// n3iwf does not support paging
	// }

	releaseList := ngapType.PDUSessionResourceReleasedListRelRes{}
	var releaseIdList []int64
	for _, item := range pDUSessionResourceToReleaseListRelCmd.List {
		pduSessionId := item.PDUSessionID.Value
		transfer := ngapType.PDUSessionResourceReleaseCommandTransfer{}
		err := ngapType.UnmarshalBinary(*item.PDUSessionResourceReleaseCommandTransfer, &transfer)
		if err != nil {
			ngapLog.Warnf(
				"[PDUSessionID: %d] PDUSessionResourceReleaseCommandTransfer Decode Error: %v\n",
				pduSessionId, err)
		} else {
			printAndGetCause(transfer.Cause)
		}
		ngapLog.Tracef("Release PDU Session Id[%d] due to PDU Session Resource Release Command", pduSessionId)
		delete(ranUeCtx.PduSessionList, pduSessionId)

		// response list
		releaseTransfer := aper.OctetString(getPDUSessionResourceReleaseResponseTransfer())
		releaseItem := ngapType.PDUSessionResourceReleasedItemRelRes{
			PDUSessionID: item.PDUSessionID,
			PDUSessionResourceReleaseResponseTransfer: &releaseTransfer,
		}
		releaseList.List = append(releaseList.List, releaseItem)

		releaseIdList = append(releaseIdList, pduSessionId)
	}

	localSPI, ok := n3iwfCtx.IkeSpiLoad(rANUENGAPID.Value)
	if !ok {
		ngapLog.Errorf("Cannot get SPI from RanUeNgapID : %+v", rANUENGAPID.Value)
		return
	}
	ranUe.GetSharedCtx().PduSessResRelState = n3iwf_context.PduSessResRelStateOngoing

	s.SendIkeEvt(n3iwf_context.NewSendChildSADeleteRequestEvt(localSPI, releaseIdList))

	ranUeCtx.PduSessionReleaseList = releaseList
	// if nASPDU != nil {
	// TODO: Send NAS to UE
	// }
	metricStatusOk = true
}

func (s *Server) HandleErrorIndication(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.ErrorIndication,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle Error Indication")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.ERROR_INDICATION, &metricStatusOk, cause)

	aMFUENGAPID := pdu.AMFUENGAPID
	rANUENGAPID := pdu.RANUENGAPID
	criticalityDiagnostics := pdu.CriticalityDiagnostics

	if amf == nil {
		ngapLog.Error("Corresponding AMF context not found")
		return
	}
	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}
	cause = pdu.Cause

	if cause == nil && criticalityDiagnostics == nil {
		ngapLog.Error("Both Cause IE and CriticalityDiagnostics IE are nil, should have at least one")
		return
	}

	if (aMFUENGAPID == nil) != (rANUENGAPID == nil) {
		ngapLog.Error("One of UE NGAP ID is not included in this message")
		return
	}

	if (aMFUENGAPID != nil) && (rANUENGAPID != nil) {
		ngapLog.Trace("UE-associated procedure error")
		ngapLog.Warnf("AMF UE NGAP ID is defined, value = %d", aMFUENGAPID.Value)
		ngapLog.Warnf("RAN UE NGAP ID is defined, value = %d", rANUENGAPID.Value)
	}

	if cause != nil {
		printAndGetCause(cause)
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(rANUENGAPID.Value)
	if ok {
		err := s.releaseIkeUeAndRanUe(ranUe)
		if err != nil {
			ngapLog.Warnf("HandleErrorIndication(): %v", err)
		}
	}

	ranUe = amf.FindUeByAmfUeNgapID(aMFUENGAPID.Value)
	if ranUe != nil {
		err := s.releaseIkeUeAndRanUe(ranUe)
		if err != nil {
			ngapLog.Warnf("HandleErrorIndication(): %v", err)
		}
	}

	metricStatusOk = true

	// TODO: handle error based on cause/criticalityDiagnostics
}

func (s *Server) HandleUERadioCapabilityCheckRequest(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.UERadioCapabilityCheckRequest,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle UE Radio Capability Check Request")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.UE_RADIO_CAPABILITY_CHECK_REQUEST, &metricStatusOk, cause)

	aMFUENGAPID := pdu.AMFUENGAPID
	rANUENGAPID := pdu.RANUENGAPID
	uERadioCapability := pdu.UERadioCapability
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfCtx := s.Context()

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	for _, mandatory := range []struct {
		id      int64
		missing bool
	}{
		{ngapType.ProtocolIEIDAMFUENGAPID, aMFUENGAPID == nil},
		{ngapType.ProtocolIEIDRANUENGAPID, rANUENGAPID == nil},
	} {
		if mandatory.missing {
			item := buildCriticalityDiagnosticsIEItem(
				ngapType.CriticalityPresentReject, mandatory.id, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		procudureCode := ngapMessage.ProcedureCodeUERadioCapabilityCheck
		trigger := ngapType.TriggeringMessagePresentInitiatingMessage
		criticality := ngapType.CriticalityPresentReject
		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procudureCode, &trigger, &criticality, &iesCriticalityDiagnostics)
		message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	ranUe, ok := n3iwfCtx.RanUePoolLoad(rANUENGAPID.Value)
	if !ok {
		ngapLog.Errorf("Unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
		cause = message.BuildCause(message.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)
		message.SendErrorIndication(amf, nil, nil, cause, nil)
		return
	}

	ranUe.GetSharedCtx().RadioCapability = uERadioCapability
	metricStatusOk = true
}

func (s *Server) HandleAMFConfigurationUpdate(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.AMFConfigurationUpdate,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle AMF Configuration Updaet")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.AMF_CONFIGURATION_UPDATE, &metricStatusOk, cause)

	aMFName := pdu.AMFName
	servedGUAMIList := pdu.ServedGUAMIList
	relativeAMFCapacity := pdu.RelativeAMFCapacity
	pLMNSupportList := pdu.PLMNSupportList
	aMFTNLAssociationToAddList := pdu.AMFTNLAssociationToAddList
	aMFTNLAssociationToRemoveList := pdu.AMFTNLAssociationToRemoveList
	aMFTNLAssociationToUpdateList := pdu.AMFTNLAssociationToUpdateList

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	if aMFName != nil {
		amf.AMFName = aMFName
	}
	if servedGUAMIList != nil {
		amf.ServedGUAMIList = servedGUAMIList
	}

	if relativeAMFCapacity != nil {
		amf.RelativeAMFCapacity = relativeAMFCapacity
	}

	if pLMNSupportList != nil {
		amf.PLMNSupportList = pLMNSupportList
	}

	successList := []ngapType.AMFTNLAssociationSetupItem{}
	if aMFTNLAssociationToAddList != nil {
		// TODO: Establish TNL Association with AMF
		for _, item := range aMFTNLAssociationToAddList.List {
			if item.AMFTNLAssociationAddress == nil {
				continue
			}
			tnlItem := amf.AddAMFTNLAssociationItem(*item.AMFTNLAssociationAddress)
			if tnlItem == nil {
				continue
			}
			tnlItem.TNLAddressWeightFactor = &item.TNLAddressWeightFactor.Value
			if item.TNLAssociationUsage != nil {
				tnlItem.TNLAssociationUsage = item.TNLAssociationUsage
			}
			setupItem := ngapType.AMFTNLAssociationSetupItem{
				AMFTNLAssociationAddress: item.AMFTNLAssociationAddress,
			}
			successList = append(successList, setupItem)
		}
	}
	if aMFTNLAssociationToRemoveList != nil {
		// TODO: Remove TNL Association with AMF
		for _, item := range aMFTNLAssociationToRemoveList.List {
			if item.AMFTNLAssociationAddress != nil {
				amf.DeleteAMFTNLAssociationItem(*item.AMFTNLAssociationAddress)
			}
		}
	}
	if aMFTNLAssociationToUpdateList != nil {
		// TODO: Update TNL Association with AMF
		for _, item := range aMFTNLAssociationToUpdateList.List {
			if item.AMFTNLAssociationAddress == nil {
				continue
			}
			tnlItem := amf.FindAMFTNLAssociationItem(*item.AMFTNLAssociationAddress)
			if tnlItem == nil {
				continue
			}
			if item.TNLAddressWeightFactor != nil {
				tnlItem.TNLAddressWeightFactor = &item.TNLAddressWeightFactor.Value
			}
			if item.TNLAssociationUsage != nil {
				tnlItem.TNLAssociationUsage = item.TNLAssociationUsage
			}
		}
	}

	var setupList *ngapType.AMFTNLAssociationSetupList
	if len(successList) > 0 {
		setupList = &ngapType.AMFTNLAssociationSetupList{
			List: successList,
		}
	}
	message.SendAMFConfigurationUpdateAcknowledge(amf, setupList, nil, nil)

	metricStatusOk = true
}

func (s *Server) HandleRANConfigurationUpdateAcknowledge(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.RANConfigurationUpdateAcknowledge,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle RAN Configuration Update Acknowledge")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.RAN_CONFIGURATION_UPDATE_ACKNOWLEDGE, &metricStatusOk, cause)

	criticalityDiagnostics := pdu.CriticalityDiagnostics

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}

	metricStatusOk = true
}

func (s *Server) HandleRANConfigurationUpdateFailure(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.RANConfigurationUpdateFailure,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle RAN Configuration Update Failure")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.RAN_CONFIGURATION_UPDATE_FAILURE, &metricStatusOk, cause)

	cause = pdu.Cause
	timeToWait := pdu.TimeToWait
	criticalityDiagnostics := pdu.CriticalityDiagnostics

	n3iwfCtx := s.Context()

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	if cause != nil {
		printAndGetCause(cause)
	}

	printCriticalityDiagnostics(criticalityDiagnostics)

	var waitingTime int

	if timeToWait != nil {
		switch timeToWait.Value {
		case ngapType.TimeToWaitPresentV1s:
			waitingTime = 1
		case ngapType.TimeToWaitPresentV2s:
			waitingTime = 2
		case ngapType.TimeToWaitPresentV5s:
			waitingTime = 5
		case ngapType.TimeToWaitPresentV10s:
			waitingTime = 10
		case ngapType.TimeToWaitPresentV20s:
			waitingTime = 20
		case ngapType.TimeToWaitPresentV60s:
			waitingTime = 60
		}
	}

	if waitingTime != 0 {
		ngapLog.Infof("Wait at lease  %ds to resend RAN Configuration Update to same AMF[%s]",
			waitingTime, amf.SCTPAddr)
		n3iwfCtx.AMFReInitAvailableListStore(amf.SCTPAddr, false)
		time.AfterFunc(time.Duration(waitingTime)*time.Second, func() {
			ngapLog.Infof("Re-send Ran Configuration Update Message when waiting time expired")
			n3iwfCtx.AMFReInitAvailableListStore(amf.SCTPAddr, true)
			message.SendRANConfigurationUpdate(n3iwfCtx, amf)
		})
		return
	}
	message.SendRANConfigurationUpdate(n3iwfCtx, amf)
	metricStatusOk = true
}

func (s *Server) HandleDownlinkRANConfigurationTransfer(
	pdu *ngapMessage.DownlinkRANConfigurationTransfer,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle Downlink RAN Configuration Transfer")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.DOWNLINK_RAN_CONFIGURATION_TRANSFER, &metricStatusOk, cause)

	metricStatusOk = true
}

func (s *Server) HandleDownlinkRANStatusTransfer(
	pdu *ngapMessage.DownlinkRANStatusTransfer,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle Downlink RAN Status Transfer")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.DOWNLINK_RAN_STATUS_TRANSFER, &metricStatusOk, cause)

	metricStatusOk = true
}

func (s *Server) HandleAMFStatusIndication(
	pdu *ngapMessage.AMFStatusIndication,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle AMF Status Indication")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.AMF_STATUS_INDICATION, &metricStatusOk, cause)

	metricStatusOk = true
}

func (s *Server) HandleLocationReportingControl(
	pdu *ngapMessage.LocationReportingControl,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle Location Reporting Control")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.LOCATION_REPORTING_CONTROL, &metricStatusOk, cause)

	metricStatusOk = true
}

func (s *Server) HandleUETNLAReleaseRequest(
	pdu *ngapMessage.UETNLABindingReleaseRequest,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle UE TNLA Release Request")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.UE_TNLA_BINDING_RELEASE_REQUEST, &metricStatusOk, cause)

	metricStatusOk = true
}

func (s *Server) HandleOverloadStart(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.OverloadStart,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle Overload Start")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.OVERLOAD_START, &metricStatusOk, cause)

	aMFOverloadResponse := pdu.AMFOverloadResponse
	aMFTrafficLoadReductionIndication := pdu.AMFTrafficLoadReductionIndication
	overloadStartNSSAIList := pdu.OverloadStartNSSAIList

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}

	if pdu == nil {
		ngapLog.Error("NGAP Message is nil")
		return
	}

	// TODO: restrict rule about overload action
	amf.StartOverload(aMFOverloadResponse, aMFTrafficLoadReductionIndication, overloadStartNSSAIList)
	metricStatusOk = true
}

func (s *Server) HandleOverloadStop(
	amf *n3iwf_context.N3IWFAMF,
	pdu *ngapMessage.OverloadStop,
) {
	ngapLog := logger.NgapLog
	ngapLog.Infoln("Handle Overload Stop")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.OVERLOAD_STOP, &metricStatusOk, cause)

	if amf == nil {
		ngapLog.Error("AMF Context is nil")
		return
	}
	// TODO: remove restrict about overload action
	amf.StopOverload()
	metricStatusOk = true
}

func buildCriticalityDiagnostics(
	procedureCode *int64,
	triggeringMessage *aper.Enumerated,
	procedureCriticality *aper.Enumerated,
	iesCriticalityDiagnostics *ngapType.CriticalityDiagnosticsIEList,
) (
	criticalityDiagnostics ngapType.CriticalityDiagnostics,
) {
	if procedureCode != nil {
		criticalityDiagnostics.ProcedureCode = new(ngapType.ProcedureCode)
		criticalityDiagnostics.ProcedureCode.Value = *procedureCode
	}

	if triggeringMessage != nil {
		criticalityDiagnostics.TriggeringMessage = new(ngapType.TriggeringMessage)
		criticalityDiagnostics.TriggeringMessage.Value = *triggeringMessage
	}

	if procedureCriticality != nil {
		criticalityDiagnostics.ProcedureCriticality = new(ngapType.Criticality)
		criticalityDiagnostics.ProcedureCriticality.Value = *procedureCriticality
	}

	if iesCriticalityDiagnostics != nil {
		criticalityDiagnostics.IEsCriticalityDiagnostics = iesCriticalityDiagnostics
	}

	return criticalityDiagnostics
}

func buildCriticalityDiagnosticsIEItem(
	ieCriticality aper.Enumerated,
	ieID int64,
	typeOfErr aper.Enumerated,
) (
	item ngapType.CriticalityDiagnosticsIEItem,
) {
	item = ngapType.CriticalityDiagnosticsIEItem{
		IECriticality: &ngapType.Criticality{
			Value: ieCriticality,
		},
		IEID: &ngapType.ProtocolIEID{
			Value: ieID,
		},
		TypeOfError: &ngapType.TypeOfError{
			Value: typeOfErr,
		},
	}

	return item
}

func printAndGetCause(
	cause *ngapType.Cause,
) (
	present int, value aper.Enumerated,
) {
	ngapLog := logger.NgapLog
	if cause == nil {
		return message.CausePresentNothing, 0
	}
	switch choice := cause.Choice.(type) {
	case *ngapType.CauseRadioNetwork:
		present, value = message.CausePresentRadioNetwork, choice.Value
		ngapLog.Warnf("Cause RadioNetwork[%d]", value)
	case *ngapType.CauseTransport:
		present, value = message.CausePresentTransport, choice.Value
		ngapLog.Warnf("Cause Transport[%d]", value)
	case *ngapType.CauseProtocol:
		present, value = message.CausePresentProtocol, choice.Value
		ngapLog.Warnf("Cause Protocol[%d]", value)
	case *ngapType.CauseNas:
		present, value = message.CausePresentNas, choice.Value
		ngapLog.Warnf("Cause Nas[%d]", value)
	case *ngapType.CauseMisc:
		present, value = message.CausePresentMisc, choice.Value
		ngapLog.Warnf("Cause Misc[%d]", value)
	default:
		present = message.CausePresentNothing
		ngapLog.Errorf("Invalid Cause choice %T", cause.Choice)
	}
	return
}

func printCriticalityDiagnostics(
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	ngapLog := logger.NgapLog
	if criticalityDiagnostics == nil {
		return
	} else {
		iesCriticalityDiagnostics := criticalityDiagnostics.IEsCriticalityDiagnostics
		if iesCriticalityDiagnostics != nil {
			for index, item := range iesCriticalityDiagnostics.List {
				ngapLog.Warnf("Criticality IE item %d:", index+1)
				if item.IEID == nil || item.IECriticality == nil || item.TypeOfError == nil {
					ngapLog.Warn("Incomplete criticality diagnostics item")
					continue
				}
				ngapLog.Warnf("IE ID: %d", item.IEID.Value)

				switch item.IECriticality.Value {
				case ngapType.CriticalityPresentReject:
					ngapLog.Warn("IE Criticality: Reject")
				case ngapType.CriticalityPresentIgnore:
					ngapLog.Warn("IE Criticality: Ignore")
				case ngapType.CriticalityPresentNotify:
					ngapLog.Warn("IE Criticality: Notify")
				}

				switch item.TypeOfError.Value {
				case ngapType.TypeOfErrorPresentNotUnderstood:
					ngapLog.Warn("Type of error: Not Understood")
				case ngapType.TypeOfErrorPresentMissing:
					ngapLog.Warn("Type of error: Missing")
				}
			}
		} else {
			ngapLog.Debug("IEsCriticalityDiagnostics is nil")
		}
		return
	}
}

func getPDUSessionResourceReleaseResponseTransfer() []byte {
	ngapLog := logger.NgapLog
	data := ngapType.PDUSessionResourceReleaseResponseTransfer{}
	encodeData, err := ngapType.MarshalBinary(&data)
	if err != nil {
		ngapLog.Errorf("NGAP IE marshal error in getPDUSessionResourceReleaseResponseTransfer: %v", err)
	}
	return encodeData
}

func (s *Server) HandleEvent(ngapEvent n3iwf_context.NgapEvt) {
	ngapLog := logger.NgapLog
	ngapLog.Infof("NGAP event handle")

	switch ngapEvent.Type() {
	case n3iwf_context.UnmarshalEAP5GData:
		s.HandleUnmarshalEAP5GData(ngapEvent)
	case n3iwf_context.SendInitialUEMessage:
		s.HandleSendInitialUEMessage(ngapEvent)
	case n3iwf_context.SendPDUSessionResourceSetupResponse:
		s.HandleSendPDUSessionResourceSetupResponse(ngapEvent)
	case n3iwf_context.SendNASMsg:
		s.HandleSendNASMsg(ngapEvent)
	case n3iwf_context.StartTCPSignalNASMsg:
		s.HandleStartTCPSignalNASMsg(ngapEvent)
	case n3iwf_context.NASTCPConnEstablishedComplete:
		s.HandleNASTCPConnEstablishedComplete(ngapEvent)
	case n3iwf_context.SendUEContextRelease:
		s.HandleSendSendUEContextRelease(ngapEvent)
	case n3iwf_context.SendUEContextReleaseRequest:
		s.HandleSendUEContextReleaseRequest(ngapEvent)
	case n3iwf_context.SendUEContextReleaseComplete:
		s.HandleSendUEContextReleaseComplete(ngapEvent)
	case n3iwf_context.SendPDUSessionResourceRelease:
		s.HandleSendSendPDUSessionResourceRelease(ngapEvent)
	case n3iwf_context.SendPDUSessionResourceReleaseResponse:
		s.HandleSendPDUSessionResourceReleaseRes(ngapEvent)
	case n3iwf_context.GetNGAPContext:
		s.HandleGetNGAPContext(ngapEvent)
	case n3iwf_context.SendUplinkNASTransport:
		s.HandleSendUplinkNASTransport(ngapEvent)
	case n3iwf_context.SendInitialContextSetupResponse:
		s.HandleSendInitialContextSetupResponse(ngapEvent)
	default:
		ngapLog.Errorf("Undefine NGAP event type")
		return
	}
}

func (s *Server) HandleGetNGAPContext(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle HandleGetNGAPContext Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg("GetNGAPContext", &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.GetNGAPContextEvt)
	ranUeNgapId := evt.RanUeNgapId
	ngapCxtReqNumlist := evt.NgapCxtReqNumlist

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	var ngapCxt []interface{}

	for _, num := range ngapCxtReqNumlist {
		switch num {
		case n3iwf_context.CxtTempPDUSessionSetupData:
			ngapCxt = append(ngapCxt, ranUe.GetSharedCtx().TemporaryPDUSessionSetupData)
		default:
			ngapLog.Errorf("Receive undefine NGAP Context Request number : %d", num)
		}
	}

	spi, ok := n3iwfCtx.IkeSpiLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get spi from ngapid : %+v", ranUeNgapId)
		return
	}

	s.SendIkeEvt(n3iwf_context.NewGetNGAPContextRepEvt(spi, ngapCxtReqNumlist, ngapCxt))

	metricStatusOk = true
}

func (s *Server) HandleUnmarshalEAP5GData(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle UnmarshalEAP5GData Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg("UnmarchalEAP5GData", &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.UnmarshalEAP5GDataEvt)
	spi := evt.LocalSPI
	eapVendorData := evt.EAPVendorData
	isInitialUE := evt.IsInitialUE

	n3iwfCtx := s.Context()

	anParameters, nasPDU, err := UnmarshalEAP5GData(eapVendorData)
	if err != nil {
		ngapLog.Errorf("Unmarshalling EAP-5G packet failed: %v", err)
		return
	}

	if !isInitialUE { // ikeSA.ikeUE == nil
		// TS 23.502 4.12.2 step5 EAP-Response/5G-NAS packet must contain AN-parameters
		if anParameters == nil {
			ngapLog.Error("Received EAP-5G packet with missing or zero-length AN-parameters in initial UE message")
			return
		}

		ngapLog.Debug("Select AMF with the following AN parameters:")
		if anParameters.GUAMI == nil {
			ngapLog.Debug("\tGUAMI: nil")
		} else {
			ngapLog.Debugf("\tGUAMI: PLMNIdentity[% x], "+
				"AMFRegionID[% x], AMFSetID[% x], AMFPointer[% x]",
				anParameters.GUAMI.PLMNIdentity, anParameters.GUAMI.AMFRegionID,
				anParameters.GUAMI.AMFSetID, anParameters.GUAMI.AMFPointer)
		}
		if anParameters.SelectedPLMNID == nil {
			ngapLog.Debug("\tSelectedPLMNID: nil")
		} else {
			ngapLog.Debugf("\tSelectedPLMNID: % v", anParameters.SelectedPLMNID.Value)
		}
		if anParameters.RequestedNSSAI == nil {
			ngapLog.Debug("\tRequestedNSSAI: nil")
		} else {
			ngapLog.Debugf("\tRequestedNSSAI:")
			for i := 0; i < len(anParameters.RequestedNSSAI.List); i++ {
				ngapLog.Debugf("\tRequestedNSSAI:")
				ngapLog.Debugf("\t\tSNSSAI %d:", i+1)
				ngapLog.Debugf("\t\t\tSST: % x", anParameters.RequestedNSSAI.List[i].SNSSAI.SST.Value)
				sd := anParameters.RequestedNSSAI.List[i].SNSSAI.SD
				if sd == nil {
					ngapLog.Debugf("\t\t\tSD: nil")
				} else {
					ngapLog.Debugf("\t\t\tSD: % x", sd.Value)
				}
			}
		}

		selectedAMF := n3iwfCtx.AMFSelection(anParameters.GUAMI, anParameters.SelectedPLMNID)
		if selectedAMF == nil {
			s.SendIkeEvt(n3iwf_context.NewSendEAP5GFailureMsgEvt(spi, n3iwf_context.ErrAMFSelection))
		} else {
			n3iwfUe := n3iwfCtx.NewN3iwfRanUe()
			n3iwfUe.AMF = selectedAMF
			if anParameters.EstablishmentCause != nil {
				value := uint64(anParameters.EstablishmentCause.Value)
				if value > uint64(math.MaxInt16) {
					ngapLog.Errorf("HandleUnmarshalEAP5GData() anParameters.EstablishmentCause.Value "+
						"exceeds int16: %+v", value)
					return
				} else {
					n3iwfUe.RRCEstablishmentCause = int16(value)
				}
			}

			s.SendIkeEvt(n3iwf_context.NewUnmarshalEAP5GDataResponseEvt(spi, n3iwfUe.RanUeNgapId, nasPDU))
		}
	} else {
		ranUeNgapId := evt.RanUeNgapId
		ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
		if !ok {
			ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
			return
		}
		message.SendUplinkNASTransport(ranUe, nasPDU)
	}
	metricStatusOk = true
}

func (s *Server) HandleSendInitialUEMessage(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendInitialUEMessage Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.INITIAL_UE_MESSAGE, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendInitialUEMessageEvt)
	ranUeNgapId := evt.RanUeNgapId
	ipv4Addr := evt.IPv4Addr
	ipv4Port := evt.IPv4Port
	nasPDU := evt.NasPDU

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}
	ranUeCtx := ranUe.GetSharedCtx()

	ranUeCtx.IPAddrv4 = ipv4Addr
	ranUeCtx.PortNumber = int32(ipv4Port) // #nosec G115
	message.SendInitialUEMessage(ranUeCtx.AMF, ranUe, nasPDU)
	metricStatusOk = true
}

func (s *Server) HandleSendPDUSessionResourceSetupResponse(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendPDUSessionResourceSetupResponse Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.PDUSESSION_RESOURCE_SETUP_RESPONSE, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendPDUSessionResourceSetupResEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}
	ranUeCtx := ranUe.GetSharedCtx()

	temporaryPDUSessionSetupData := ranUeCtx.TemporaryPDUSessionSetupData

	if len(temporaryPDUSessionSetupData.UnactivatedPDUSession) != 0 {
		for index, pduSession := range temporaryPDUSessionSetupData.UnactivatedPDUSession {
			errStr := temporaryPDUSessionSetupData.FailedErrStr[index]
			if errStr != n3iwf_context.ErrNil {
				switch errStr {
				case n3iwf_context.ErrTransportResourceUnavailable:
					cause = message.BuildCause(message.CausePresentTransport,
						ngapType.CauseTransportPresentTransportResourceUnavailable)
				default:
					ngapLog.Errorf("Undefine event error string : %+s", errStr.Error())
					return
				}

				transfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					ngapLog.Errorf("Build PDU Session Resource Setup Unsuccessful Transfer Failed: %v", err)
					continue
				}

				if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapMessage.ProcedureCodeInitialContextSetup {
					message.AppendPDUSessionResourceFailedToSetupListCxtRes(
						temporaryPDUSessionSetupData.FailedListCxtRes, pduSession.Id, transfer)
				} else {
					message.AppendPDUSessionResourceFailedToSetupListSURes(
						temporaryPDUSessionSetupData.FailedListSURes, pduSession.Id, transfer)
				}
			} else {
				var gtpAddr string
				switch ranUe.(type) {
				case *n3iwf_context.N3IWFRanUe:
					gtpAddr = s.Config().GetN3iwfGtpBindAddress()
				}

				// Append NGAP PDU session resource setup response transfer
				transfer, err := message.BuildPDUSessionResourceSetupResponseTransfer(
					pduSession, gtpAddr)
				if err != nil {
					ngapLog.Errorf("Build PDU session resource setup response transfer failed: %v", err)
					return
				}
				if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapMessage.ProcedureCodeInitialContextSetup {
					message.AppendPDUSessionResourceSetupListCxtRes(
						temporaryPDUSessionSetupData.SetupListCxtRes, pduSession.Id, transfer)
				} else {
					message.AppendPDUSessionResourceSetupListSURes(
						temporaryPDUSessionSetupData.SetupListSURes, pduSession.Id, transfer)
				}
			}
		}

		if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapMessage.ProcedureCodeInitialContextSetup {
			message.SendInitialContextSetupResponse(ranUe,
				temporaryPDUSessionSetupData.SetupListCxtRes,
				temporaryPDUSessionSetupData.FailedListCxtRes, nil)
		} else {
			message.SendPDUSessionResourceSetupResponse(ranUe,
				temporaryPDUSessionSetupData.SetupListSURes,
				temporaryPDUSessionSetupData.FailedListSURes, nil)
		}
	} else {
		message.SendInitialContextSetupResponse(ranUe, nil, nil, nil)
	}

	metricStatusOk = true
}

func (s *Server) HandleSendNASMsg(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendNASMsg Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg("SendNASMsg", &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendNASMsgEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	n3iwfUe, ok := ranUe.(*n3iwf_context.N3IWFRanUe)
	if !ok {
		ngapLog.Errorln("HandleSendNASMsg(): [Type Assertion] RanUe -> N3iwfUe failed")
		return
	}

	if n, ikeErr := n3iwfUe.TCPConnection.Write(n3iwfUe.TemporaryCachedNASMessage); ikeErr != nil {
		ngapLog.Errorf("Writing via IPSec signalling SA failed: %v", ikeErr)
	} else {
		ngapLog.Tracef("Forward PDU Seesion Establishment Accept to UE. Wrote %d bytes", n)
		n3iwfUe.TemporaryCachedNASMessage = nil
	}

	metricStatusOk = true
}

func (s *Server) HandleStartTCPSignalNASMsg(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle StartTCPSignalNASMsg Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg("StartTCPSignalNASMsg", &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.StartTCPSignalNASMsgEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	n3iwfUe, ok := ranUe.(*n3iwf_context.N3IWFRanUe)
	if !ok {
		ngapLog.Errorln("HandleStartTCPSignalNASMsg(): [Type Assertion] RanUe -> N3iwfUe failed")
		return
	}

	n3iwfUe.IsNASTCPConnEstablished = true

	metricStatusOk = true
}

func (s *Server) HandleNASTCPConnEstablishedComplete(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle NASTCPConnEstablishedComplete Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg("NASTCPConnEstablishedComplete", &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.NASTCPConnEstablishedCompleteEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}
	n3iwfUe, ok := ranUe.(*n3iwf_context.N3IWFRanUe)
	if !ok {
		ngapLog.Errorln("HandleNASTCPConnEstablishedComplete(): [Type Assertion] RanUe -> N3iwfUe failed")
		return
	}

	n3iwfUe.IsNASTCPConnEstablishedComplete = true

	if n3iwfUe.TemporaryCachedNASMessage != nil {
		// Send to UE
		if n, err := n3iwfUe.TCPConnection.Write(n3iwfUe.TemporaryCachedNASMessage); err != nil {
			ngapLog.Errorf("Writing via IPSec signalling SA failed: %v", err)
		} else {
			ngapLog.Trace("Forward NWu <- N2")
			ngapLog.Tracef("Wrote %d bytes", n)
		}
		n3iwfUe.TemporaryCachedNASMessage = nil
	}
	metricStatusOk = true
}

func (s *Server) HandleSendUEContextReleaseRequest(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendUEContextReleaseRequest Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.UE_CONTEXT_RELEASE_REQUEST, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendUEContextReleaseRequestEvt)

	ranUeNgapId := evt.RanUeNgapId
	errMsg := evt.ErrMsg

	switch errMsg {
	case n3iwf_context.ErrRadioConnWithUeLost:
		cause = message.BuildCause(message.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentRadioConnectionWithUeLost)
	case n3iwf_context.ErrNil:
	default:
		ngapLog.Errorf("Undefine event error string : %+s", errMsg.Error())
		return
	}

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	message.SendUEContextReleaseRequest(ranUe, *cause)
	metricStatusOk = true
}

func (s *Server) HandleSendUEContextReleaseComplete(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendUEContextReleaseComplete Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.UE_CONTEXT_RELEASE_COMPLETE, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendUEContextReleaseCompleteEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	if err := ranUe.Remove(); err != nil {
		ngapLog.Errorf("Delete RanUe Context error : %v", err)
	}
	message.SendUEContextReleaseComplete(ranUe, nil)

	metricStatusOk = true
}

func (s *Server) HandleSendPDUSessionResourceReleaseRes(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendPDUSessionResourceReleaseResponse Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.PDUSESSION_RESOURCE_RELEASE_RESPONSE, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendPDUSessionResourceReleaseResEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	message.SendPDUSessionResourceReleaseResponse(ranUe, ranUe.GetSharedCtx().PduSessionReleaseList, nil)

	metricStatusOk = true
}

func (s *Server) HandleSendUplinkNASTransport(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendUplinkNASTransport Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.UPLINK_NAS_TRANSPORT, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendUplinkNASTransportEvt)
	ranUeNgapId := evt.RanUeNgapId
	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	message.SendUplinkNASTransport(ranUe, evt.Pdu)

	metricStatusOk = true
}

func (s *Server) HandleSendInitialContextSetupResponse(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendInitialContextSetupResponse Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.INITIAL_CONTEXT_SETUP_RESPONSE, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendInitialContextSetupRespEvt)
	ranUeNgapId := evt.RanUeNgapId
	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	message.SendInitialContextSetupResponse(ranUe, evt.ResponseList, evt.FailedList, evt.CriticalityDiagnostics)

	metricStatusOk = true
}

func (s *Server) HandleSendSendUEContextRelease(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendSendUEContextRelease Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.UE_CONTEXT_RELEASE_REQUEST, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendUEContextReleaseEvt)
	ranUeNgapId := evt.RanUeNgapId
	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	if ranUe.GetSharedCtx().UeCtxRelState {
		if err := ranUe.Remove(); err != nil {
			ngapLog.Errorf("Delete RanUe Context error : %v", err)
		}
		message.SendUEContextReleaseComplete(ranUe, nil)
		ranUe.GetSharedCtx().UeCtxRelState = n3iwf_context.UeCtxRelStateNone
	} else {
		cause = message.BuildCause(message.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentRadioConnectionWithUeLost)
		message.SendUEContextReleaseRequest(ranUe, *cause)
		ranUe.GetSharedCtx().UeCtxRelState = n3iwf_context.UeCtxRelStateOngoing
	}

	metricStatusOk = true
}

func (s *Server) HandleSendSendPDUSessionResourceRelease(
	ngapEvent n3iwf_context.NgapEvt,
) {
	ngapLog := logger.NgapLog
	ngapLog.Tracef("Handle SendSendPDUSessionResourceRelease Event")

	var cause *ngapType.Cause
	metricStatusOk := false
	defer ngap_metrics.IncrMetricsRcvMsg(ngap_metrics.PDUSESSION_RESOURCE_RELEASE_RESPONSE, &metricStatusOk, cause)

	evt := ngapEvent.(*n3iwf_context.SendPDUSessionResourceReleaseEvt)
	ranUeNgapId := evt.RanUeNgapId
	deletPduIds := evt.DeletPduIds
	n3iwfCtx := s.Context()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		ngapLog.Errorf("Cannot get RanUE from ranUeNgapId : %+v", ranUeNgapId)
		return
	}

	if ranUe.GetSharedCtx().PduSessResRelState {
		message.SendPDUSessionResourceReleaseResponse(ranUe, ranUe.GetSharedCtx().PduSessionReleaseList, nil)
		ranUe.GetSharedCtx().PduSessResRelState = n3iwf_context.PduSessResRelStateNone
	} else {
		for _, id := range deletPduIds {
			ranUe.GetSharedCtx().DeletePDUSession(id)
		}
		ranUe.GetSharedCtx().PduSessResRelState = n3iwf_context.PduSessResRelStateOngoing
	}

	metricStatusOk = true
}
