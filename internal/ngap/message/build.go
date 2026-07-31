package message

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/pkg/errors"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/internal/util"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngap "github.com/free5gc/ngap/message"
)

const (
	CausePresentRadioNetwork = iota
	CausePresentTransport
	CausePresentNas
	CausePresentProtocol
	CausePresentMisc
	CausePresentChoiceExtensions
	CausePresentNothing
)

func ueIDs(ranUe n3iwf_context.RanUe) (*ngapType.AMFUENGAPID, *ngapType.RANUENGAPID) {
	ctx := ranUe.GetSharedCtx()
	return &ngapType.AMFUENGAPID{Value: ctx.AmfUeNgapId},
		&ngapType.RANUENGAPID{Value: ctx.RanUeNgapId}
}

func buildSupportedTAList(items []factory.SupportedTAItem) *ngapType.SupportedTAList {
	result := &ngapType.SupportedTAList{}
	for _, configuredTA := range items {
		tac, err := hex.DecodeString(configuredTA.TAC)
		if err != nil {
			logger.NgapLog.Errorf("TAC[%s] DecodeString error: %v", configuredTA.TAC, err)
		}
		item := ngapType.SupportedTAItem{
			TAC:               &ngapType.TAC{Value: tac},
			BroadcastPLMNList: &ngapType.BroadcastPLMNList{},
		}
		for _, configuredPLMN := range configuredTA.BroadcastPLMNList {
			plmn := util.PlmnIdToNgap(*configuredPLMN.PLMNID)
			broadcast := ngapType.BroadcastPLMNItem{
				PLMNIdentity:        &plmn,
				TAISliceSupportList: &ngapType.SliceSupportList{},
			}
			for _, configuredSlice := range configuredPLMN.TAISliceSupportList {
				snssai := &ngapType.SNSSAI{
					SST: &ngapType.SST{Value: aper.OctetString{byte(configuredSlice.SNSSAI.SST)}},
				}
				if configuredSlice.SNSSAI.SD != "" {
					sd, decodeErr := hex.DecodeString(configuredSlice.SNSSAI.SD)
					if decodeErr != nil {
						logger.NgapLog.Errorf("SD[%s] DecodeString error: %v",
							configuredSlice.SNSSAI.SD, decodeErr)
					}
					snssai.SD = &ngapType.SD{Value: sd}
				}
				broadcast.TAISliceSupportList.List = append(
					broadcast.TAISliceSupportList.List,
					ngapType.SliceSupportItem{SNSSAI: snssai},
				)
			}
			item.BroadcastPLMNList.List = append(item.BroadcastPLMNList.List, broadcast)
		}
		result.List = append(result.List, item)
	}
	return result
}

func BuildNGSetupRequest(
	gN3iwfID *factory.GlobalN3IWFID,
	ranNodeName string,
	suppTAList []factory.SupportedTAItem,
) ([]byte, error) {
	plmn := util.PlmnIdToNgap(*gN3iwfID.PLMNID)
	n3iwfID := util.N3iwfIdToNgap(gN3iwfID.N3IWFID)
	msg := &ngap.NGSetupRequest{
		GlobalRANNodeID: &ngapType.GlobalRANNodeID{
			Choice: &ngapType.GlobalN3IWFID{
				PLMNIdentity: &plmn,
				N3IWFID: &ngapType.N3IWFID{
					Choice: &ngapType.N3IWFIDForN3IWFID{Value: *n3iwfID},
				},
			},
		},
		RANNodeName:      &ngapType.RANNodeName{Value: aper.PrintableString(ranNodeName)},
		SupportedTAList:  buildSupportedTAList(suppTAList),
		DefaultPagingDRX: &ngapType.PagingDRX{Value: ngapType.PagingDRXPresentV128},
	}
	return msg.MarshalBinary()
}

func BuildNGReset(
	ngCause ngapType.Cause,
	partOfNGInterface *ngapType.UEAssociatedLogicalNGConnectionList,
) ([]byte, error) {
	resetType := &ngapType.ResetType{}
	if partOfNGInterface == nil {
		resetType.Choice = &ngapType.ResetAll{Value: ngapType.ResetAllPresentResetAll}
	} else {
		resetType.Choice = partOfNGInterface
	}
	return (&ngap.NGReset{Cause: &ngCause, ResetType: resetType}).MarshalBinary()
}

func BuildNGResetAcknowledge(
	partOfNGInterface *ngapType.UEAssociatedLogicalNGConnectionList,
	diagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngap.NGResetAcknowledge{
		UEAssociatedLogicalNGConnectionList: partOfNGInterface,
		CriticalityDiagnostics:              diagnostics,
	}).MarshalBinary()
}

func BuildInitialContextSetupResponse(
	ranUe n3iwf_context.RanUe,
	responseList *ngapType.PDUSessionResourceSetupListCxtRes,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	if responseList != nil && len(responseList.List) == 0 {
		responseList = nil
	}
	if failedList != nil && len(failedList.List) == 0 {
		failedList = nil
	}
	return (&ngap.InitialContextSetupResponse{
		AMFUENGAPID:                       amfID,
		RANUENGAPID:                       ranID,
		PDUSessionResourceSetupListCxtRes: responseList,
		PDUSessionResourceFailedToSetupListCxtRes: failedList,
		CriticalityDiagnostics:                    criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildInitialContextSetupFailure(
	ranUe n3iwf_context.RanUe,
	cause ngapType.Cause,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtFail,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	if failedList != nil && len(failedList.List) == 0 {
		failedList = nil
	}
	return (&ngap.InitialContextSetupFailure{
		AMFUENGAPID: amfID,
		RANUENGAPID: ranID,
		PDUSessionResourceFailedToSetupListCxtFail: failedList,
		Cause:                  &cause,
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildUEContextModificationResponse(
	ranUe n3iwf_context.RanUe,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	return (&ngap.UEContextModificationResponse{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildUEContextModificationFailure(
	ranUe n3iwf_context.RanUe,
	cause ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	return (&ngap.UEContextModificationFailure{
		AMFUENGAPID: amfID, RANUENGAPID: ranID, Cause: &cause,
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildUEContextReleaseComplete(
	ranUe n3iwf_context.RanUe,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	ctx := ranUe.GetSharedCtx()
	msg := &ngap.UEContextReleaseComplete{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		UserLocationInformation: ranUe.GetUserLocationInformation(),
		CriticalityDiagnostics:  criticalityDiagnostics,
	}
	if len(ctx.PduSessionList) != 0 {
		msg.PDUSessionResourceListCxtRelCpl = &ngapType.PDUSessionResourceListCxtRelCpl{}
		for _, session := range ctx.PduSessionList {
			msg.PDUSessionResourceListCxtRelCpl.List = append(
				msg.PDUSessionResourceListCxtRelCpl.List,
				ngapType.PDUSessionResourceItemCxtRelCpl{
					PDUSessionID: &ngapType.PDUSessionID{Value: session.Id},
				},
			)
		}
	}
	return msg.MarshalBinary()
}

func BuildUEContextReleaseRequest(
	ranUe n3iwf_context.RanUe,
	cause ngapType.Cause,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	ctx := ranUe.GetSharedCtx()
	msg := &ngap.UEContextReleaseRequest{
		AMFUENGAPID: amfID, RANUENGAPID: ranID, Cause: &cause,
	}
	if len(ctx.PduSessionList) != 0 {
		msg.PDUSessionResourceListCxtRelReq = &ngapType.PDUSessionResourceListCxtRelReq{}
		for _, session := range ctx.PduSessionList {
			msg.PDUSessionResourceListCxtRelReq.List = append(
				msg.PDUSessionResourceListCxtRelReq.List,
				ngapType.PDUSessionResourceItemCxtRelReq{
					PDUSessionID: &ngapType.PDUSessionID{Value: session.Id},
				},
			)
		}
	}
	return msg.MarshalBinary()
}

func BuildInitialUEMessage(
	ranUe n3iwf_context.RanUe,
	nasPDU []byte,
	allowedNSSAI *ngapType.AllowedNSSAI,
) ([]byte, error) {
	ctx := ranUe.GetSharedCtx()
	if ctx.RRCEstablishmentCause < 0 {
		return nil, errors.Errorf("BuildInitialUEMessage() ranUe.RRCEstablishmentCause negative value: %d",
			ctx.RRCEstablishmentCause)
	}
	msg := &ngap.InitialUEMessage{
		RANUENGAPID:             &ngapType.RANUENGAPID{Value: ctx.RanUeNgapId},
		NASPDU:                  &ngapType.NASPDU{Value: nasPDU},
		UserLocationInformation: ranUe.GetUserLocationInformation(),
		RRCEstablishmentCause:   &ngapType.RRCEstablishmentCause{Value: aper.Enumerated(ctx.RRCEstablishmentCause)},
		UEContextRequest:        &ngapType.UEContextRequest{Value: ngapType.UEContextRequestPresentRequested},
		AllowedNSSAI:            allowedNSSAI,
	}
	if ctx.Guti != "" {
		var amfID, tmsi string
		if len(ctx.Guti) == 19 {
			amfID, tmsi = ctx.Guti[5:11], ctx.Guti[11:]
		} else {
			amfID, tmsi = ctx.Guti[6:12], ctx.Guti[12:]
		}
		_, setID, pointer := util.AmfIdToNgap(amfID)
		tmsiBytes, err := hex.DecodeString(tmsi)
		if err != nil {
			return nil, errors.Wrap(err, "decode 5G-TMSI")
		}
		msg.FiveGSTMSI = &ngapType.FiveGSTMSI{
			AMFSetID:   &ngapType.AMFSetID{Value: setID},
			AMFPointer: &ngapType.AMFPointer{Value: pointer},
			FiveGTMSI:  &ngapType.FiveGTMSI{Value: tmsiBytes},
		}
		msg.AMFSetID = &ngapType.AMFSetID{Value: setID}
	}
	return msg.MarshalBinary()
}

func BuildUplinkNASTransport(
	ranUe n3iwf_context.RanUe,
	nasPDU []byte,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	return (&ngap.UplinkNASTransport{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		NASPDU:                  &ngapType.NASPDU{Value: nasPDU},
		UserLocationInformation: ranUe.GetUserLocationInformation(),
	}).MarshalBinary()
}

func BuildNASNonDeliveryIndication(
	ranUe n3iwf_context.RanUe,
	nasPDU []byte,
	cause ngapType.Cause,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	return (&ngap.NASNonDeliveryIndication{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		NASPDU: &ngapType.NASPDU{Value: nasPDU}, Cause: &cause,
	}).MarshalBinary()
}

func BuildRerouteNASRequest() ([]byte, error) {
	return nil, errors.New("BuildRerouteNASRequest: not implemented")
}

func BuildPDUSessionResourceSetupResponse(
	ranUe n3iwf_context.RanUe,
	responseList *ngapType.PDUSessionResourceSetupListSURes,
	failedList *ngapType.PDUSessionResourceFailedToSetupListSURes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	if responseList != nil && len(responseList.List) == 0 {
		responseList = nil
	}
	if failedList != nil && len(failedList.List) == 0 {
		failedList = nil
	}
	return (&ngap.PDUSessionResourceSetupResponse{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceSetupListSURes:         responseList,
		PDUSessionResourceFailedToSetupListSURes: failedList,
		CriticalityDiagnostics:                   criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildPDUSessionResourceModifyResponse(
	ranUe n3iwf_context.RanUe,
	responseList *ngapType.PDUSessionResourceModifyListModRes,
	failedList *ngapType.PDUSessionResourceFailedToModifyListModRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	if responseList != nil && len(responseList.List) == 0 {
		responseList = nil
	}
	if failedList != nil && len(failedList.List) == 0 {
		failedList = nil
	}
	return (&ngap.PDUSessionResourceModifyResponse{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceModifyListModRes:         responseList,
		PDUSessionResourceFailedToModifyListModRes: failedList,
		UserLocationInformation:                    ranUe.GetUserLocationInformation(),
		CriticalityDiagnostics:                     criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildPDUSessionResourceModifyIndication(
	ranUe n3iwf_context.RanUe,
	modifyList []ngapType.PDUSessionResourceModifyItemModInd,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	return (&ngap.PDUSessionResourceModifyIndication{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceModifyListModInd: &ngapType.PDUSessionResourceModifyListModInd{
			List: modifyList,
		},
	}).MarshalBinary()
}

func BuildPDUSessionResourceNotify(
	ranUe n3iwf_context.RanUe,
	notiList *ngapType.PDUSessionResourceNotifyList,
	relList *ngapType.PDUSessionResourceReleasedListNot,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	ctx := ranUe.GetSharedCtx()
	msg := &ngap.PDUSessionResourceNotify{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceNotifyList:      notiList,
		PDUSessionResourceReleasedListNot: relList,
	}
	if (ctx.IPAddrv4 != "" || ctx.IPAddrv6 != "") && ctx.PortNumber != 0 {
		msg.UserLocationInformation = ranUe.GetUserLocationInformation()
	}
	return msg.MarshalBinary()
}

func BuildPDUSessionResourceReleaseResponse(
	ranUe n3iwf_context.RanUe,
	relList ngapType.PDUSessionResourceReleasedListRelRes,
	diagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	amfID, ranID := ueIDs(ranUe)
	ctx := ranUe.GetSharedCtx()
	msg := &ngap.PDUSessionResourceReleaseResponse{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceReleasedListRelRes: &relList,
		CriticalityDiagnostics:               diagnostics,
	}
	if (ctx.IPAddrv4 != "" || ctx.IPAddrv6 != "") && ctx.PortNumber != 0 {
		msg.UserLocationInformation = ranUe.GetUserLocationInformation()
	}
	return msg.MarshalBinary()
}

func BuildErrorIndication(
	amfUENGAPID *int64,
	ranUENGAPID *int64,
	cause *ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	msg := &ngap.ErrorIndication{Cause: cause, CriticalityDiagnostics: criticalityDiagnostics}
	if amfUENGAPID != nil && ranUENGAPID != nil {
		msg.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: *amfUENGAPID}
		msg.RANUENGAPID = &ngapType.RANUENGAPID{Value: *ranUENGAPID}
	}
	return msg.MarshalBinary()
}

func BuildUERadioCapabilityInfoIndication() ([]byte, error) {
	return nil, errors.New("BuildUERadioCapabilityInfoIndication: not implemented")
}

func BuildUERadioCapabilityCheckResponse(
	ranUe n3iwf_context.RanUe,
	diagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	ctx := ranUe.GetSharedCtx()
	if ctx.IMSVoiceSupported < 0 {
		return nil, errors.Errorf(
			"BuildUERadioCapabilityCheckResponse() ranUe.IMSVoiceSupported negative value: %d",
			ctx.IMSVoiceSupported)
	}
	amfID, ranID := ueIDs(ranUe)
	return (&ngap.UERadioCapabilityCheckResponse{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		IMSVoiceSupportIndicator: &ngapType.IMSVoiceSupportIndicator{
			Value: aper.Enumerated(ctx.IMSVoiceSupported),
		},
		CriticalityDiagnostics: diagnostics,
	}).MarshalBinary()
}

func BuildAMFConfigurationUpdateAcknowledge(
	setupList *ngapType.AMFTNLAssociationSetupList,
	failList *ngapType.TNLAssociationList,
	diagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngap.AMFConfigurationUpdateAcknowledge{
		AMFTNLAssociationSetupList:         setupList,
		AMFTNLAssociationFailedToSetupList: failList,
		CriticalityDiagnostics:             diagnostics,
	}).MarshalBinary()
}

func BuildAMFConfigurationUpdateFailure(
	ngCause ngapType.Cause,
	time *ngapType.TimeToWait,
	diagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngap.AMFConfigurationUpdateFailure{
		Cause: &ngCause, TimeToWait: time, CriticalityDiagnostics: diagnostics,
	}).MarshalBinary()
}

func BuildRANConfigurationUpdate(
	ranNodeName string,
	suppTAList []factory.SupportedTAItem,
) ([]byte, error) {
	msg := &ngap.RANConfigurationUpdate{}
	if ranNodeName != "" {
		msg.RANNodeName = &ngapType.RANNodeName{Value: aper.PrintableString(ranNodeName)}
	}
	if len(suppTAList) != 0 {
		msg.SupportedTAList = buildSupportedTAList(suppTAList)
	}
	return msg.MarshalBinary()
}

func BuildUplinkRANConfigurationTransfer() ([]byte, error) {
	return nil, errors.New("BuildUplinkRANConfigurationTransfer: not implemented")
}

func BuildUplinkRANStatusTransfer() ([]byte, error) {
	return nil, errors.New("BuildUplinkRANStatusTransfer: not implemented")
}

func BuildLocationReportingFailureIndication() ([]byte, error) {
	return nil, errors.New("BuildLocationReportingFailureIndication: not implemented")
}

func BuildLocationReport() ([]byte, error) {
	return nil, errors.New("BuildLocationReport: not implemented")
}

func BuildRRCInactiveTransitionReport() ([]byte, error) {
	return nil, errors.New("BuildRRCInactiveTransitionReport: not implemented")
}

func BuildPDUSessionResourceSetupResponseTransfer(
	pduSession *n3iwf_context.PDUSession,
	gtpBindIPv4 string,
) ([]byte, error) {
	address := util.IPAddressToNgap(gtpBindIPv4, "")
	teid := make([]byte, 4)
	binary.BigEndian.PutUint32(teid, pduSession.GTPConnInfo.IncomingTEID)
	tunnel := &ngapType.GTPTunnel{
		TransportLayerAddress: &address,
		GTPTEID:               &ngapType.GTPTEID{Value: teid},
	}
	flowList := &ngapType.AssociatedQosFlowList{}
	for _, qfi := range pduSession.QFIList {
		flowList.List = append(flowList.List, ngapType.AssociatedQosFlowItem{
			QosFlowIdentifier: &ngapType.QosFlowIdentifier{Value: int64(qfi)},
		})
	}
	transfer := &ngapType.PDUSessionResourceSetupResponseTransfer{
		DLQosFlowPerTNLInformation: &ngapType.QosFlowPerTNLInformation{
			UPTransportLayerInformation: &ngapType.UPTransportLayerInformation{Choice: tunnel},
			AssociatedQosFlowList:       flowList,
		},
	}
	return ngapType.MarshalBinary(transfer)
}

func BuildPDUSessionResourceSetupUnsuccessfulTransfer(
	cause ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	return ngapType.MarshalBinary(&ngapType.PDUSessionResourceSetupUnsuccessfulTransfer{
		Cause: &cause, CriticalityDiagnostics: criticalityDiagnostics,
	})
}

func BuildPDUSessionResourceModifyResponseTransfer(
	ulNGUUPTNLInformation *ngapType.UPTransportLayerInformation,
	dlNGUUPTNLInformation *ngapType.UPTransportLayerInformation,
	responseList *ngapType.QosFlowAddOrModifyResponseList,
	failedList *ngapType.QosFlowListWithCause,
) ([]byte, error) {
	transfer := &ngapType.PDUSessionResourceModifyResponseTransfer{
		ULNGUUPTNLInformation: ulNGUUPTNLInformation,
		DLNGUUPTNLInformation: dlNGUUPTNLInformation,
	}
	if responseList != nil && len(responseList.List) != 0 {
		transfer.QosFlowAddOrModifyResponseList = responseList
	}
	if failedList != nil && len(failedList.List) != 0 {
		transfer.QosFlowFailedToAddOrModifyList = failedList
	}
	return ngapType.MarshalBinary(transfer)
}

func BuildPDUSessionResourceModifyUnsuccessfulTransfer(
	cause ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) ([]byte, error) {
	return ngapType.MarshalBinary(&ngapType.PDUSessionResourceModifyUnsuccessfulTransfer{
		Cause: &cause, CriticalityDiagnostics: criticalityDiagnostics,
	})
}

func BuildCause(present int, value aper.Enumerated) *ngapType.Cause {
	cause := &ngapType.Cause{}
	switch present {
	case CausePresentRadioNetwork:
		cause.Choice = &ngapType.CauseRadioNetwork{Value: value}
	case CausePresentTransport:
		cause.Choice = &ngapType.CauseTransport{Value: value}
	case CausePresentNas:
		cause.Choice = &ngapType.CauseNas{Value: value}
	case CausePresentProtocol:
		cause.Choice = &ngapType.CauseProtocol{Value: value}
	case CausePresentMisc:
		cause.Choice = &ngapType.CauseMisc{Value: value}
	}
	return cause
}
