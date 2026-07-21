package message

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/aper"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

const (
	testRanUeNgapID  int64 = 123
	testAmfUeNgapID  int64 = 456
	testPDUSessionID int64 = 10
)

var testNASPDU = []byte{0x7e, 0x00, 0x41, 0x01, 0x02, 0x03}

type ngapGoldenCase struct {
	name          string
	wantHex       string
	wantPresent   int
	wantProcedure int64
	build         func() ([]byte, error)
	validate      func(t *testing.T, pdu *ngapType.NGAPPDU)
}

func TestGoldenNGAPPDUBuilders(t *testing.T) {
	cause := testCause()

	tests := []ngapGoldenCase{
		{
			name: "NGSetupRequest",
			wantHex: "00150035000003001b00078002f8390081000052400f0600667265653547432d4e33495746" +
				"0066001000000000010002f83900001008010203",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeNGSetup,
			build: func() ([]byte, error) {
				return BuildNGSetupRequest(testGlobalN3IWFID(), "free5GC-N3IWF", testSupportedTAList())
			},
		},
		{
			name:          "NGReset",
			wantHex:       "00140014000002000f400200000058000740016201c8007b",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeNGReset,
			build: func() ([]byte, error) {
				return BuildNGReset(cause, testUEAssociatedLogicalNGConnectionList())
			},
		},
		{
			name:          "NGResetAcknowledge",
			wantHex:       "2014000d000001006f4006016201c8007b",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeNGReset,
			build: func() ([]byte, error) {
				return BuildNGResetAcknowledge(testUEAssociatedLogicalNGConnectionList(), nil)
			},
		},
		{
			name:          "InitialContextSetupResponseWithoutDiagnostics",
			wantHex:       "200e0026000004000a40032001c800554002007b0048400700000a030102030037400700000a03010203",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeInitialContextSetup,
			build: func() ([]byte, error) {
				return BuildInitialContextSetupResponse(
					testRanUE(), testSetupListCxtRes(), testFailedSetupListCxtRes(), nil,
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateInitialContextSetupResponse(t, pdu, false)
			},
		},
		{
			name: "InitialContextSetupResponseWithDiagnostics",
			wantHex: "200e0032000005000a40032001c800554002007b0048400700000a030102030037400700000a03010203" +
				"00134008780e000010000a00",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeInitialContextSetup,
			build: func() ([]byte, error) {
				return BuildInitialContextSetupResponse(
					testRanUE(),
					testSetupListCxtRes(),
					testFailedSetupListCxtRes(),
					testCriticalityDiagnostics(ngapType.ProcedureCodeInitialContextSetup),
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateInitialContextSetupResponse(t, pdu, true)
			},
		},
		{
			name:          "InitialContextSetupFailureWithoutDiagnostics",
			wantHex:       "400e0021000004000a40032001c800554002007b0084400700000a03010203000f40020000",
			wantPresent:   ngapType.NGAPPDUPresentUnsuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeInitialContextSetup,
			build: func() ([]byte, error) {
				return BuildInitialContextSetupFailure(testRanUE(), cause, testFailedSetupListCxtFail(), nil)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateInitialContextSetupFailure(t, pdu, false)
			},
		},
		{
			name: "InitialContextSetupFailureWithDiagnostics",
			wantHex: "400e002d000005000a40032001c800554002007b0084400700000a03010203000f40020000" +
				"00134008780e000010000a00",
			wantPresent:   ngapType.NGAPPDUPresentUnsuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeInitialContextSetup,
			build: func() ([]byte, error) {
				return BuildInitialContextSetupFailure(
					testRanUE(),
					cause,
					testFailedSetupListCxtFail(),
					testCriticalityDiagnostics(ngapType.ProcedureCodeInitialContextSetup),
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateInitialContextSetupFailure(t, pdu, true)
			},
		},
		{
			name:          "UEContextModificationResponseWithoutDiagnostics",
			wantHex:       "20280010000002000a40032001c800554002007b",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeUEContextModification,
			build: func() ([]byte, error) {
				return BuildUEContextModificationResponse(testRanUE(), nil)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateUEContextModificationResponse(t, pdu, false)
			},
		},
		{
			name:          "UEContextModificationResponseWithDiagnostics",
			wantHex:       "2028001c000003000a40032001c800554002007b001340087828000010000a00",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeUEContextModification,
			build: func() ([]byte, error) {
				return BuildUEContextModificationResponse(
					testRanUE(), testCriticalityDiagnostics(ngapType.ProcedureCodeUEContextModification),
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateUEContextModificationResponse(t, pdu, true)
			},
		},
		{
			name:          "UEContextModificationFailureWithoutDiagnostics",
			wantHex:       "40280016000003000a40032001c800554002007b000f40020000",
			wantPresent:   ngapType.NGAPPDUPresentUnsuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeUEContextModification,
			build: func() ([]byte, error) {
				return BuildUEContextModificationFailure(testRanUE(), cause, nil)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateUEContextModificationFailure(t, pdu, false)
			},
		},
		{
			name:          "UEContextModificationFailureWithDiagnostics",
			wantHex:       "40280022000004000a40032001c800554002007b000f40020000001340087828000010000a00",
			wantPresent:   ngapType.NGAPPDUPresentUnsuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeUEContextModification,
			build: func() ([]byte, error) {
				return BuildUEContextModificationFailure(
					testRanUE(), cause, testCriticalityDiagnostics(ngapType.ProcedureCodeUEContextModification),
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateUEContextModificationFailure(t, pdu, true)
			},
		},
		{
			name:          "UEContextReleaseCompleteWithoutDiagnostics",
			wantHex:       "20290023000004000a40032001c800554002007b0079400880f8c000020a1194003c000300000a",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeUEContextRelease,
			build: func() ([]byte, error) {
				return BuildUEContextReleaseComplete(testRanUE(), nil)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateUEContextReleaseComplete(t, pdu, false)
			},
		},
		{
			name: "UEContextReleaseCompleteWithDiagnostics",
			wantHex: "2029002f000005000a40032001c800554002007b0079400880f8c000020a1194003c000300000a" +
				"001340087829000010000a00",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeUEContextRelease,
			build: func() ([]byte, error) {
				return BuildUEContextReleaseComplete(
					testRanUE(), testCriticalityDiagnostics(ngapType.ProcedureCodeUEContextRelease),
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validateUEContextReleaseComplete(t, pdu, true)
			},
		},
		{
			name:          "UEContextReleaseRequest",
			wantHex:       "002a401d000004000a00032001c800550002007b0085000300000a000f40020000",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeUEContextReleaseRequest,
			build: func() ([]byte, error) {
				return BuildUEContextReleaseRequest(testRanUE(), cause)
			},
		},
		{
			name:          "InitialUEMessageWithoutOptionalIEs",
			wantHex:       "000f402a00000500550002007b00260007067e00410102030079000880f8c000020a1194005a4001180070400100",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeInitialUEMessage,
			build: func() ([]byte, error) {
				return BuildInitialUEMessage(testRanUE(), testNASPDU, nil)
			},
		},
		{
			name: "InitialUEMessageWithGUTIAndAllowedNSSAI",
			wantHex: "000f404400000800550002007b00260007067e00410102030079000880f8c000020a1194" +
				"005a400118001a00070080c0010203040003400202000070400100000040050201010203",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeInitialUEMessage,
			build: func() ([]byte, error) {
				ranUe := testRanUE()
				ranUe.Guti = "2089301020301020304"
				return BuildInitialUEMessage(ranUe, testNASPDU, testAllowedNSSAI())
			},
		},
		{
			name:          "UplinkNASTransport",
			wantHex:       "002e4027000004000a00032001c800550002007b00260007067e00410102030079400880f8c000020a1194",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeUplinkNASTransport,
			build: func() ([]byte, error) {
				return BuildUplinkNASTransport(testRanUE(), testNASPDU)
			},
		},
		{
			name:          "NASNonDeliveryIndication",
			wantHex:       "00134021000004000a00032001c800550002007b00264007067e0041010203000f40020000",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeNASNonDeliveryIndication,
			build: func() ([]byte, error) {
				return BuildNASNonDeliveryIndication(testRanUE(), testNASPDU, cause)
			},
		},
		{
			name:          "PDUSessionResourceSetupResponseWithoutDiagnostics",
			wantHex:       "201d0026000004000a40032001c800554002007b004b400700000a03010203003a400700000a03010203",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodePDUSessionResourceSetup,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceSetupResponse(
					testRanUE(), testSetupListSURes(), testFailedSetupListSURes(), nil,
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validatePDUSessionResourceSetupResponse(t, pdu, false)
			},
		},
		{
			name: "PDUSessionResourceSetupResponseWithDiagnostics",
			wantHex: "201d0032000005000a40032001c800554002007b004b400700000a03010203003a400700000a03010203" +
				"00134008781d000010000a00",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodePDUSessionResourceSetup,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceSetupResponse(
					testRanUE(),
					testSetupListSURes(),
					testFailedSetupListSURes(),
					testCriticalityDiagnostics(ngapType.ProcedureCodePDUSessionResourceSetup),
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validatePDUSessionResourceSetupResponse(t, pdu, true)
			},
		},
		{
			name: "PDUSessionResourceModifyResponseWithoutDiagnostics",
			wantHex: "201a0032000005000a40032001c800554002007b0041400700000a03010203" +
				"0036400700000a030102030079400880f8c000020a1194",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodePDUSessionResourceModify,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceModifyResponse(
					testRanUE(), testModifyListModRes(), testFailedModifyListModRes(), nil,
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validatePDUSessionResourceModifyResponse(t, pdu, false)
			},
		},
		{
			name: "PDUSessionResourceModifyResponseWithDiagnostics",
			wantHex: "201a003e000006000a40032001c800554002007b0041400700000a03010203" +
				"0036400700000a030102030079400880f8c000020a119400134008781a000010000a00",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodePDUSessionResourceModify,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceModifyResponse(
					testRanUE(),
					testModifyListModRes(),
					testFailedModifyListModRes(),
					testCriticalityDiagnostics(ngapType.ProcedureCodePDUSessionResourceModify),
				)
			},
			validate: func(t *testing.T, pdu *ngapType.NGAPPDU) {
				validatePDUSessionResourceModifyResponse(t, pdu, true)
			},
		},
		{
			name:          "PDUSessionResourceModifyIndication",
			wantHex:       "001b001b000003000a00032001c800550002007b003f000700000a03010203",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodePDUSessionResourceModifyIndication,
			build: func() ([]byte, error) {
				item := ngapType.PDUSessionResourceModifyItemModInd{}
				item.PDUSessionID.Value = testPDUSessionID
				item.PDUSessionResourceModifyIndicationTransfer = testTransferBytes()
				return BuildPDUSessionResourceModifyIndication(testRanUE(), []ngapType.PDUSessionResourceModifyItemModInd{item})
			},
		},
		{
			name: "PDUSessionResourceNotify",
			wantHex: "001e4032000005000a00032001c800550002007b0042000700000a03010203" +
				"0043400700000a030102030079400880f8c000020a1194",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodePDUSessionResourceNotify,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceNotify(testRanUE(), testNotifyList(), testReleasedListNot())
			},
		},
		{
			name:          "PDUSessionResourceReleaseResponse",
			wantHex:       "201c0027000004000a40032001c800554002007b0046400700000a030102030079400880f8c000020a1194",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodePDUSessionResourceRelease,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceReleaseResponse(testRanUE(), testReleasedListRelRes(), nil)
			},
		},
		{
			name:          "ErrorIndication",
			wantHex:       "00094016000003000a40032001c800554002007b000f40020000",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeErrorIndication,
			build: func() ([]byte, error) {
				amfID, ranID := testAmfUeNgapID, testRanUeNgapID
				return BuildErrorIndication(&amfID, &ranID, &cause, nil)
			},
		},
		{
			name:          "UERadioCapabilityCheckResponse",
			wantHex:       "202b0015000003000a40032001c800554002007b001e000140",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeUERadioCapabilityCheck,
			build: func() ([]byte, error) {
				return BuildUERadioCapabilityCheckResponse(testRanUE(), nil)
			},
		},
		{
			name:          "AMFConfigurationUpdateAcknowledge",
			wantHex:       "2000001b00000200054007000f80c633640a00044009000f80c633640b0000",
			wantPresent:   ngapType.NGAPPDUPresentSuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeAMFConfigurationUpdate,
			build: func() ([]byte, error) {
				return BuildAMFConfigurationUpdateAcknowledge(testAMFTNLAssociationSetupList(), testTNLAssociationList(), nil)
			},
		},
		{
			name:          "AMFConfigurationUpdateFailure",
			wantHex:       "4000000e000002000f40020000006b400120",
			wantPresent:   ngapType.NGAPPDUPresentUnsuccessfulOutcome,
			wantProcedure: ngapType.ProcedureCodeAMFConfigurationUpdate,
			build: func() ([]byte, error) {
				timeToWait := &ngapType.TimeToWait{Value: ngapType.TimeToWaitPresentV5s}
				return BuildAMFConfigurationUpdateFailure(cause, timeToWait, nil)
			},
		},
		{
			name:          "RANConfigurationUpdate",
			wantHex:       "0023002a0000020052400f0600667265653547432d4e334957460066001000000000010002f83900001008010203",
			wantPresent:   ngapType.NGAPPDUPresentInitiatingMessage,
			wantProcedure: ngapType.ProcedureCodeRANConfigurationUpdate,
			build: func() ([]byte, error) {
				return BuildRANConfigurationUpdate("free5GC-N3IWF", testSupportedTAList())
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := assertGoldenBytes(t, test.wantHex, test.build)
			pdu, err := ngap.Decoder(got)
			require.NoError(t, err)
			require.Equal(t, test.wantPresent, pdu.Present)
			require.Equal(t, test.wantProcedure, procedureCode(pdu))
			if test.validate != nil {
				test.validate(t, pdu)
			}
		})
	}
}

func TestGoldenNGAPTransferBuilders(t *testing.T) {
	cause := testCause()

	t.Run("PDUSessionResourceSetupResponseTransfer", func(t *testing.T) {
		build := func() ([]byte, error) {
			pduSession := &n3iwf_context.PDUSession{
				GTPConnInfo: &n3iwf_context.GTPConnectionInfo{IncomingTEID: 0x01020304},
				QFIList:     []uint8{1, 9},
			}
			return BuildPDUSessionResourceSetupResponseTransfer(pduSession, "192.0.2.20")
		}
		got := assertGoldenBytes(t, "0003e0c00002140102030404010240", build)

		var decoded ngapType.PDUSessionResourceSetupResponseTransfer
		require.NoError(t, aper.UnmarshalWithParams(got, &decoded, "valueExt"))
		gotTEID := decoded.DLQosFlowPerTNLInformation.UPTransportLayerInformation.GTPTunnel.GTPTEID.Value
		require.Equal(t, aper.OctetString{0x01, 0x02, 0x03, 0x04}, gotTEID)
		require.Len(t, decoded.DLQosFlowPerTNLInformation.AssociatedQosFlowList.List, 2)
		require.Equal(t, int64(1), decoded.DLQosFlowPerTNLInformation.AssociatedQosFlowList.List[0].QosFlowIdentifier.Value)
		require.Equal(t, int64(9), decoded.DLQosFlowPerTNLInformation.AssociatedQosFlowList.List[1].QosFlowIdentifier.Value)
	})

	t.Run("PDUSessionResourceSetupUnsuccessfulTransfer", func(t *testing.T) {
		build := func() ([]byte, error) {
			return BuildPDUSessionResourceSetupUnsuccessfulTransfer(cause, nil)
		}
		got := assertGoldenBytes(t, "0000", build)

		var decoded ngapType.PDUSessionResourceSetupUnsuccessfulTransfer
		require.NoError(t, aper.UnmarshalWithParams(got, &decoded, "valueExt"))
		require.Equal(t, ngapType.CausePresentRadioNetwork, decoded.Cause.Present)
	})

	t.Run("PDUSessionResourceModifyResponseTransfer", func(t *testing.T) {
		build := func() ([]byte, error) {
			responseList := &ngapType.QosFlowAddOrModifyResponseList{
				List: []ngapType.QosFlowAddOrModifyResponseItem{{
					QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1},
				}},
			}
			failedList := &ngapType.QosFlowListWithCause{
				List: []ngapType.QosFlowWithCauseItem{{
					QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 9},
					Cause:             cause,
				}},
			}
			return BuildPDUSessionResourceModifyResponseTransfer(
				testUPTransportLayerInformation("198.51.100.10", []byte{0x11, 0x12, 0x13, 0x14}),
				testUPTransportLayerInformation("192.0.2.20", []byte{0x01, 0x02, 0x03, 0x04}),
				responseList,
				failedList,
			)
		}
		got := assertGoldenBytes(t, "7403e0c00002140102030401f0c633640a111213140002002400", build)

		var decoded ngapType.PDUSessionResourceModifyResponseTransfer
		require.NoError(t, aper.UnmarshalWithParams(got, &decoded, "valueExt"))
		require.NotNil(t, decoded.ULNGUUPTNLInformation)
		require.NotNil(t, decoded.DLNGUUPTNLInformation)
		require.Len(t, decoded.QosFlowAddOrModifyResponseList.List, 1)
		require.Len(t, decoded.QosFlowFailedToAddOrModifyList.List, 1)
	})

	t.Run("PDUSessionResourceModifyUnsuccessfulTransfer", func(t *testing.T) {
		build := func() ([]byte, error) {
			return BuildPDUSessionResourceModifyUnsuccessfulTransfer(cause, nil)
		}
		got := assertGoldenBytes(t, "0000", build)

		var decoded ngapType.PDUSessionResourceModifyUnsuccessfulTransfer
		require.NoError(t, aper.UnmarshalWithParams(got, &decoded, "valueExt"))
		require.Equal(t, ngapType.CausePresentRadioNetwork, decoded.Cause.Present)
	})
}

func assertGoldenBytes(t *testing.T, wantHex string, build func() ([]byte, error)) []byte {
	t.Helper()

	got, err := build()
	require.NoError(t, err)
	require.NotEmpty(t, got)

	gotAgain, err := build()
	require.NoError(t, err)
	require.Equal(t, got, gotAgain, "builder output is not deterministic")

	require.Equal(t, wantHex, hex.EncodeToString(got))

	return got
}

func procedureCode(pdu *ngapType.NGAPPDU) int64 {
	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		return pdu.InitiatingMessage.ProcedureCode.Value
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		return pdu.SuccessfulOutcome.ProcedureCode.Value
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		return pdu.UnsuccessfulOutcome.ProcedureCode.Value
	default:
		return -1
	}
}

func validateInitialContextSetupResponse(t *testing.T, pdu *ngapType.NGAPPDU, wantDiagnostics bool) {
	t.Helper()

	require.NotNil(t, pdu.SuccessfulOutcome)
	require.Equal(
		t,
		ngapType.SuccessfulOutcomePresentInitialContextSetupResponse,
		pdu.SuccessfulOutcome.Value.Present,
	)
	require.NotNil(t, pdu.SuccessfulOutcome.Value.InitialContextSetupResponse)

	ies := pdu.SuccessfulOutcome.Value.InitialContextSetupResponse.ProtocolIEs.List
	if wantDiagnostics {
		require.Len(t, ies, 5)
	} else {
		require.Len(t, ies, 4)
	}

	diagnosticsCount := 0
	diagnosticsPresent := 0
	var diagnostics *ngapType.CriticalityDiagnostics
	for i := range ies {
		ie := &ies[i]
		if ie.Id.Value == ngapType.ProtocolIEIDCriticalityDiagnostics {
			diagnosticsCount++
			diagnosticsPresent = ie.Value.Present
			diagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	requireCriticalityDiagnosticsIE(
		t,
		wantDiagnostics,
		diagnosticsCount,
		diagnosticsPresent,
		ngapType.InitialContextSetupResponseIEsPresentCriticalityDiagnostics,
		diagnostics,
		ngapType.ProcedureCodeInitialContextSetup,
	)
}

func validateInitialContextSetupFailure(t *testing.T, pdu *ngapType.NGAPPDU, wantDiagnostics bool) {
	t.Helper()

	require.NotNil(t, pdu.UnsuccessfulOutcome)
	require.Equal(
		t,
		ngapType.UnsuccessfulOutcomePresentInitialContextSetupFailure,
		pdu.UnsuccessfulOutcome.Value.Present,
	)
	require.NotNil(t, pdu.UnsuccessfulOutcome.Value.InitialContextSetupFailure)

	ies := pdu.UnsuccessfulOutcome.Value.InitialContextSetupFailure.ProtocolIEs.List
	if wantDiagnostics {
		require.Len(t, ies, 5)
	} else {
		require.Len(t, ies, 4)
	}

	var cause *ngapType.Cause
	diagnosticsCount := 0
	diagnosticsPresent := 0
	var diagnostics *ngapType.CriticalityDiagnostics
	for i := range ies {
		ie := &ies[i]
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			cause = ie.Value.Cause
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			diagnosticsCount++
			diagnosticsPresent = ie.Value.Present
			diagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	requireRadioNetworkUnspecifiedCause(t, cause)
	requireCriticalityDiagnosticsIE(
		t,
		wantDiagnostics,
		diagnosticsCount,
		diagnosticsPresent,
		ngapType.InitialContextSetupFailureIEsPresentCriticalityDiagnostics,
		diagnostics,
		ngapType.ProcedureCodeInitialContextSetup,
	)
}

func validateUEContextModificationResponse(t *testing.T, pdu *ngapType.NGAPPDU, wantDiagnostics bool) {
	t.Helper()

	require.NotNil(t, pdu.SuccessfulOutcome)
	require.Equal(
		t,
		ngapType.SuccessfulOutcomePresentUEContextModificationResponse,
		pdu.SuccessfulOutcome.Value.Present,
	)
	require.NotNil(t, pdu.SuccessfulOutcome.Value.UEContextModificationResponse)

	ies := pdu.SuccessfulOutcome.Value.UEContextModificationResponse.ProtocolIEs.List
	if wantDiagnostics {
		require.Len(t, ies, 3)
	} else {
		require.Len(t, ies, 2)
	}

	diagnosticsCount := 0
	diagnosticsPresent := 0
	var diagnostics *ngapType.CriticalityDiagnostics
	for i := range ies {
		ie := &ies[i]
		if ie.Id.Value == ngapType.ProtocolIEIDCriticalityDiagnostics {
			diagnosticsCount++
			diagnosticsPresent = ie.Value.Present
			diagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	requireCriticalityDiagnosticsIE(
		t,
		wantDiagnostics,
		diagnosticsCount,
		diagnosticsPresent,
		ngapType.UEContextModificationResponseIEsPresentCriticalityDiagnostics,
		diagnostics,
		ngapType.ProcedureCodeUEContextModification,
	)
}

func validateUEContextModificationFailure(t *testing.T, pdu *ngapType.NGAPPDU, wantDiagnostics bool) {
	t.Helper()

	require.NotNil(t, pdu.UnsuccessfulOutcome)
	require.Equal(
		t,
		ngapType.UnsuccessfulOutcomePresentUEContextModificationFailure,
		pdu.UnsuccessfulOutcome.Value.Present,
	)
	require.NotNil(t, pdu.UnsuccessfulOutcome.Value.UEContextModificationFailure)

	ies := pdu.UnsuccessfulOutcome.Value.UEContextModificationFailure.ProtocolIEs.List
	if wantDiagnostics {
		require.Len(t, ies, 4)
	} else {
		require.Len(t, ies, 3)
	}

	var cause *ngapType.Cause
	diagnosticsCount := 0
	diagnosticsPresent := 0
	var diagnostics *ngapType.CriticalityDiagnostics
	for i := range ies {
		ie := &ies[i]
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			cause = ie.Value.Cause
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			diagnosticsCount++
			diagnosticsPresent = ie.Value.Present
			diagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	requireRadioNetworkUnspecifiedCause(t, cause)
	requireCriticalityDiagnosticsIE(
		t,
		wantDiagnostics,
		diagnosticsCount,
		diagnosticsPresent,
		ngapType.UEContextModificationFailureIEsPresentCriticalityDiagnostics,
		diagnostics,
		ngapType.ProcedureCodeUEContextModification,
	)
}

func validateUEContextReleaseComplete(t *testing.T, pdu *ngapType.NGAPPDU, wantDiagnostics bool) {
	t.Helper()

	require.NotNil(t, pdu.SuccessfulOutcome)
	require.Equal(
		t,
		ngapType.SuccessfulOutcomePresentUEContextReleaseComplete,
		pdu.SuccessfulOutcome.Value.Present,
	)
	require.NotNil(t, pdu.SuccessfulOutcome.Value.UEContextReleaseComplete)

	ies := pdu.SuccessfulOutcome.Value.UEContextReleaseComplete.ProtocolIEs.List
	if wantDiagnostics {
		require.Len(t, ies, 5)
	} else {
		require.Len(t, ies, 4)
	}

	diagnosticsCount := 0
	diagnosticsPresent := 0
	var diagnostics *ngapType.CriticalityDiagnostics
	for i := range ies {
		ie := &ies[i]
		if ie.Id.Value == ngapType.ProtocolIEIDCriticalityDiagnostics {
			diagnosticsCount++
			diagnosticsPresent = ie.Value.Present
			diagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	requireCriticalityDiagnosticsIE(
		t,
		wantDiagnostics,
		diagnosticsCount,
		diagnosticsPresent,
		ngapType.UEContextReleaseCompleteIEsPresentCriticalityDiagnostics,
		diagnostics,
		ngapType.ProcedureCodeUEContextRelease,
	)
}

func validatePDUSessionResourceSetupResponse(t *testing.T, pdu *ngapType.NGAPPDU, wantDiagnostics bool) {
	t.Helper()

	require.NotNil(t, pdu.SuccessfulOutcome)
	require.Equal(
		t,
		ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse,
		pdu.SuccessfulOutcome.Value.Present,
	)
	require.NotNil(t, pdu.SuccessfulOutcome.Value.PDUSessionResourceSetupResponse)

	ies := pdu.SuccessfulOutcome.Value.PDUSessionResourceSetupResponse.ProtocolIEs.List
	if wantDiagnostics {
		require.Len(t, ies, 5)
	} else {
		require.Len(t, ies, 4)
	}

	diagnosticsCount := 0
	diagnosticsPresent := 0
	var diagnostics *ngapType.CriticalityDiagnostics
	for i := range ies {
		ie := &ies[i]
		if ie.Id.Value == ngapType.ProtocolIEIDCriticalityDiagnostics {
			diagnosticsCount++
			diagnosticsPresent = ie.Value.Present
			diagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	requireCriticalityDiagnosticsIE(
		t,
		wantDiagnostics,
		diagnosticsCount,
		diagnosticsPresent,
		ngapType.PDUSessionResourceSetupResponseIEsPresentCriticalityDiagnostics,
		diagnostics,
		ngapType.ProcedureCodePDUSessionResourceSetup,
	)
}

func validatePDUSessionResourceModifyResponse(t *testing.T, pdu *ngapType.NGAPPDU, wantDiagnostics bool) {
	t.Helper()

	require.NotNil(t, pdu.SuccessfulOutcome)
	require.Equal(
		t,
		ngapType.SuccessfulOutcomePresentPDUSessionResourceModifyResponse,
		pdu.SuccessfulOutcome.Value.Present,
	)
	require.NotNil(t, pdu.SuccessfulOutcome.Value.PDUSessionResourceModifyResponse)

	ies := pdu.SuccessfulOutcome.Value.PDUSessionResourceModifyResponse.ProtocolIEs.List
	if wantDiagnostics {
		require.Len(t, ies, 6)
	} else {
		require.Len(t, ies, 5)
	}

	diagnosticsCount := 0
	diagnosticsPresent := 0
	var diagnostics *ngapType.CriticalityDiagnostics
	for i := range ies {
		ie := &ies[i]
		if ie.Id.Value == ngapType.ProtocolIEIDCriticalityDiagnostics {
			diagnosticsCount++
			diagnosticsPresent = ie.Value.Present
			diagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	requireCriticalityDiagnosticsIE(
		t,
		wantDiagnostics,
		diagnosticsCount,
		diagnosticsPresent,
		ngapType.PDUSessionResourceModifyResponseIEsPresentCriticalityDiagnostics,
		diagnostics,
		ngapType.ProcedureCodePDUSessionResourceModify,
	)
}

func requireCriticalityDiagnosticsIE(
	t *testing.T,
	want bool,
	count int,
	present int,
	wantPresent int,
	diagnostics *ngapType.CriticalityDiagnostics,
	wantProcedureCode int64,
) {
	t.Helper()

	if !want {
		require.Zero(t, count)
		require.Nil(t, diagnostics)
		return
	}

	require.Equal(t, 1, count)
	require.Equal(t, wantPresent, present)
	requireCriticalityDiagnostics(t, diagnostics, wantProcedureCode)
}

func requireCriticalityDiagnostics(
	t *testing.T,
	diagnostics *ngapType.CriticalityDiagnostics,
	wantProcedureCode int64,
) {
	t.Helper()

	require.NotNil(t, diagnostics)
	require.NotNil(t, diagnostics.ProcedureCode)
	require.Equal(t, wantProcedureCode, diagnostics.ProcedureCode.Value)
	require.NotNil(t, diagnostics.TriggeringMessage)
	require.Equal(t, ngapType.TriggeringMessagePresentInitiatingMessage, diagnostics.TriggeringMessage.Value)
	require.NotNil(t, diagnostics.ProcedureCriticality)
	require.Equal(t, ngapType.CriticalityPresentReject, diagnostics.ProcedureCriticality.Value)
	require.NotNil(t, diagnostics.IEsCriticalityDiagnostics)
	require.Len(t, diagnostics.IEsCriticalityDiagnostics.List, 1)

	item := diagnostics.IEsCriticalityDiagnostics.List[0]
	require.Equal(t, ngapType.CriticalityPresentIgnore, item.IECriticality.Value)
	require.Equal(t, ngapType.ProtocolIEIDAMFUENGAPID, item.IEID.Value)
	require.Equal(t, ngapType.TypeOfErrorPresentNotUnderstood, item.TypeOfError.Value)
}

func requireRadioNetworkUnspecifiedCause(t *testing.T, cause *ngapType.Cause) {
	t.Helper()

	require.NotNil(t, cause)
	require.Equal(t, ngapType.CausePresentRadioNetwork, cause.Present)
	require.NotNil(t, cause.RadioNetwork)
	require.Equal(t, ngapType.CauseRadioNetworkPresentUnspecified, cause.RadioNetwork.Value)
}

func testRanUE() *n3iwf_context.N3IWFRanUe {
	return &n3iwf_context.N3IWFRanUe{
		RanUeSharedCtx: n3iwf_context.RanUeSharedCtx{
			RanUeNgapId:           testRanUeNgapID,
			AmfUeNgapId:           testAmfUeNgapID,
			IPAddrv4:              "192.0.2.10",
			PortNumber:            4500,
			PduSessionList:        map[int64]*n3iwf_context.PDUSession{testPDUSessionID: {Id: testPDUSessionID}},
			RRCEstablishmentCause: EstablishmentCauseMO_Signalling,
			IMSVoiceSupported:     1,
		},
	}
}

func testCause() ngapType.Cause {
	return *BuildCause(
		ngapType.CausePresentRadioNetwork,
		ngapType.CauseRadioNetworkPresentUnspecified,
	)
}

func testCriticalityDiagnostics(procedureCode int64) *ngapType.CriticalityDiagnostics {
	return &ngapType.CriticalityDiagnostics{
		ProcedureCode: &ngapType.ProcedureCode{
			Value: procedureCode,
		},
		TriggeringMessage: &ngapType.TriggeringMessage{
			Value: ngapType.TriggeringMessagePresentInitiatingMessage,
		},
		ProcedureCriticality: &ngapType.Criticality{
			Value: ngapType.CriticalityPresentReject,
		},
		IEsCriticalityDiagnostics: &ngapType.CriticalityDiagnosticsIEList{
			List: []ngapType.CriticalityDiagnosticsIEItem{
				{
					IECriticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
					IEID:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
					TypeOfError:   ngapType.TypeOfError{Value: ngapType.TypeOfErrorPresentNotUnderstood},
				},
			},
		},
	}
}

func testGlobalN3IWFID() *factory.GlobalN3IWFID {
	return &factory.GlobalN3IWFID{
		PLMNID:  &factory.PLMNID{Mcc: "208", Mnc: "93"},
		N3IWFID: 0x0102,
	}
}

func testSupportedTAList() []factory.SupportedTAItem {
	return []factory.SupportedTAItem{{
		TAC: "000001",
		BroadcastPLMNList: []factory.BroadcastPLMNItem{{
			PLMNID: &factory.PLMNID{Mcc: "208", Mnc: "93"},
			TAISliceSupportList: []factory.SliceSupportItem{{
				SNSSAI: factory.SNSSAIItem{SST: 1, SD: "010203"},
			}},
		}},
	}}
}

func testAllowedNSSAI() *ngapType.AllowedNSSAI {
	return &ngapType.AllowedNSSAI{
		List: []ngapType.AllowedNSSAIItem{{
			SNSSAI: ngapType.SNSSAI{
				SST: ngapType.SST{Value: aper.OctetString{0x01}},
				SD:  &ngapType.SD{Value: aper.OctetString{0x01, 0x02, 0x03}},
			},
		}},
	}
}

func testUEAssociatedLogicalNGConnectionList() *ngapType.UEAssociatedLogicalNGConnectionList {
	return &ngapType.UEAssociatedLogicalNGConnectionList{
		List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
			AMFUENGAPID: &ngapType.AMFUENGAPID{Value: testAmfUeNgapID},
			RANUENGAPID: &ngapType.RANUENGAPID{Value: testRanUeNgapID},
		}},
	}
}

func testTransferBytes() []byte {
	return []byte{0x01, 0x02, 0x03}
}

func testSetupListCxtRes() *ngapType.PDUSessionResourceSetupListCxtRes {
	list := new(ngapType.PDUSessionResourceSetupListCxtRes)
	AppendPDUSessionResourceSetupListCxtRes(list, testPDUSessionID, testTransferBytes())
	return list
}

func testFailedSetupListCxtRes() *ngapType.PDUSessionResourceFailedToSetupListCxtRes {
	list := new(ngapType.PDUSessionResourceFailedToSetupListCxtRes)
	AppendPDUSessionResourceFailedToSetupListCxtRes(list, testPDUSessionID, testTransferBytes())
	return list
}

func testFailedSetupListCxtFail() *ngapType.PDUSessionResourceFailedToSetupListCxtFail {
	list := new(ngapType.PDUSessionResourceFailedToSetupListCxtFail)
	AppendPDUSessionResourceFailedToSetupListCxtfail(list, testPDUSessionID, testTransferBytes())
	return list
}

func testSetupListSURes() *ngapType.PDUSessionResourceSetupListSURes {
	list := new(ngapType.PDUSessionResourceSetupListSURes)
	AppendPDUSessionResourceSetupListSURes(list, testPDUSessionID, testTransferBytes())
	return list
}

func testFailedSetupListSURes() *ngapType.PDUSessionResourceFailedToSetupListSURes {
	list := new(ngapType.PDUSessionResourceFailedToSetupListSURes)
	AppendPDUSessionResourceFailedToSetupListSURes(list, testPDUSessionID, testTransferBytes())
	return list
}

func testModifyListModRes() *ngapType.PDUSessionResourceModifyListModRes {
	list := new(ngapType.PDUSessionResourceModifyListModRes)
	AppendPDUSessionResourceModifyListModRes(list, testPDUSessionID, testTransferBytes())
	return list
}

func testFailedModifyListModRes() *ngapType.PDUSessionResourceFailedToModifyListModRes {
	list := new(ngapType.PDUSessionResourceFailedToModifyListModRes)
	AppendPDUSessionResourceFailedToModifyListModRes(list, testPDUSessionID, testTransferBytes())
	return list
}

func testNotifyList() *ngapType.PDUSessionResourceNotifyList {
	item := ngapType.PDUSessionResourceNotifyItem{}
	item.PDUSessionID.Value = testPDUSessionID
	item.PDUSessionResourceNotifyTransfer = testTransferBytes()
	return &ngapType.PDUSessionResourceNotifyList{List: []ngapType.PDUSessionResourceNotifyItem{item}}
}

func testReleasedListNot() *ngapType.PDUSessionResourceReleasedListNot {
	item := ngapType.PDUSessionResourceReleasedItemNot{}
	item.PDUSessionID.Value = testPDUSessionID
	item.PDUSessionResourceNotifyReleasedTransfer = testTransferBytes()
	return &ngapType.PDUSessionResourceReleasedListNot{List: []ngapType.PDUSessionResourceReleasedItemNot{item}}
}

func testReleasedListRelRes() ngapType.PDUSessionResourceReleasedListRelRes {
	item := ngapType.PDUSessionResourceReleasedItemRelRes{}
	item.PDUSessionID.Value = testPDUSessionID
	item.PDUSessionResourceReleaseResponseTransfer = testTransferBytes()
	return ngapType.PDUSessionResourceReleasedListRelRes{
		List: []ngapType.PDUSessionResourceReleasedItemRelRes{item},
	}
}

func testUPTransportLayerInformation(ipAddress string, teid []byte) *ngapType.UPTransportLayerInformation {
	return &ngapType.UPTransportLayerInformation{
		Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
		GTPTunnel: &ngapType.GTPTunnel{
			TransportLayerAddress: ngapConvert.IPAddressToNgap(ipAddress, ""),
			GTPTEID:               ngapType.GTPTEID{Value: teid},
		},
	}
}

func testCPTransportLayerInformation(ipAddress string) ngapType.CPTransportLayerInformation {
	address := ngapConvert.IPAddressToNgap(ipAddress, "")
	return ngapType.CPTransportLayerInformation{
		Present:           ngapType.CPTransportLayerInformationPresentEndpointIPAddress,
		EndpointIPAddress: &address,
	}
}

func testAMFTNLAssociationSetupList() *ngapType.AMFTNLAssociationSetupList {
	return &ngapType.AMFTNLAssociationSetupList{
		List: []ngapType.AMFTNLAssociationSetupItem{{
			AMFTNLAssociationAddress: testCPTransportLayerInformation("198.51.100.10"),
		}},
	}
}

func testTNLAssociationList() *ngapType.TNLAssociationList {
	return &ngapType.TNLAssociationList{
		List: []ngapType.TNLAssociationItem{{
			TNLAssociationAddress: testCPTransportLayerInformation("198.51.100.11"),
			Cause:                 testCause(),
		}},
	}
}
