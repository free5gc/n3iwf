package message

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/util"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngap "github.com/free5gc/ngap/message"
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
	wantPresent   int64
	wantProcedure int64
	build         func() ([]byte, error)
	validate      func(t *testing.T, pdu ngap.Message)
}

func TestGoldenNGAPPDUBuilders(t *testing.T) {
	cause := testCause()

	tests := []ngapGoldenCase{
		{
			name: "NGSetupRequest",
			wantHex: "0015003a000004001b00078002f8390081000052400f0600667265653547432d4e33495746" +
				"0066001000000000010002f839000010080102030015400140",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeNGSetup,
			build: func() ([]byte, error) {
				return BuildNGSetupRequest(testGlobalN3IWFID(), "free5GC-N3IWF", testSupportedTAList())
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				msg, ok := pdu.(*ngap.NGSetupRequest)
				require.True(t, ok)
				require.NotNil(t, msg.DefaultPagingDRX)
				require.Equal(t, ngapType.PagingDRXPresentV128, msg.DefaultPagingDRX.Value)
			},
		},
		{
			name:          "NGReset",
			wantHex:       "00140014000002000f400200000058000740016201c8007b",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeNGReset,
			build: func() ([]byte, error) {
				return BuildNGReset(cause, testUEAssociatedLogicalNGConnectionList())
			},
		},
		{
			name:          "NGResetAcknowledge",
			wantHex:       "2014000d000001006f4006016201c8007b",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeNGReset,
			build: func() ([]byte, error) {
				return BuildNGResetAcknowledge(testUEAssociatedLogicalNGConnectionList(), nil)
			},
		},
		{
			name:          "InitialContextSetupResponseWithoutDiagnostics",
			wantHex:       "200e0026000004000a40032001c800554002007b0048400700000a030102030037400700000a03010203",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeInitialContextSetup,
			build: func() ([]byte, error) {
				return BuildInitialContextSetupResponse(
					testRanUE(), testSetupListCxtRes(), testFailedSetupListCxtRes(), nil,
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateInitialContextSetupResponse(t, pdu, false)
			},
		},
		{
			name: "InitialContextSetupResponseWithDiagnostics",
			wantHex: "200e0032000005000a40032001c800554002007b0048400700000a030102030037400700000a03010203" +
				"00134008780e000010000a00",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeInitialContextSetup,
			build: func() ([]byte, error) {
				return BuildInitialContextSetupResponse(
					testRanUE(),
					testSetupListCxtRes(),
					testFailedSetupListCxtRes(),
					testCriticalityDiagnostics(ngap.ProcedureCodeInitialContextSetup),
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateInitialContextSetupResponse(t, pdu, true)
			},
		},
		{
			name:          "InitialContextSetupFailureWithoutDiagnostics",
			wantHex:       "400e0021000004000a40032001c800554002007b0084400700000a03010203000f40020000",
			wantPresent:   ngap.MessageTypeUnsuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeInitialContextSetup,
			build: func() ([]byte, error) {
				return BuildInitialContextSetupFailure(testRanUE(), cause, testFailedSetupListCxtFail(), nil)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateInitialContextSetupFailure(t, pdu, false)
			},
		},
		{
			name: "InitialContextSetupFailureWithDiagnostics",
			wantHex: "400e002d000005000a40032001c800554002007b0084400700000a03010203000f40020000" +
				"00134008780e000010000a00",
			wantPresent:   ngap.MessageTypeUnsuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeInitialContextSetup,
			build: func() ([]byte, error) {
				return BuildInitialContextSetupFailure(
					testRanUE(),
					cause,
					testFailedSetupListCxtFail(),
					testCriticalityDiagnostics(ngap.ProcedureCodeInitialContextSetup),
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateInitialContextSetupFailure(t, pdu, true)
			},
		},
		{
			name:          "UEContextModificationResponseWithoutDiagnostics",
			wantHex:       "20280010000002000a40032001c800554002007b",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeUEContextModification,
			build: func() ([]byte, error) {
				return BuildUEContextModificationResponse(testRanUE(), nil)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateUEContextModificationResponse(t, pdu, false)
			},
		},
		{
			name:          "UEContextModificationResponseWithDiagnostics",
			wantHex:       "2028001c000003000a40032001c800554002007b001340087828000010000a00",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeUEContextModification,
			build: func() ([]byte, error) {
				return BuildUEContextModificationResponse(
					testRanUE(), testCriticalityDiagnostics(ngap.ProcedureCodeUEContextModification),
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateUEContextModificationResponse(t, pdu, true)
			},
		},
		{
			name:          "UEContextModificationFailureWithoutDiagnostics",
			wantHex:       "40280016000003000a40032001c800554002007b000f40020000",
			wantPresent:   ngap.MessageTypeUnsuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeUEContextModification,
			build: func() ([]byte, error) {
				return BuildUEContextModificationFailure(testRanUE(), cause, nil)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateUEContextModificationFailure(t, pdu, false)
			},
		},
		{
			name:          "UEContextModificationFailureWithDiagnostics",
			wantHex:       "40280022000004000a40032001c800554002007b000f40020000001340087828000010000a00",
			wantPresent:   ngap.MessageTypeUnsuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeUEContextModification,
			build: func() ([]byte, error) {
				return BuildUEContextModificationFailure(
					testRanUE(), cause, testCriticalityDiagnostics(ngap.ProcedureCodeUEContextModification),
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateUEContextModificationFailure(t, pdu, true)
			},
		},
		{
			name:          "UEContextReleaseCompleteWithoutDiagnostics",
			wantHex:       "20290023000004000a40032001c800554002007b0079400880f8c000020a1194003c000300000a",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeUEContextRelease,
			build: func() ([]byte, error) {
				return BuildUEContextReleaseComplete(testRanUE(), nil)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateUEContextReleaseComplete(t, pdu, false)
			},
		},
		{
			name: "UEContextReleaseCompleteWithDiagnostics",
			wantHex: "2029002f000005000a40032001c800554002007b0079400880f8c000020a1194003c000300000a" +
				"001340087829000010000a00",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeUEContextRelease,
			build: func() ([]byte, error) {
				return BuildUEContextReleaseComplete(
					testRanUE(), testCriticalityDiagnostics(ngap.ProcedureCodeUEContextRelease),
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validateUEContextReleaseComplete(t, pdu, true)
			},
		},
		{
			name:          "UEContextReleaseRequest",
			wantHex:       "002a401d000004000a00032001c800550002007b0085000300000a000f40020000",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeUEContextReleaseRequest,
			build: func() ([]byte, error) {
				return BuildUEContextReleaseRequest(testRanUE(), cause)
			},
		},
		{
			name:          "InitialUEMessageWithoutOptionalIEs",
			wantHex:       "000f402a00000500550002007b00260007067e00410102030079000880f8c000020a1194005a4001180070400100",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeInitialUEMessage,
			build: func() ([]byte, error) {
				return BuildInitialUEMessage(testRanUE(), testNASPDU, nil)
			},
		},
		{
			name: "InitialUEMessageWithGUTIAndAllowedNSSAI",
			wantHex: "000f404400000800550002007b00260007067e00410102030079000880f8c000020a1194" +
				"005a400118001a00070080c0010203040003400202000070400100000000050201010203",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeInitialUEMessage,
			build: func() ([]byte, error) {
				ranUe := testRanUE()
				ranUe.Guti = "2089301020301020304"
				return BuildInitialUEMessage(ranUe, testNASPDU, testAllowedNSSAI())
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				msg, ok := pdu.(*ngap.InitialUEMessage)
				require.True(t, ok)
				require.NotNil(t, msg.AllowedNSSAI)
			},
		},
		{
			name:          "UplinkNASTransport",
			wantHex:       "002e4027000004000a00032001c800550002007b00260007067e00410102030079400880f8c000020a1194",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeUplinkNASTransport,
			build: func() ([]byte, error) {
				return BuildUplinkNASTransport(testRanUE(), testNASPDU)
			},
		},
		{
			name:          "NASNonDeliveryIndication",
			wantHex:       "00134021000004000a00032001c800550002007b00264007067e0041010203000f40020000",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeNASNonDeliveryIndication,
			build: func() ([]byte, error) {
				return BuildNASNonDeliveryIndication(testRanUE(), testNASPDU, cause)
			},
		},
		{
			name:          "PDUSessionResourceSetupResponseWithoutDiagnostics",
			wantHex:       "201d0026000004000a40032001c800554002007b004b400700000a03010203003a400700000a03010203",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodePDUSessionResourceSetup,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceSetupResponse(
					testRanUE(), testSetupListSURes(), testFailedSetupListSURes(), nil,
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validatePDUSessionResourceSetupResponse(t, pdu, false)
			},
		},
		{
			name: "PDUSessionResourceSetupResponseWithDiagnostics",
			wantHex: "201d0032000005000a40032001c800554002007b004b400700000a03010203003a400700000a03010203" +
				"00134008781d000010000a00",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodePDUSessionResourceSetup,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceSetupResponse(
					testRanUE(),
					testSetupListSURes(),
					testFailedSetupListSURes(),
					testCriticalityDiagnostics(ngap.ProcedureCodePDUSessionResourceSetup),
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validatePDUSessionResourceSetupResponse(t, pdu, true)
			},
		},
		{
			name: "PDUSessionResourceModifyResponseWithoutDiagnostics",
			wantHex: "201a0032000005000a40032001c800554002007b0041400700000a03010203" +
				"0036400700000a030102030079400880f8c000020a1194",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodePDUSessionResourceModify,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceModifyResponse(
					testRanUE(), testModifyListModRes(), testFailedModifyListModRes(), nil,
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validatePDUSessionResourceModifyResponse(t, pdu, false)
			},
		},
		{
			name: "PDUSessionResourceModifyResponseWithDiagnostics",
			wantHex: "201a003e000006000a40032001c800554002007b0041400700000a03010203" +
				"0036400700000a030102030079400880f8c000020a119400134008781a000010000a00",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodePDUSessionResourceModify,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceModifyResponse(
					testRanUE(),
					testModifyListModRes(),
					testFailedModifyListModRes(),
					testCriticalityDiagnostics(ngap.ProcedureCodePDUSessionResourceModify),
				)
			},
			validate: func(t *testing.T, pdu ngap.Message) {
				validatePDUSessionResourceModifyResponse(t, pdu, true)
			},
		},
		{
			name:          "PDUSessionResourceModifyIndication",
			wantHex:       "001b001b000003000a00032001c800550002007b003f000700000a03010203",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodePDUSessionResourceModifyIndication,
			build: func() ([]byte, error) {
				transfer := aper.OctetString(testTransferBytes())
				item := ngapType.PDUSessionResourceModifyItemModInd{
					PDUSessionID: &ngapType.PDUSessionID{Value: testPDUSessionID},
					PDUSessionResourceModifyIndicationTransfer: &transfer,
				}
				return BuildPDUSessionResourceModifyIndication(testRanUE(), []ngapType.PDUSessionResourceModifyItemModInd{item})
			},
		},
		{
			name: "PDUSessionResourceNotify",
			wantHex: "001e4032000005000a00032001c800550002007b0042000700000a03010203" +
				"0043400700000a030102030079400880f8c000020a1194",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodePDUSessionResourceNotify,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceNotify(testRanUE(), testNotifyList(), testReleasedListNot())
			},
		},
		{
			name:          "PDUSessionResourceReleaseResponse",
			wantHex:       "201c0027000004000a40032001c800554002007b0046400700000a030102030079400880f8c000020a1194",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodePDUSessionResourceRelease,
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceReleaseResponse(testRanUE(), testReleasedListRelRes(), nil)
			},
		},
		{
			name:          "ErrorIndication",
			wantHex:       "00094016000003000a40032001c800554002007b000f40020000",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeErrorIndication,
			build: func() ([]byte, error) {
				amfID, ranID := testAmfUeNgapID, testRanUeNgapID
				return BuildErrorIndication(&amfID, &ranID, &cause, nil)
			},
		},
		{
			name:          "UERadioCapabilityCheckResponse",
			wantHex:       "202b0015000003000a40032001c800554002007b001e000140",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeUERadioCapabilityCheck,
			build: func() ([]byte, error) {
				return BuildUERadioCapabilityCheckResponse(testRanUE(), nil)
			},
		},
		{
			name:          "AMFConfigurationUpdateAcknowledge",
			wantHex:       "2000001b00000200054007000f80c633640a00044009000f80c633640b0000",
			wantPresent:   ngap.MessageTypeSuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeAMFConfigurationUpdate,
			build: func() ([]byte, error) {
				return BuildAMFConfigurationUpdateAcknowledge(testAMFTNLAssociationSetupList(), testTNLAssociationList(), nil)
			},
		},
		{
			name:          "AMFConfigurationUpdateFailure",
			wantHex:       "4000000e000002000f40020000006b400120",
			wantPresent:   ngap.MessageTypeUnsuccessfulOutcome,
			wantProcedure: ngap.ProcedureCodeAMFConfigurationUpdate,
			build: func() ([]byte, error) {
				timeToWait := &ngapType.TimeToWait{Value: ngapType.TimeToWaitPresentV5s}
				return BuildAMFConfigurationUpdateFailure(cause, timeToWait, nil)
			},
		},
		{
			name:          "RANConfigurationUpdate",
			wantHex:       "0023002a0000020052400f0600667265653547432d4e334957460066001000000000010002f83900001008010203",
			wantPresent:   ngap.MessageTypeInitiatingMessage,
			wantProcedure: ngap.ProcedureCodeRANConfigurationUpdate,
			build: func() ([]byte, error) {
				return BuildRANConfigurationUpdate("free5GC-N3IWF", testSupportedTAList())
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := assertGoldenBytes(t, test.wantHex, test.build)
			pdu, err := ngap.Parse(got)
			require.NoError(t, err)
			require.Equal(t, test.wantPresent, pdu.MessageType())
			require.Equal(t, test.wantProcedure, pdu.ProcedureCode())
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
		require.NoError(t, ngapType.UnmarshalBinary(got, &decoded))
		tunnel, ok := decoded.DLQosFlowPerTNLInformation.UPTransportLayerInformation.Choice.(*ngapType.GTPTunnel)
		require.True(t, ok)
		gotTEID := tunnel.GTPTEID.Value
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
		require.NoError(t, ngapType.UnmarshalBinary(got, &decoded))
		_, ok := decoded.Cause.Choice.(*ngapType.CauseRadioNetwork)
		require.True(t, ok)
	})

	t.Run("PDUSessionResourceModifyResponseTransfer", func(t *testing.T) {
		build := func() ([]byte, error) {
			responseList := &ngapType.QosFlowAddOrModifyResponseList{
				List: []ngapType.QosFlowAddOrModifyResponseItem{{
					QosFlowIdentifier: &ngapType.QosFlowIdentifier{Value: 1},
				}},
			}
			failedList := &ngapType.QosFlowListWithCause{
				List: []ngapType.QosFlowWithCauseItem{{
					QosFlowIdentifier: &ngapType.QosFlowIdentifier{Value: 9},
					Cause:             &cause,
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
		require.NoError(t, ngapType.UnmarshalBinary(got, &decoded))
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
		require.NoError(t, ngapType.UnmarshalBinary(got, &decoded))
		_, ok := decoded.Cause.Choice.(*ngapType.CauseRadioNetwork)
		require.True(t, ok)
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

func requireDiagnosticsPresence(
	t *testing.T,
	diagnostics *ngapType.CriticalityDiagnostics,
	want bool,
) {
	t.Helper()
	if want {
		require.NotNil(t, diagnostics)
		requireCriticalityDiagnostics(t, diagnostics, diagnostics.ProcedureCode.Value)
	} else {
		require.Nil(t, diagnostics)
	}
}

func validateInitialContextSetupResponse(t *testing.T, parsed ngap.Message, want bool) {
	t.Helper()
	msg, ok := parsed.(*ngap.InitialContextSetupResponse)
	require.True(t, ok)
	require.NotNil(t, msg.AMFUENGAPID)
	require.NotNil(t, msg.RANUENGAPID)
	requireDiagnosticsPresence(t, msg.CriticalityDiagnostics, want)
}

func validateInitialContextSetupFailure(t *testing.T, parsed ngap.Message, want bool) {
	t.Helper()
	msg, ok := parsed.(*ngap.InitialContextSetupFailure)
	require.True(t, ok)
	require.NotNil(t, msg.Cause)
	requireDiagnosticsPresence(t, msg.CriticalityDiagnostics, want)
}

func validateUEContextModificationResponse(t *testing.T, parsed ngap.Message, want bool) {
	t.Helper()
	msg, ok := parsed.(*ngap.UEContextModificationResponse)
	require.True(t, ok)
	requireDiagnosticsPresence(t, msg.CriticalityDiagnostics, want)
}

func validateUEContextModificationFailure(t *testing.T, parsed ngap.Message, want bool) {
	t.Helper()
	msg, ok := parsed.(*ngap.UEContextModificationFailure)
	require.True(t, ok)
	require.NotNil(t, msg.Cause)
	requireDiagnosticsPresence(t, msg.CriticalityDiagnostics, want)
}

func validateUEContextReleaseComplete(t *testing.T, parsed ngap.Message, want bool) {
	t.Helper()
	msg, ok := parsed.(*ngap.UEContextReleaseComplete)
	require.True(t, ok)
	requireDiagnosticsPresence(t, msg.CriticalityDiagnostics, want)
}

func validatePDUSessionResourceSetupResponse(t *testing.T, parsed ngap.Message, want bool) {
	t.Helper()
	msg, ok := parsed.(*ngap.PDUSessionResourceSetupResponse)
	require.True(t, ok)
	requireDiagnosticsPresence(t, msg.CriticalityDiagnostics, want)
}

func validatePDUSessionResourceModifyResponse(t *testing.T, parsed ngap.Message, want bool) {
	t.Helper()
	msg, ok := parsed.(*ngap.PDUSessionResourceModifyResponse)
	require.True(t, ok)
	requireDiagnosticsPresence(t, msg.CriticalityDiagnostics, want)
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
	require.NotNil(t, diagnostics.ProcedureCriticality)
	require.NotNil(t, diagnostics.IEsCriticalityDiagnostics)
	require.Len(t, diagnostics.IEsCriticalityDiagnostics.List, 1)
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
		CausePresentRadioNetwork,
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
					IECriticality: &ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
					IEID:          &ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
					TypeOfError:   &ngapType.TypeOfError{Value: ngapType.TypeOfErrorPresentNotUnderstood},
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
			SNSSAI: &ngapType.SNSSAI{
				SST: &ngapType.SST{Value: aper.OctetString{0x01}},
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
	transfer := aper.OctetString(testTransferBytes())
	item := ngapType.PDUSessionResourceNotifyItem{
		PDUSessionID:                     &ngapType.PDUSessionID{Value: testPDUSessionID},
		PDUSessionResourceNotifyTransfer: &transfer,
	}
	return &ngapType.PDUSessionResourceNotifyList{List: []ngapType.PDUSessionResourceNotifyItem{item}}
}

func testReleasedListNot() *ngapType.PDUSessionResourceReleasedListNot {
	transfer := aper.OctetString(testTransferBytes())
	item := ngapType.PDUSessionResourceReleasedItemNot{
		PDUSessionID:                             &ngapType.PDUSessionID{Value: testPDUSessionID},
		PDUSessionResourceNotifyReleasedTransfer: &transfer,
	}
	return &ngapType.PDUSessionResourceReleasedListNot{List: []ngapType.PDUSessionResourceReleasedItemNot{item}}
}

func testReleasedListRelRes() ngapType.PDUSessionResourceReleasedListRelRes {
	transfer := aper.OctetString(testTransferBytes())
	item := ngapType.PDUSessionResourceReleasedItemRelRes{
		PDUSessionID: &ngapType.PDUSessionID{Value: testPDUSessionID},
		PDUSessionResourceReleaseResponseTransfer: &transfer,
	}
	return ngapType.PDUSessionResourceReleasedListRelRes{
		List: []ngapType.PDUSessionResourceReleasedItemRelRes{item},
	}
}

func testUPTransportLayerInformation(ipAddress string, teid []byte) *ngapType.UPTransportLayerInformation {
	address := util.IPAddressToNgap(ipAddress, "")
	return &ngapType.UPTransportLayerInformation{
		Choice: &ngapType.GTPTunnel{
			TransportLayerAddress: &address,
			GTPTEID:               &ngapType.GTPTEID{Value: teid},
		},
	}
}

func testCPTransportLayerInformation(ipAddress string) *ngapType.CPTransportLayerInformation {
	address := util.IPAddressToNgap(ipAddress, "")
	return &ngapType.CPTransportLayerInformation{
		Choice: &address,
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
			Cause: func() *ngapType.Cause {
				cause := testCause()
				return &cause
			}(),
		}},
	}
}
