package ngap

import (
	"runtime/debug"

	"github.com/free5gc/n3iwf/internal/logger"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/sctp"
)

func (s *Server) NGAPDispatch(conn *sctp.SCTPConn, encoded []byte) {
	ngapLog := logger.NgapLog
	defer func() {
		if recovered := recover(); recovered != nil {
			ngapLog.Fatalf("panic: %v\n%s", recovered, string(debug.Stack()))
		}
	}()

	sctpAddr := conn.RemoteAddr().String()
	amf, _ := s.Context().AMFPoolLoad(sctpAddr)
	parsed, err := ngapMessage.Parse(encoded)
	if err != nil {
		ngapLog.Errorf("NGAP decode error: %+v", err)
		return
	}
	if !isHandledInboundMessage(parsed) {
		ngapLog.Warnf("Not implemented NGAP message type=%T messageType=%d procedureCode=%d",
			parsed, parsed.MessageType(), parsed.ProcedureCode())
		return
	}

	switch msg := parsed.(type) {
	case *ngapMessage.NGReset:
		s.HandleNGReset(amf, msg)
	case *ngapMessage.InitialContextSetupRequest:
		s.HandleInitialContextSetupRequest(amf, msg)
	case *ngapMessage.UEContextModificationRequest:
		s.HandleUEContextModificationRequest(amf, msg)
	case *ngapMessage.UEContextReleaseCommand:
		s.HandleUEContextReleaseCommand(amf, msg)
	case *ngapMessage.DownlinkNASTransport:
		s.HandleDownlinkNASTransport(amf, msg)
	case *ngapMessage.PDUSessionResourceSetupRequest:
		s.HandlePDUSessionResourceSetupRequest(amf, msg)
	case *ngapMessage.PDUSessionResourceModifyRequest:
		s.HandlePDUSessionResourceModifyRequest(amf, msg)
	case *ngapMessage.PDUSessionResourceReleaseCommand:
		s.HandlePDUSessionResourceReleaseCommand(amf, msg)
	case *ngapMessage.ErrorIndication:
		s.HandleErrorIndication(amf, msg)
	case *ngapMessage.UERadioCapabilityCheckRequest:
		s.HandleUERadioCapabilityCheckRequest(amf, msg)
	case *ngapMessage.AMFConfigurationUpdate:
		s.HandleAMFConfigurationUpdate(amf, msg)
	case *ngapMessage.DownlinkRANConfigurationTransfer:
		s.HandleDownlinkRANConfigurationTransfer(msg)
	case *ngapMessage.DownlinkRANStatusTransfer:
		s.HandleDownlinkRANStatusTransfer(msg)
	case *ngapMessage.AMFStatusIndication:
		s.HandleAMFStatusIndication(msg)
	case *ngapMessage.LocationReportingControl:
		s.HandleLocationReportingControl(msg)
	case *ngapMessage.UETNLABindingReleaseRequest:
		s.HandleUETNLAReleaseRequest(msg)
	case *ngapMessage.OverloadStart:
		s.HandleOverloadStart(amf, msg)
	case *ngapMessage.OverloadStop:
		s.HandleOverloadStop(amf, msg)
	case *ngapMessage.NGSetupResponse:
		s.HandleNGSetupResponse(sctpAddr, conn, msg)
	case *ngapMessage.NGResetAcknowledge:
		s.HandleNGResetAcknowledge(amf, msg)
	case *ngapMessage.PDUSessionResourceModifyConfirm:
		s.HandlePDUSessionResourceModifyConfirm(amf, msg)
	case *ngapMessage.RANConfigurationUpdateAcknowledge:
		s.HandleRANConfigurationUpdateAcknowledge(amf, msg)
	case *ngapMessage.NGSetupFailure:
		s.HandleNGSetupFailure(sctpAddr, conn, msg)
	case *ngapMessage.RANConfigurationUpdateFailure:
		s.HandleRANConfigurationUpdateFailure(amf, msg)
	default:
		ngapLog.Warnf("Not implemented NGAP message type=%T messageType=%d procedureCode=%d",
			parsed, parsed.MessageType(), parsed.ProcedureCode())
	}
}

func isHandledInboundMessage(parsed ngapMessage.Message) bool {
	switch parsed.(type) {
	case *ngapMessage.NGReset,
		*ngapMessage.InitialContextSetupRequest,
		*ngapMessage.UEContextModificationRequest,
		*ngapMessage.UEContextReleaseCommand,
		*ngapMessage.DownlinkNASTransport,
		*ngapMessage.PDUSessionResourceSetupRequest,
		*ngapMessage.PDUSessionResourceModifyRequest,
		*ngapMessage.PDUSessionResourceReleaseCommand,
		*ngapMessage.ErrorIndication,
		*ngapMessage.UERadioCapabilityCheckRequest,
		*ngapMessage.AMFConfigurationUpdate,
		*ngapMessage.DownlinkRANConfigurationTransfer,
		*ngapMessage.DownlinkRANStatusTransfer,
		*ngapMessage.AMFStatusIndication,
		*ngapMessage.LocationReportingControl,
		*ngapMessage.UETNLABindingReleaseRequest,
		*ngapMessage.OverloadStart,
		*ngapMessage.OverloadStop,
		*ngapMessage.NGSetupResponse,
		*ngapMessage.NGResetAcknowledge,
		*ngapMessage.PDUSessionResourceModifyConfirm,
		*ngapMessage.RANConfigurationUpdateAcknowledge,
		*ngapMessage.NGSetupFailure,
		*ngapMessage.RANConfigurationUpdateFailure:
		return true
	default:
		return false
	}
}
