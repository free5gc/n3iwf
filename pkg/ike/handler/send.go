package handler

import (
	"encoding/binary"
	"net"
	"runtime/debug"
	"time"

	ngap_message "github.com/free5gc/n3iwf/internal/ngap/message"
	"github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	ike_message "github.com/free5gc/n3iwf/pkg/ike/message"
	"github.com/free5gc/ngap/ngapType"
)

func SendIKEMessageToUE(udpConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	ikeLog.Trace("Send IKE message to UE")
	ikeLog.Trace("Encoding...")
	pkt, err := message.Encode()
	if err != nil {
		ikeLog.Errorln(err)
		return
	}
	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if srcAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		pkt = append(prependZero, pkt...)
	}

	ikeLog.Trace("Sending...")
	n, err := udpConn.WriteToUDP(pkt, dstAddr)
	if err != nil {
		ikeLog.Error(err)
		return
	}
	if n != len(pkt) {
		ikeLog.Errorf("Not all of the data is sent. Total length: %d. Sent: %d.", len(pkt), n)
		return
	}
}

func SendUEInformationExchange(
	n3iwfUe *context.N3IWFUe, payload ike_message.IKEPayloadContainer) {
	ikeSecurityAssociation := n3iwfUe.N3IWFIKESecurityAssociation
	responseIKEMessage := new(ike_message.IKEMessage)

	// Build IKE message
	responseIKEMessage.BuildIKEHeader(ikeSecurityAssociation.RemoteSPI,
		ikeSecurityAssociation.LocalSPI, ike_message.INFORMATIONAL, 0,
		ikeSecurityAssociation.ResponderMessageID)
	if payload != nil { // This message isn't a DPD message
		if err := EncryptProcedure(ikeSecurityAssociation, payload, responseIKEMessage); err != nil {
			ikeLog.Errorf("Encrypting IKE message failed: %+v", err)
			return
		}
	}
	SendIKEMessageToUE(n3iwfUe.IKEConnection.Conn, n3iwfUe.IKEConnection.N3IWFAddr,
		n3iwfUe.IKEConnection.UEAddr, responseIKEMessage)
}

func SendIKEDeleteRequest(n3iwfUe *context.N3IWFUe) {
	var deletePayload ike_message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(ike_message.TypeIKE, 0, 0, nil)
	SendUEInformationExchange(n3iwfUe, deletePayload)
}

func SendChildSADeleteRequest(n3iwfUe *context.N3IWFUe, relaseList []ngapType.PDUSessionResourceReleasedItemRelRes) {
	var deleteSPIs []byte
	spiLen := uint16(0)
	for _, releaseItem := range relaseList {
		for _, childSA := range n3iwfUe.N3IWFChildSecurityAssociation {
			if childSA.PDUSessionIds[0] == releaseItem.PDUSessionID.Value {
				spiByte := make([]byte, 4)
				binary.BigEndian.PutUint32(spiByte, uint32(childSA.XfrmStateList[0].Spi))
				deleteSPIs = append(deleteSPIs, spiByte...)
				spiLen += 1
				if err := n3iwfUe.DeleteChildSA(childSA); err != nil {
					ikeLog.Errorf("Delete Child SA error : %+v", err)
				}
			}
		}
	}

	var deletePayload ike_message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(ike_message.TypeESP, 4, spiLen, deleteSPIs)
	SendUEInformationExchange(n3iwfUe, deletePayload)
}

func StartDPD(n3iwfUe *context.N3IWFUe) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ikeLog.Errorf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	n3iwfUe.N3IWFIKESecurityAssociation.IKESAClosedCh = make(chan struct{})

	liveness := factory.N3iwfConfig.Configuration.LivenessCheck
	if liveness.Enable {
		timer := time.NewTicker(liveness.TransFreq)
		for {
			select {
			case <-n3iwfUe.N3IWFIKESecurityAssociation.IKESAClosedCh:
				close(n3iwfUe.N3IWFIKESecurityAssociation.IKESAClosedCh)
				timer.Stop()
				return
			case <-timer.C:
				SendUEInformationExchange(n3iwfUe, nil)
				var DPDReqRetransTime time.Duration = 2 * time.Second
				n3iwfUe.N3IWFIKESecurityAssociation.DPDReqRetransTimer = context.NewDPDPeriodicTimer(DPDReqRetransTime,
					liveness.MaxRetryTimes, n3iwfUe.N3IWFIKESecurityAssociation, func() {
						ikeLog.Errorf("UE is down")
						cause := ngap_message.BuildCause(ngapType.CausePresentRadioNetwork,
							ngapType.CauseRadioNetworkPresentRadioConnectionWithUeLost)
						ngap_message.SendUEContextReleaseRequest(n3iwfUe.AMF, n3iwfUe, *cause)
						n3iwfUe.N3IWFIKESecurityAssociation.DPDReqRetransTimer = nil
						timer.Stop()
					})
			}
		}
	}
}
