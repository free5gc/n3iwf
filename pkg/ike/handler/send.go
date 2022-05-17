package handler

import (
	"net"

	"github.com/free5gc/n3iwf/pkg/context"
	ike_message "github.com/free5gc/n3iwf/pkg/ike/message"
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
	deletePayload.BuildDeletePayload(1, 0, 0, nil)
	SendUEInformationExchange(n3iwfUe, deletePayload)
}
