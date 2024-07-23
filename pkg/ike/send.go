package ike

import (
	"encoding/binary"
	"net"

	"github.com/free5gc/n3iwf/internal/logger"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/ike/message"
	"github.com/free5gc/n3iwf/pkg/ike/security"
)

func SendIKEMessageToUE(
	udpConn *net.UDPConn,
	srcAddr, dstAddr *net.UDPAddr,
	message *message.IKEMessage,
) {
	ikeLog := logger.IKELog
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
	ikeUe *n3iwf_context.N3IWFIkeUe,
	payload message.IKEPayloadContainer,
) {
	ikeLog := logger.IKELog
	ikeSA := ikeUe.N3IWFIKESecurityAssociation
	responseIKEMessage := new(message.IKEMessage)

	// Build IKE message
	responseIKEMessage.BuildIKEHeader(
		ikeSA.RemoteSPI, ikeSA.LocalSPI,
		message.INFORMATIONAL, 0,
		ikeSA.ResponderMessageID)
	if payload != nil { // This message isn't a DPD message
		err := security.EncryptProcedure(
			ikeSA, payload, responseIKEMessage)
		if err != nil {
			ikeLog.Errorf("Encrypting IKE message failed: %+v", err)
			return
		}
	}
	SendIKEMessageToUE(
		ikeUe.IKEConnection.Conn, ikeUe.IKEConnection.N3IWFAddr,
		ikeUe.IKEConnection.UEAddr, responseIKEMessage)
}

func SendIKEDeleteRequest(n3iwfCtx *n3iwf_context.N3IWFContext, localSPI uint64) {
	ikeLog := logger.IKELog
	ikeUe, ok := n3iwfCtx.IkeUePoolLoad(localSPI)
	if !ok {
		ikeLog.Errorf("Cannot get IkeUE from SPI : %+v", localSPI)
		return
	}

	var deletePayload message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(message.TypeIKE, 0, 0, nil)
	SendUEInformationExchange(ikeUe, deletePayload)
}

func SendChildSADeleteRequest(
	ikeUe *n3iwf_context.N3IWFIkeUe,
	relaseList []int64,
) {
	ikeLog := logger.IKELog
	var deleteSPIs []byte
	spiLen := uint16(0)
	for _, releaseItem := range relaseList {
		for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
			if childSA.PDUSessionIds[0] == releaseItem {
				spiByte := make([]byte, 4)
				binary.BigEndian.PutUint32(spiByte, uint32(childSA.XfrmStateList[0].Spi))
				deleteSPIs = append(deleteSPIs, spiByte...)
				spiLen += 1
				err := ikeUe.DeleteChildSA(childSA)
				if err != nil {
					ikeLog.Errorf("Delete Child SA error : %v", err)
				}
			}
		}
	}

	var deletePayload message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(message.TypeESP, 4, spiLen, deleteSPIs)
	SendUEInformationExchange(ikeUe, deletePayload)
}
