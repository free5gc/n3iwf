package handler

import (
	"encoding/binary"
	"net"
	"runtime/debug"
	"time"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	ike_message "github.com/free5gc/n3iwf/pkg/ike/message"
)

func SendIKEMessageToUE(udpConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	logger.IKELog.Trace("Send IKE message to UE")
	logger.IKELog.Trace("Encoding...")
	pkt, err := message.Encode()
	if err != nil {
		logger.IKELog.Errorln(err)
		return
	}
	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if srcAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		pkt = append(prependZero, pkt...)
	}

	logger.IKELog.Trace("Sending...")
	n, err := udpConn.WriteToUDP(pkt, dstAddr)
	if err != nil {
		logger.IKELog.Error(err)
		return
	}
	if n != len(pkt) {
		logger.IKELog.Errorf("Not all of the data is sent. Total length: %d. Sent: %d.", len(pkt), n)
		return
	}
}

func SendUEInformationExchange(
	ikeUe *context.N3IWFIkeUe, payload ike_message.IKEPayloadContainer,
) {
	ikeSecurityAssociation := ikeUe.N3IWFIKESecurityAssociation
	responseIKEMessage := new(ike_message.IKEMessage)

	// Build IKE message
	responseIKEMessage.BuildIKEHeader(ikeSecurityAssociation.RemoteSPI,
		ikeSecurityAssociation.LocalSPI, ike_message.INFORMATIONAL, 0,
		ikeSecurityAssociation.ResponderMessageID)
	if payload != nil { // This message isn't a DPD message
		if err := EncryptProcedure(ikeSecurityAssociation, payload, responseIKEMessage); err != nil {
			logger.IKELog.Errorf("Encrypting IKE message failed: %+v", err)
			return
		}
	}
	SendIKEMessageToUE(ikeUe.IKEConnection.Conn, ikeUe.IKEConnection.N3IWFAddr,
		ikeUe.IKEConnection.UEAddr, responseIKEMessage)
}

func SendIKEDeleteRequest(localSPI uint64) {
	ikeUe, ok := context.N3IWFSelf().IkeUePoolLoad(localSPI)
	if !ok {
		logger.IKELog.Errorf("Cannot get IkeUE from SPI : %+v", localSPI)
		return
	}

	var deletePayload ike_message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(ike_message.TypeIKE, 0, 0, nil)
	SendUEInformationExchange(ikeUe, deletePayload)
}

func SendChildSADeleteRequest(ikeUe *context.N3IWFIkeUe, relaseList []int64) {
	var deleteSPIs []byte
	spiLen := uint16(0)
	for _, releaseItem := range relaseList {
		for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
			if childSA.PDUSessionIds[0] == releaseItem {
				spiByte := make([]byte, 4)
				binary.BigEndian.PutUint32(spiByte, uint32(childSA.XfrmStateList[0].Spi))
				deleteSPIs = append(deleteSPIs, spiByte...)
				spiLen += 1
				if err := ikeUe.DeleteChildSA(childSA); err != nil {
					logger.IKELog.Errorf("Delete Child SA error : %+v", err)
				}
			}
		}
	}

	var deletePayload ike_message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(ike_message.TypeESP, 4, spiLen, deleteSPIs)
	SendUEInformationExchange(ikeUe, deletePayload)
}

func StartDPD(ikeUe *context.N3IWFIkeUe) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.IKELog.Errorf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	ikeUe.N3IWFIKESecurityAssociation.IKESAClosedCh = make(chan struct{})

	n3iwfSelf := context.N3IWFSelf()

	liveness := factory.N3iwfConfig.Configuration.LivenessCheck
	if liveness.Enable {
		ikeUe.N3IWFIKESecurityAssociation.IsUseDPD = true
		timer := time.NewTicker(liveness.TransFreq)
		for {
			select {
			case <-ikeUe.N3IWFIKESecurityAssociation.IKESAClosedCh:
				close(ikeUe.N3IWFIKESecurityAssociation.IKESAClosedCh)
				timer.Stop()
				return
			case <-timer.C:
				SendUEInformationExchange(ikeUe, nil)
				var DPDReqRetransTime time.Duration = 2 * time.Second
				ikeUe.N3IWFIKESecurityAssociation.DPDReqRetransTimer = context.NewDPDPeriodicTimer(DPDReqRetransTime,
					liveness.MaxRetryTimes, ikeUe.N3IWFIKESecurityAssociation, func() {
						logger.IKELog.Errorf("UE is down")
						ranNgapId, ok := n3iwfSelf.NgapIdLoad(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
						if !ok {
							logger.IKELog.Infof("Cannot find ranNgapId form SPI : %+v", ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
							return
						}

						n3iwfSelf.NGAPServer.RcvEventCh <- context.NewSendUEContextReleaseRequestEvt(
							ranNgapId, context.ErrRadioConnWithUeLost,
						)

						ikeUe.N3IWFIKESecurityAssociation.DPDReqRetransTimer = nil
						timer.Stop()
					})
			}
		}
	}
}
