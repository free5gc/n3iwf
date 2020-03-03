package ike_handler

import (
	"gofree5gc/src/n3iwf/n3iwf_handler/n3iwf_message"
	"gofree5gc/src/n3iwf/n3iwf_ike/ike_message"
	"gofree5gc/src/n3iwf/n3iwf_ike/udp_server"
)

func SendIKEMessageToUE(ueSendInfo *n3iwf_message.UDPSendInfoGroup, message *ike_message.IKEMessage) {
	ikeLog.Trace("[IKE] Send IKE message to UE")
	ikeLog.Trace("[IKE] Encoding...")
	pkt, err := ike_message.Encode(message)
	if err != nil {
		ikeLog.Errorln(err)
		return
	}
	ikeLog.Trace("[IKE] Sending...")
	udp_server.Send(ueSendInfo, pkt)
}
