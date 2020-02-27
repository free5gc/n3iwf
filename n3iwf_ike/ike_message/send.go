package ike_message

func SendIKEMessageToUE(ueSendInfo n3iwf_message.UDPSendInfoGroup, message *IKEMessage) {
	ikeLog.Trace("[IKE] Send IKE message to UE")
	ikeLog.Trace("[IKE] Encoding...")
	pkt, err := Encode(message)
	if err != nil {
		ikeLog.Errorln(err)
		return
	}
	ikeLog.Trace("[IKE] Sending...")
	udp_server.Send(ueSendInfo, pkt)
	return
}
