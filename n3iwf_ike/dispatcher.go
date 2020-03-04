package n3iwf_ike

import (
	"gofree5gc/src/n3iwf/logger"
	"gofree5gc/src/n3iwf/n3iwf_handler/n3iwf_message"
	"gofree5gc/src/n3iwf/n3iwf_ike/ike_handler"
	"gofree5gc/src/n3iwf/n3iwf_ike/ike_message"
	"gofree5gc/src/n3iwf/n3iwf_ike/udp_server"

	"github.com/sirupsen/logrus"
)

var ikeLog *logrus.Entry

func init() {
	ikeLog = logger.IKELog
}

func Dispatch(ueSendInfo *n3iwf_message.UDPSendInfoGroup, msg []byte) {
	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if ueSendInfo.ChannelID == udp_server.ChannelIDForPort4500 {
		for i := 0; i < 4; i++ {
			if msg[i] != 0 {
				ikeLog.Warn("[IKE] Received an IKE packet that does not prepend 4 bytes zero from UDP port 4500, this packet may be the UDP encapsulated ESP. The packet will not be handled.")
				return
			}
		}
		msg = msg[4:]
	}

	ikeMessage, err := ike_message.Decode(msg)
	if err != nil {
		ikeLog.Error(err)
		return
	}

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		ike_handler.HandleIKESAINIT(ueSendInfo, ikeMessage)
	case ike_message.IKE_AUTH:
		ike_handler.HandleIKEAUTH(ueSendInfo, ikeMessage)
	default:
		ikeLog.Warnf("Unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}

}
