package ike

import (
	"net"
	"runtime/debug"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/ike/handler"
	ike_message "github.com/free5gc/n3iwf/pkg/ike/message"
)

func IkeDispatch(udpConn *net.UDPConn, localAddr, remoteAddr *net.UDPAddr, msg []byte) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.IKELog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if localAddr.Port == 4500 {
		for i := 0; i < 4; i++ {
			if msg[i] != 0 {
				logger.IKELog.Warn(
					"Received an IKE packet that does not prepend 4 bytes zero from UDP port 4500," +
						" this packet may be the UDP encapsulated ESP. The packet will not be handled.")
				return
			}
		}
		msg = msg[4:]
	}

	ikeMessage := new(ike_message.IKEMessage)

	err := ikeMessage.Decode(msg)
	if err != nil {
		logger.IKELog.Error(err)
		return
	}

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		handler.HandleIKESAINIT(udpConn, localAddr, remoteAddr, ikeMessage, msg)
	case ike_message.IKE_AUTH:
		handler.HandleIKEAUTH(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.CREATE_CHILD_SA:
		handler.HandleCREATECHILDSA(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.INFORMATIONAL:
		handler.HandleInformational(udpConn, localAddr, remoteAddr, ikeMessage)
	default:
		logger.IKELog.Warnf("Unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}
}
