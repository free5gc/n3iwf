package n3iwf_message

import "net"

type HandlerMessage struct {
	Event    Event
	Addr     *net.UDPAddr // used only when Event == EventN1UDPMessage
	SCTPAddr string       // used when Event == EventNGAPMessage || Event == EventSCTPConnectMessage
	Value    interface{}
}
