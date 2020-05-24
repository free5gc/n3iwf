package message

type Event int

const (
	EventN1UDPMessage Event = iota
	EventN1TunnelCPMessage
	EventN1TunnelUPMessage
	EventSCTPConnectMessage
	EventNGAPMessage
	EventGTPMessage
	EventTimerSendRanConfigUpdateMessage
)
