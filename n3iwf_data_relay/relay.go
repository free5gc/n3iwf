package n3iwf_data_relay

import (
	"context"
	"errors"
	"gofree5gc/src/n3iwf/logger"
	"gofree5gc/src/n3iwf/n3iwf_context"
	"gofree5gc/src/n3iwf/n3iwf_handler/n3iwf_message"
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
	gtpv1 "github.com/wmnsk/go-gtp/v1"
	"golang.org/x/net/ipv4"
)

var relayLog *logrus.Entry

func init() {
	relayLog = logger.RelayLog
}

func listenRawSocket(rawSocket *ipv4.RawConn) {
	defer rawSocket.Close()

	buffer := make([]byte, 1500)

	for {
		ipHeader, ipPayload, _, err := rawSocket.ReadFrom(buffer)
		if err != nil {
			relayLog.Errorf("Error read from raw socket: %+v", err)
			return
		}

		msg := n3iwf_message.HandlerMessage{
			Event:     n3iwf_message.EventN1TunnelUPMessage,
			UEInnerIP: ipHeader.Src.String(),
			Value:     ipPayload[4:],
		}

		n3iwf_message.SendMessage(msg)
	}

}

// ListenN1UPTraffic bind and listen raw socket on N3IWF N1 interface
// with UP_IP_ADDRESS, catching GRE encapsulated packets and send it
// to N3IWF handler
func ListenN1UPTraffic() error {
	// Local IPSec address
	n3iwfSelf := n3iwf_context.N3IWFSelf()
	listenAddr := n3iwfSelf.IPSecGatewayAddress

	// Setup raw socket
	// This raw socket will only capture GRE encapsulated packet
	connection, err := net.ListenPacket("ip4:gre", listenAddr)
	if err != nil {
		relayLog.Errorf("Error setting listen socket on %s: %+v", listenAddr, err)
		return errors.New("ListenPacket failed")
	}
	rawSocket, err := ipv4.NewRawConn(connection)
	if err != nil {
		relayLog.Errorf("Error opening raw socket on %s: %+v", listenAddr, err)
		return errors.New("NewRawConn failed")
	}

	n3iwfSelf.N1RawSocket = rawSocket
	go listenRawSocket(rawSocket)

	return nil
}

// ForwardUPTrafficFromN1 forward user plane packets from N1 to UPF,
// with GTP header encapsulated
func ForwardUPTrafficFromN1(ue *n3iwf_context.N3IWFUe, packet []byte) {
	if len(ue.GTPConnection) == 0 {
		relayLog.Error("This UE doesn't have any available user plane session")
		return
	}

	gtpConnection := ue.GTPConnection[0]

	userPlaneConnection := gtpConnection.UserPlaneConnection

	n, err := userPlaneConnection.WriteToGTP(gtpConnection.OutgoingTEID, packet, gtpConnection.RemoteAddr)
	if err != nil {
		relayLog.Errorf("Write to UPF failed: %+v", err)
		if err == gtpv1.ErrConnNotOpened {
			relayLog.Error("The connection has been closed")
			// TODO: Release the GTP resource
		}
		return
	} else {
		relayLog.Tracef("Wrote %d bytes", n)
		return
	}
}

// SetupGTPTunnelWithUPF set up GTP connection with UPF
// return *gtpv1.UPlaneConn, net.Addr and error
func SetupGTPTunnelWithUPF(upfIPAddr string) (*gtpv1.UPlaneConn, net.Addr, error) {
	n3iwfSelf := n3iwf_context.N3IWFSelf()

	// Set up GTP connection
	upfUDPAddr := upfIPAddr + ":2152"

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", upfUDPAddr)
	if err != nil {
		relayLog.Errorf("Resolve UDP address %s failed: %+v", upfUDPAddr, err)
		return nil, nil, errors.New("Resolve Address Failed")
	}

	n3iwfUDPAddr := n3iwfSelf.GTPBindAddress + ":2152"

	localUDPAddr, err := net.ResolveUDPAddr("udp", n3iwfUDPAddr)
	if err != nil {
		relayLog.Errorf("Resolve UDP address %s failed: %+v", n3iwfUDPAddr, err)
		return nil, nil, errors.New("Resolve Address Failed")
	}

	context := context.TODO()

	// Dial to UPF
	userPlaneConnection, err := gtpv1.DialUPlane(context, localUDPAddr, remoteUDPAddr)
	if err != nil {
		relayLog.Errorf("Dial to UPF failed: %+v", err)
		return nil, nil, errors.New("Dial failed")
	}

	return userPlaneConnection, remoteUDPAddr, nil

}

func listenGTP(userPlaneConnection *gtpv1.UPlaneConn) {
	defer userPlaneConnection.Close()

	payload := make([]byte, 1500)

	for {
		n, _, teid, err := userPlaneConnection.ReadFromGTP(payload)
		if err != nil {
			relayLog.Errorf("Read from GTP failed: %+v", err)
			return
		}

		msg := n3iwf_message.HandlerMessage{
			Event: n3iwf_message.EventGTPMessage,
			TEID:  teid,
			Value: payload[:n],
		}

		n3iwf_message.SendMessage(msg)
	}

}

// ListenGTP binds and listens raw socket on N3IWF N3 interface,
// catching GTP packets and send it to N3IWF handler
func ListenGTP(userPlaneConnection *gtpv1.UPlaneConn) error {
	go listenGTP(userPlaneConnection)
	return nil
}

// ForwardUPTrafficFromN3 forward user plane packets from N3 to UE,
// with GRE header and new IP header encapsulated
func ForwardUPTrafficFromN3(ue *n3iwf_context.N3IWFUe, packet []byte) {
	// This is the IP header template for packets with GRE header encapsulated.
	// The remaining mandatory fields are Dst and TotalLen, which specified
	// the destination IP address and the packet total length.
	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0,
		Flags:    ipv4.DontFragment,
		FragOff:  0,
		TTL:      64,
		Protocol: syscall.IPPROTO_GRE,
	}

	// GRE header
	greHeader := []byte{0, 0, 8, 0}

	// UE IP
	ueInnerIP := net.ParseIP(ue.IPSecInnerIP)

	greEncapsulatedPacket := append(greHeader, packet...)
	packetTotalLength := 20 + len(greEncapsulatedPacket)

	ipHeader.Dst = ueInnerIP
	ipHeader.TotalLen = packetTotalLength

	n3iwfSelf := n3iwf_context.N3IWFSelf()
	rawSocket := n3iwfSelf.N1RawSocket

	// Send to UE
	if err := rawSocket.WriteTo(ipHeader, greEncapsulatedPacket, nil); err != nil {
		relayLog.Errorf("Write to raw socket failed: %+v", err)
		return
	}
}
