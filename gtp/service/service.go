package service

import (
	"context"
	"errors"
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"
	gtp "github.com/wmnsk/go-gtp/gtpv1"
	gtpMessage "github.com/wmnsk/go-gtp/gtpv1/message"

	n3iwfContext "github.com/free5gc/n3iwf/context"
	"github.com/free5gc/n3iwf/logger"
)

var gtpLog *logrus.Entry

var gtpContext context.Context

func init() {
	gtpLog = logger.GTPLog
	gtpContext = context.TODO()
}

// SetupGTPTunnelWithUPF set up GTP connection with UPF
// return *gtp.UPlaneConn, net.Addr and error
func SetupGTPTunnelWithUPF(upfIPAddr string) (*gtp.UPlaneConn, net.Addr, error) {
	n3iwfSelf := n3iwfContext.N3IWFSelf()

	// Set up GTP connection
	upfUDPAddr := upfIPAddr + gtp.GTPUPort

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", upfUDPAddr)
	if err != nil {
		gtpLog.Errorf("Resolve UDP address %s failed: %+v", upfUDPAddr, err)
		return nil, nil, errors.New("Resolve Address Failed")
	}

	n3iwfUDPAddr := n3iwfSelf.GTPBindAddress + gtp.GTPUPort

	localUDPAddr, err := net.ResolveUDPAddr("udp", n3iwfUDPAddr)
	if err != nil {
		gtpLog.Errorf("Resolve UDP address %s failed: %+v", n3iwfUDPAddr, err)
		return nil, nil, errors.New("Resolve Address Failed")
	}

	// Dial to UPF
	userPlaneConnection, err := gtp.DialUPlane(gtpContext, localUDPAddr, remoteUDPAddr)
	if err != nil {
		gtpLog.Errorf("Dial to UPF failed: %+v", err)
		return nil, nil, errors.New("Dial failed")
	}

	// Overwrite T-PDU handler for supporting extension header containing QoS parameters
	userPlaneConnection.AddHandler(gtpMessage.MsgTypeTPDU, handle5GTPDU)

	return userPlaneConnection, remoteUDPAddr, nil
}

// Parse the fields not supported by go-gtp and forward data to UE.
func handle5GTPDU(c gtp.Conn, senderAddr net.Addr, msg gtpMessage.Message) error {
	pdu := TPDUPacket{qos: false}
	if err := pdu.Unmarshal(msg.(*gtpMessage.TPDU)); err != nil {
		return err
	}

	forward(pdu)
	return nil
}

// Forward user plane packets from N3 to UE with GRE header and new IP header encapsulated
func forward(packet TPDUPacket) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			gtpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// N3IWF context
	self := n3iwfContext.N3IWFSelf()

	// Nwu connection in IPv4
	NWuConn := self.NWuIPv4PacketConn

	// Find UE information
	ue, ok := self.AllocatedUETEIDLoad(packet.GetTEID())
	if !ok {
		gtpLog.Error("UE context not found")
		return
	}

	// UE inner IP in IPSec
	ueInnerIPAddr := ue.IPSecInnerIPAddr

	// QoS Related Parameter
	if packet.HasQoS() {
		RQI, QFI := packet.GetQoSParameters()
		gtpLog.Tracef("RQI: %v, QFI: %v", RQI, QFI)
	}

	// TODO: Support QoS paramater in GRE header
	greHeader := []byte{0, 0, 8, 0}
	greEncapsulatedPacket := append(greHeader, packet.GetPayload()...)

	// Send to UE through Nwu
	if n, err := NWuConn.WriteTo(greEncapsulatedPacket, nil, ueInnerIPAddr); err != nil {
		gtpLog.Errorf("Write to UE failed: %+v", err)
		return
	} else {
		gtpLog.Trace("Forward NWu <- N3")
		gtpLog.Tracef("Wrote %d bytes", n)
	}
}
