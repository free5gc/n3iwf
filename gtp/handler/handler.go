package handler

import (
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"
	gtp "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"

	gtpQoSMsg "github.com/free5gc/n3iwf/gtp/message"
	"github.com/free5gc/n3iwf/logger"
	n3iwfContext "github.com/free5gc/n3iwf/context"
)

var gtpLog *logrus.Entry

func init() {
	gtpLog = logger.GTPLog
}

// Parse the fields not supported by go-gtp and forward data to UE.
func HandleQoSTPDU(c gtp.Conn, senderAddr net.Addr, msg gtpMsg.Message) error {
	pdu := gtpQoSMsg.QoSTPDUPacket{}
	if err := pdu.Unmarshal(msg.(*gtpMsg.TPDU)); err != nil {
		return err
	}

	forward(pdu)
	return nil
}

// Forward user plane packets from N3 to UE with GRE header and new IP header encapsulated
func forward(packet gtpQoSMsg.QoSTPDUPacket) {
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
