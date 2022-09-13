package handler

import (
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"
	gtp "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwf/internal/gre"
	gtpQoSMsg "github.com/free5gc/n3iwf/internal/gtp/message"
	"github.com/free5gc/n3iwf/internal/logger"
	n3iwfContext "github.com/free5gc/n3iwf/pkg/context"
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

	pktTEID := packet.GetTEID()
	gtpLog.Tracef("pkt teid : %d", pktTEID)

	// Find UE information
	ue, ok := self.AllocatedUETEIDLoad(packet.GetTEID())
	if !ok {
		gtpLog.Error("UE context not found")
		return
	}

	// UE inner IP in IPSec
	ueInnerIPAddr := ue.IPSecInnerIPAddr

	var cm *ipv4.ControlMessage

	for _, childSA := range ue.N3IWFChildSecurityAssociation {
		pdusession := ue.FindPDUSession(childSA.PDUSessionIds[0])
		if pdusession != nil && pdusession.GTPConnection.IncomingTEID == pktTEID {
			gtpLog.Tracef("forwarding IPSec xfrm interfaceid : %d", childSA.XfrmIface.Attrs().Index)
			cm = &ipv4.ControlMessage{
				IfIndex: childSA.XfrmIface.Attrs().Index,
			}
		}
	}

	var (
		qfi uint8
		rqi bool
	)

	// QoS Related Parameter
	if packet.HasQoS() {
		qfi, rqi = packet.GetQoSParameters()
		gtpLog.Tracef("QFI: %v, RQI: %v", qfi, rqi)
	}

	// Encasulate IPv4 packet with GRE header before forward to UE through IPsec
	grePacket := gre.GREPacket{}

	// TODO:[24.502(v15.7) 9.3.3 ] The Protocol Type field should be set to zero
	grePacket.SetPayload(packet.GetPayload(), gre.IPv4)
	grePacket.SetQoS(qfi, rqi)
	forwardData := grePacket.Marshal()

	// Send to UE through Nwu
	if n, err := NWuConn.WriteTo(forwardData, cm, ueInnerIPAddr); err != nil {
		gtpLog.Errorf("Write to UE failed: %+v", err)
		return
	} else {
		gtpLog.Trace("Forward NWu <- N3")
		gtpLog.Tracef("Wrote %d bytes", n)
	}
}
