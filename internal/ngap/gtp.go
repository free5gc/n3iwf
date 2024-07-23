package ngap

import (
	"net"
	"runtime/debug"

	"github.com/pkg/errors"
	gtp "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwf/internal/gre"
	gtpQoSMsg "github.com/free5gc/n3iwf/internal/gtp/message"
	"github.com/free5gc/n3iwf/internal/logger"
)

// set up GTP connection with UPF
func (s *Server) setupGTPTunnelWithUPF(
	upfIPAddr string,
) (*gtp.UPlaneConn, net.Addr, error) {
	gtpLog := logger.GTPLog
	cfg := s.Config()

	// Set up GTP connection
	upfUDPAddr := upfIPAddr + gtp.GTPUPort

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", upfUDPAddr)
	if err != nil {
		gtpLog.Errorf("Resolve UDP address %s failed: %+v", upfUDPAddr, err)
		return nil, nil, errors.Errorf("Resolve Address Failed")
	}

	n3iwfUDPAddr := cfg.GetGTPBindAddr() + gtp.GTPUPort

	localUDPAddr, err := net.ResolveUDPAddr("udp", n3iwfUDPAddr)
	if err != nil {
		gtpLog.Errorf("Resolve UDP address %s failed: %+v", n3iwfUDPAddr, err)
		return nil, nil, errors.Errorf("Resolve Address Failed")
	}

	// Dial to UPF
	userPlaneConnection, err := gtp.DialUPlane(
		s.CancelContext(), localUDPAddr, remoteUDPAddr)
	if err != nil {
		gtpLog.Errorf("Dial to UPF failed: %+v", err)
		return nil, nil, errors.Errorf("Dial failed")
	}

	// Overwrite T-PDU handler for supporting extension header containing QoS parameters
	userPlaneConnection.AddHandler(gtpMsg.MsgTypeTPDU, s.handleQoSTPDU)

	return userPlaneConnection, remoteUDPAddr, nil
}

// Parse the fields not supported by go-gtp and forward data to UE.
func (s *Server) handleQoSTPDU(c gtp.Conn, senderAddr net.Addr, msg gtpMsg.Message) error {
	pdu := gtpQoSMsg.QoSTPDUPacket{}
	err := pdu.Unmarshal(msg.(*gtpMsg.TPDU))
	if err != nil {
		return err
	}

	s.forward(pdu)
	return nil
}

// Forward user plane packets from N3 to UE with GRE header and new IP header encapsulated
func (s *Server) forward(packet gtpQoSMsg.QoSTPDUPacket) {
	gtpLog := logger.GTPLog

	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			gtpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// N3IWF context
	self := s.Context()

	pktTEID := packet.GetTEID()
	gtpLog.Tracef("pkt teid : %d", pktTEID)

	// Find UE information
	ranUe, ok := self.AllocatedUETEIDLoad(pktTEID)
	if !ok {
		gtpLog.Errorf("Cannot find RanUE context from QosPacket TEID : %+v", pktTEID)
		return
	}

	ikeUe, err := self.IkeUeLoadFromNgapId(ranUe.RanUeNgapId)
	if err != nil {
		gtpLog.Errorf("Cannot find IkeUe context from RanUe , NgapID : %+v", ranUe.RanUeNgapId)
		return
	}

	// UE inner IP in IPSec
	ueInnerIPAddr := ikeUe.IPSecInnerIPAddr

	var cm *ipv4.ControlMessage
	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		pdusession := ranUe.FindPDUSession(childSA.PDUSessionIds[0])
		if pdusession != nil && pdusession.GTPConnection.IncomingTEID == pktTEID {
			gtpLog.Tracef("forwarding IPSec xfrm interfaceid : %d", childSA.XfrmIface.Attrs().Index)
			cm = &ipv4.ControlMessage{
				IfIndex: childSA.XfrmIface.Attrs().Index,
			}
			break
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
	if n, err := s.NwuupIPv4PktConn().WriteTo(forwardData, cm, ueInnerIPAddr); err != nil {
		gtpLog.Errorf("Write to UE failed: %+v", err)
		return
	} else {
		gtpLog.Trace("Forward NWu <- N3")
		gtpLog.Tracef("Wrote %d bytes", n)
	}
}
