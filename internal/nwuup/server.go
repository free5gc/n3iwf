package nwuup

import (
	"context"
	"net"
	"runtime/debug"
	"sync"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwf/internal/gre"
	gtpQoSMsg "github.com/free5gc/n3iwf/internal/gtp/message"
	"github.com/free5gc/n3iwf/internal/logger"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
)

type n3iwf interface {
	Config() *factory.Config
	Context() *n3iwf_context.N3IWFContext
	CancelContext() context.Context
}

type Server struct {
	n3iwf

	gtpuConn *gtpv1.UPlaneConn
	greConn  *ipv4.PacketConn
}

func NewServer(n3iwf n3iwf) (*Server, error) {
	s := &Server{
		n3iwf: n3iwf,
	}
	return s, nil
}

// Run bind and listen IPv4 packet connection on N3IWF NWu interface
// with UP_IP_ADDRESS, catching GRE encapsulated packets and forward
// to N3 interface.
func (s *Server) Run(wg *sync.WaitGroup) error {
	err := s.newGreConn()
	if err != nil {
		return err
	}

	err = s.newGtpuConn()
	if err != nil {
		return err
	}

	wg.Add(1)
	go s.greListenAndServe(wg)

	wg.Add(1)
	go s.gtpuListenAndServe(wg)

	return nil
}

func (s *Server) newGreConn() error {
	cfg := s.Config()
	listenAddr := cfg.GetIPSecGatewayAddr()

	// Setup IPv4 packet connection socket
	// This socket will only capture GRE encapsulated packet
	connection, err := net.ListenPacket("ip4:gre", listenAddr)
	if err != nil {
		return errors.Wrapf(err, "Error setting GRE listen socket on %s", listenAddr)
	}
	s.greConn = ipv4.NewPacketConn(connection)
	if s.greConn == nil {
		return errors.Wrapf(err, "Error opening GRE IPv4 packet connection socket on %s", listenAddr)
	}
	return nil
}

func (s *Server) newGtpuConn() error {
	cfg := s.Config()
	gtpuAddr := cfg.GetGTPBindAddr() + gtpv1.GTPUPort

	laddr, err := net.ResolveUDPAddr("udp", gtpuAddr)
	if err != nil {
		return errors.Wrapf(err, "Resolve GTP-U address %s Failed", gtpuAddr)
	}

	upConn := gtpv1.NewUPlaneConn(laddr)
	// Overwrite T-PDU handler for supporting extension header containing QoS parameters
	upConn.AddHandler(gtpMsg.MsgTypeTPDU, s.handleQoSTPDU)
	s.gtpuConn = upConn
	return nil
}

// Parse the fields not supported by go-gtp and forward data to UE.
func (s *Server) handleQoSTPDU(c gtpv1.Conn, senderAddr net.Addr, msg gtpMsg.Message) error {
	pdu := gtpQoSMsg.QoSTPDUPacket{}
	err := pdu.Unmarshal(msg.(*gtpMsg.TPDU))
	if err != nil {
		return err
	}

	s.forwardDL(pdu)
	return nil
}

// Forward user plane packets from N3 to UE with GRE header and new IP header encapsulated
func (s *Server) forwardDL(packet gtpQoSMsg.QoSTPDUPacket) {
	gtpLog := logger.GTPLog

	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			gtpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	n3iwfCtx := s.Context()

	pktTEID := packet.GetTEID()
	gtpLog.Tracef("pkt teid : %d", pktTEID)

	// Find UE information
	ranUe, ok := n3iwfCtx.AllocatedUETEIDLoad(pktTEID)
	if !ok {
		gtpLog.Errorf("Cannot find RanUE context from QosPacket TEID : %+v", pktTEID)
		return
	}

	ikeUe, err := n3iwfCtx.IkeUeLoadFromNgapId(ranUe.RanUeNgapId)
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
	if n, err := s.greConn.WriteTo(forwardData, cm, ueInnerIPAddr); err != nil {
		gtpLog.Errorf("Write to UE failed: %+v", err)
		return
	} else {
		gtpLog.Trace("Forward NWu <- N3")
		gtpLog.Tracef("Wrote %d bytes", n)
	}
}

func (s *Server) gtpuListenAndServe(wg *sync.WaitGroup) {
	nwuupLog := logger.NWuUPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		wg.Done()
	}()

	if err := s.gtpuConn.ListenAndServe(context.Background()); err != nil {
		nwuupLog.Errorf("GTP-U server err: %v", err)
	}
}

// listenAndServe read from socket and call forward() to
// forward packet.
func (s *Server) greListenAndServe(wg *sync.WaitGroup) {
	nwuupLog := logger.NWuUPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := s.greConn.Close()
		if err != nil {
			nwuupLog.Errorf("Error closing raw socket: %+v", err)
		}
		wg.Done()
	}()

	buffer := make([]byte, 65535)

	err := s.greConn.SetControlMessage(ipv4.FlagInterface|ipv4.FlagTTL, true)
	if err != nil {
		nwuupLog.Errorf("Set control message visibility for IPv4 packet connection fail: %+v", err)
		return
	}

	for {
		n, cm, src, err := s.greConn.ReadFrom(buffer)
		nwuupLog.Tracef("Read %d bytes, %s", n, cm)
		if err != nil {
			nwuupLog.Errorf("Error read from IPv4 packet connection: %+v", err)
			return
		}

		forwardData := make([]byte, n)
		copy(forwardData, buffer)

		wg.Add(1)
		go s.forwardUL(src.String(), cm.IfIndex, forwardData, wg)
	}
}

// forward forwards user plane packets from NWu to UPF
// with GTP header encapsulated
func (s *Server) forwardUL(ueInnerIP string, ifIndex int, rawData []byte, wg *sync.WaitGroup) {
	nwuupLog := logger.NWuUPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		wg.Done()
	}()

	// Find UE information
	n3iwfCtx := s.Context()
	ikeUe, ok := n3iwfCtx.AllocatedUEIPAddressLoad(ueInnerIP)
	if !ok {
		nwuupLog.Error("Ike UE context not found")
		return
	}

	ranUe, err := n3iwfCtx.RanUeLoadFromIkeSPI(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	if err != nil {
		nwuupLog.Error("ranUe not found")
		return
	}

	var pduSession *n3iwf_context.PDUSession

	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		// Check which child SA the packet come from with interface index,
		// and find the corresponding PDU session
		if childSA.XfrmIface != nil && childSA.XfrmIface.Attrs().Index == ifIndex {
			pduSession = ranUe.PduSessionList[childSA.PDUSessionIds[0]]
			break
		}
	}

	if pduSession == nil {
		nwuupLog.Error("This UE doesn't have any available PDU session")
		return
	}

	gtpConnection := pduSession.GTPConnection

	// Decapsulate GRE header and extract QoS Parameters if exist
	grePacket := gre.GREPacket{}
	if err := grePacket.Unmarshal(rawData); err != nil {
		nwuupLog.Errorf("gre Unmarshal err: %+v", err)
		return
	}

	var (
		n        int
		writeErr error
	)

	payload, _ := grePacket.GetPayload()

	// Encapsulate UL PDU SESSION INFORMATION with extension header if the QoS parameters exist
	if grePacket.GetKeyFlag() {
		qfi := grePacket.GetQFI()
		gtpPacket, err := buildQoSGTPPacket(gtpConnection.OutgoingTEID, qfi, payload)
		if err != nil {
			nwuupLog.Errorf("buildQoSGTPPacket err: %+v", err)
			return
		}

		n, writeErr = s.gtpuConn.WriteTo(gtpPacket, gtpConnection.UPFUDPAddr)
	} else {
		nwuupLog.Warnf("Receive GRE header without key field specifying QFI and RQI.")
		n, writeErr = s.gtpuConn.WriteToGTP(gtpConnection.OutgoingTEID, payload, gtpConnection.UPFUDPAddr)
	}

	if writeErr != nil {
		nwuupLog.Errorf("Write to UPF failed: %+v", writeErr)
		if writeErr == gtpv1.ErrConnNotOpened {
			nwuupLog.Error("The connection has been closed")
			// TODO: Release the GTP resource
		}
		return
	}
	nwuupLog.Trace("Forward NWu -> N3")
	nwuupLog.Tracef("Wrote %d bytes", n)
}

func buildQoSGTPPacket(teid uint32, qfi uint8, payload []byte) ([]byte, error) {
	nwuupLog := logger.NWuUPLog
	header := gtpMsg.NewHeader(0x34, gtpMsg.MsgTypeTPDU, teid, 0x00, payload).WithExtensionHeaders(
		gtpMsg.NewExtensionHeader(
			gtpMsg.ExtHeaderTypePDUSessionContainer,
			[]byte{gtpQoSMsg.UL_PDU_SESSION_INFORMATION_TYPE, qfi},
			gtpMsg.ExtHeaderTypeNoMoreExtensionHeaders,
		),
	)

	b := make([]byte, header.MarshalLen())

	if err := header.MarshalTo(b); err != nil {
		nwuupLog.Errorf("go-gtp MarshalTo err: %v", err)
		return nil, err
	}

	return b, nil
}

func (s *Server) Stop() {
	nwuupLog := logger.NWuUPLog
	nwuupLog.Infof("Close Nwuup server...")

	if err := s.greConn.Close(); err != nil {
		nwuupLog.Errorf("Stop nwuup greConn error : %v", err)
	}
	if err := s.gtpuConn.Close(); err != nil {
		nwuupLog.Errorf("Stop nwuup gtpuConn error : %v", err)
	}
}
