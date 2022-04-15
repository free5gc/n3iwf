package service

import (
	"errors"
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwf/internal/gre"
	gtpQoSMsg "github.com/free5gc/n3iwf/internal/gtp/message"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/context"
)

var nwuupLog *logrus.Entry

func init() {
	nwuupLog = logger.NWuUPLog
}

// Run bind and listen IPv4 packet connection on N3IWF NWu interface
// with UP_IP_ADDRESS, catching GRE encapsulated packets and forward
// to N3 interface.
func Run() error {
	// Local IPSec address
	n3iwfSelf := context.N3IWFSelf()
	listenAddr := n3iwfSelf.IPSecGatewayAddress

	// Setup IPv4 packet connection socket
	// This socket will only capture GRE encapsulated packet
	connection, err := net.ListenPacket("ip4:gre", listenAddr)
	if err != nil {
		nwuupLog.Errorf("Error setting listen socket on %s: %+v", listenAddr, err)
		return errors.New("ListenPacket failed")
	}
	ipv4PacketConn := ipv4.NewPacketConn(connection)
	if err != nil {
		nwuupLog.Errorf("Error opening IPv4 packet connection socket on %s: %+v", listenAddr, err)
		return errors.New("NewPacketConn failed")
	}

	n3iwfSelf.NWuIPv4PacketConn = ipv4PacketConn
	go listenAndServe(ipv4PacketConn)

	return nil
}

// listenAndServe read from socket and call forward() to
// forward packet.
func listenAndServe(ipv4PacketConn *ipv4.PacketConn) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NWuUPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := ipv4PacketConn.Close()
		if err != nil {
			nwuupLog.Errorf("Error closing raw socket: %+v", err)
		}
	}()

	buffer := make([]byte, 65535)

	if err := ipv4PacketConn.SetControlMessage(ipv4.FlagInterface|ipv4.FlagTTL, true); err != nil {
		nwuupLog.Errorf("Set control message visibility for IPv4 packet connection fail: %+v", err)
		return
	}

	for {
		n, cm, src, err := ipv4PacketConn.ReadFrom(buffer)
		nwuupLog.Tracef("Read %d bytes, %s", n, cm)
		if err != nil {
			nwuupLog.Errorf("Error read from IPv4 packet connection: %+v", err)
			return
		}

		forwardData := make([]byte, n)
		copy(forwardData, buffer)

		go forward(src.String(), cm.IfIndex, forwardData)
	}
}

// forward forwards user plane packets from NWu to UPF
// with GTP header encapsulated
func forward(ueInnerIP string, ifIndex int, rawData []byte) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NWuUPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// Find UE information
	self := context.N3IWFSelf()
	ue, ok := self.AllocatedUEIPAddressLoad(ueInnerIP)
	if !ok {
		nwuupLog.Error("UE context not found")
		return
	}

	var pduSession *context.PDUSession

	for _, childSA := range ue.N3IWFChildSecurityAssociation {
		// Check which child SA the packet come from with interface index,
		// and find the corresponding PDU session
		if childSA.XfrmIface != nil && childSA.XfrmIface.Attrs().Index == ifIndex {
			pduSession = ue.PduSessionList[childSA.PDUSessionIds[0]]
		}
	}

	if pduSession == nil {
		nwuupLog.Error("This UE doesn't have any available PDU session")
		return
	}

	gtpConnection := pduSession.GTPConnection

	userPlaneConnection := gtpConnection.UserPlaneConnection

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

		n, writeErr = userPlaneConnection.WriteTo(gtpPacket, gtpConnection.UPFUDPAddr)
	} else {
		nwuupLog.Warnf("Receive GRE header without key field specifying QFI and RQI.")
		n, writeErr = userPlaneConnection.WriteToGTP(gtpConnection.OutgoingTEID, payload, gtpConnection.UPFUDPAddr)
	}

	if writeErr != nil {
		nwuupLog.Errorf("Write to UPF failed: %+v", writeErr)
		if writeErr == gtpv1.ErrConnNotOpened {
			nwuupLog.Error("The connection has been closed")
			// TODO: Release the GTP resource
		}
		return
	} else {
		nwuupLog.Trace("Forward NWu -> N3")
		nwuupLog.Tracef("Wrote %d bytes", n)
		return
	}
}

func buildQoSGTPPacket(teid uint32, qfi uint8, payload []byte) ([]byte, error) {
	header := gtpMsg.NewHeader(0x34, gtpMsg.MsgTypeTPDU, teid, 0x00, payload).WithExtensionHeaders(
		gtpMsg.NewExtensionHeader(
			gtpMsg.ExtHeaderTypePDUSessionContainer,
			[]byte{gtpQoSMsg.UL_PDU_SESSION_INFORMATION_TYPE, qfi},
			gtpMsg.ExtHeaderTypeNoMoreExtensionHeaders,
		),
	)

	b := make([]byte, header.MarshalLen())

	if err := header.MarshalTo(b); err != nil {
		nwuupLog.Errorf("go-gtp MarshalTo err: %+v", err)
		return nil, err
	}

	return b, nil
}
