package service

import (
	"net"
	"runtime/debug"
	"sync"

	"github.com/pkg/errors"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwf/internal/gre"
	gtpQoSMsg "github.com/free5gc/n3iwf/internal/gtp/message"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/context"
)

// Run bind and listen IPv4 packet connection on N3IWF NWu interface
// with UP_IP_ADDRESS, catching GRE encapsulated packets and forward
// to N3 interface.
func Run(wg *sync.WaitGroup) error {
	// Local IPSec address
	n3iwfSelf := context.N3IWFSelf()
	listenAddr := n3iwfSelf.IPSecGatewayAddress

	// Setup IPv4 packet connection socket
	// This socket will only capture GRE encapsulated packet
	connection, err := net.ListenPacket("ip4:gre", listenAddr)
	if err != nil {
		return errors.Wrapf(err, "Error setting listen socket on %s", listenAddr)
	}
	ipv4PacketConn := ipv4.NewPacketConn(connection)
	if ipv4PacketConn == nil {
		return errors.Wrapf(err, "Error opening IPv4 packet connection socket on %s", listenAddr)
	}

	n3iwfSelf.NWuIPv4PacketConn = ipv4PacketConn

	wg.Add(1)
	go listenAndServe(ipv4PacketConn, wg)

	return nil
}

// listenAndServe read from socket and call forward() to
// forward packet.
func listenAndServe(ipv4PacketConn *ipv4.PacketConn, wg *sync.WaitGroup) {
	nwuupLog := logger.NWuUPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := ipv4PacketConn.Close()
		if err != nil {
			nwuupLog.Errorf("Error closing raw socket: %+v", err)
		}
		wg.Done()
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

		wg.Add(1)
		go forward(src.String(), cm.IfIndex, forwardData, wg)
	}
}

// forward forwards user plane packets from NWu to UPF
// with GTP header encapsulated
func forward(ueInnerIP string, ifIndex int, rawData []byte, wg *sync.WaitGroup) {
	nwuupLog := logger.NWuUPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		wg.Done()
	}()

	// Find UE information
	self := context.N3IWFSelf()
	ikeUe, ok := self.AllocatedUEIPAddressLoad(ueInnerIP)
	if !ok {
		nwuupLog.Error("Ike UE context not found")
		return
	}

	ranUe, err := self.RanUeLoadFromIkeSPI(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	if err != nil {
		nwuupLog.Error("ranUe not found")
		return
	}

	var pduSession *context.PDUSession

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
		nwuupLog.Errorf("go-gtp MarshalTo err: %+v", err)
		return nil, err
	}

	return b, nil
}

func Stop(n3iwfContext *context.N3IWFContext) {
	nwuupLog := logger.NWuUPLog
	nwuupLog.Infof("Close Nwuup server...")

	if err := n3iwfContext.NWuIPv4PacketConn.Close(); err != nil {
		nwuupLog.Errorf("Stop nwuup server error : %+v", err)
	}
}
