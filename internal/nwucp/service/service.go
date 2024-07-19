package service

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/internal/ngap/message"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
)

var tcpListener net.Listener

// Run setup N3IWF NAS for UE to forward NAS message
// to AMF
func Run(wg *sync.WaitGroup) error {
	// N3IWF context
	n3iwfSelf := n3iwf_context.N3IWFSelf()
	cfg := n3iwfSelf.Config()

	listener, err := net.Listen("tcp", cfg.GetNasTcpAddr())
	if err != nil {
		return err
	}

	tcpListener = listener

	wg.Add(1)
	go listenAndServe(tcpListener, wg)

	return nil
}

// listenAndServe handle TCP listener and accept incoming
// requests. It also stores accepted connection into UE
// context, and finally, call serveConn() to serve the messages
// received from the connection.
func listenAndServe(listener net.Listener, wg *sync.WaitGroup) {
	nwucpLog := logger.NWuCPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwucpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := tcpListener.Close()
		if err != nil {
			nwucpLog.Errorf("Error closing tcpListener: %+v", err)
		}
		wg.Done()
	}()

	for {
		connection, err := listener.Accept()
		if err != nil {
			nwucpLog.Errorf("TCP server accept failed : %+v. Close the listener...", err)
			return
		}

		nwucpLog.Tracef("Accepted one UE from %+v", connection.RemoteAddr())

		// Find UE context and store this connection in to it, then check if
		// there is any cached NAS message for this UE. If yes, send to it.
		n3iwfSelf := n3iwf_context.N3IWFSelf()

		ueIP := strings.Split(connection.RemoteAddr().String(), ":")[0]
		ikeUe, ok := n3iwfSelf.AllocatedUEIPAddressLoad(ueIP)
		if !ok {
			nwucpLog.Errorf("UE context not found for peer %+v", ueIP)
			continue
		}

		ranUe, err := n3iwfSelf.RanUeLoadFromIkeSPI(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
		if err != nil {
			nwucpLog.Errorf("RanUe context not found : %+v", err)
			continue
		}
		// Store connection
		ranUe.TCPConnection = connection

		n3iwfSelf.NGAPServer.RcvEventCh <- n3iwf_context.NewNASTCPConnEstablishedCompleteEvt(
			ranUe.RanUeNgapId,
		)

		wg.Add(1)
		go serveConn(ranUe, connection, wg)
	}
}

func decapNasMsgFromEnvelope(envelop []byte) []byte {
	// According to TS 24.502 8.2.4,
	// in order to transport a NAS message over the non-3GPP access between the UE and the N3IWF,
	// the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
	// According to TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message

	// Get NAS Message Length
	nasLen := binary.BigEndian.Uint16(envelop[:2])
	nasMsg := make([]byte, nasLen)
	copy(nasMsg, envelop[2:2+nasLen])

	return nasMsg
}

func Stop(n3iwfContext *n3iwf_context.N3IWFContext) {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Infof("Close Nwucp server...")

	if err := tcpListener.Close(); err != nil {
		nwucpLog.Errorf("Stop nwuup server error : %+v", err)
	}

	n3iwfContext.RANUePool.Range(
		func(key, value interface{}) bool {
			ranUe := value.(*n3iwf_context.N3IWFRanUe)
			if ranUe.TCPConnection != nil {
				if err := ranUe.TCPConnection.Close(); err != nil {
					logger.InitLog.Errorf("Stop nwucp server error : %+v", err)
				}
			}
			return true
		})
}

// serveConn handle accepted TCP connection. It reads NAS packets
// from the connection and call forward() to forward NAS messages
// to AMF
func serveConn(ranUe *n3iwf_context.N3IWFRanUe, connection net.Conn, wg *sync.WaitGroup) {
	nwucpLog := logger.NWuCPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwucpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := connection.Close()
		if err != nil {
			nwucpLog.Errorf("Error closing connection: %+v", err)
		}
		wg.Done()
	}()

	data := make([]byte, 65535)
	for {
		n, err := connection.Read(data)
		if err != nil {
			nwucpLog.Errorf("Read TCP connection failed: %+v", err)
			ranUe.TCPConnection = nil
			return
		}
		nwucpLog.Tracef("Get NAS PDU from UE:\nNAS length: %d\nNAS content:\n%s", n, hex.Dump(data[:n]))

		// Decap Nas envelope
		forwardData := decapNasMsgFromEnvelope(data)

		wg.Add(1)
		go forward(ranUe, forwardData, wg)
	}
}

// forward forwards NAS messages sent from UE to the
// associated AMF
func forward(ranUe *n3iwf_context.N3IWFRanUe, packet []byte, wg *sync.WaitGroup) {
	nwucpLog := logger.NWuCPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwucpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		wg.Done()
	}()

	nwucpLog.Trace("Forward NWu -> N2")
	message.SendUplinkNASTransport(ranUe, packet)
}
