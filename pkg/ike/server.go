package ike

import (
	"bytes"
	"context"
	"net"
	"runtime/debug"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"

	"github.com/free5gc/ike"
	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/n3iwf/internal/logger"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
)

var (
	RECEIVE_IKEPACKET_CHANNEL_LEN = 512
	RECEIVE_IKEEVENT_CHANNEL_LEN  = 512
)

type n3iwf interface {
	Config() *factory.Config
	Context() *n3iwf_context.N3IWFContext
	CancelContext() context.Context
	NgapEvtCh() chan n3iwf_context.NgapEvt
}

type EspHandler func(srcIP, dstIP *net.UDPAddr, espPkt []byte) error

type Server struct {
	n3iwf

	Listener    map[int]*net.UDPConn
	RcvIkePktCh chan IkeReceivePacket
	RcvEventCh  chan n3iwf_context.IkeEvt
	StopServer  chan struct{}
}

type IkeReceivePacket struct {
	Listener   net.UDPConn
	LocalAddr  net.UDPAddr
	RemoteAddr net.UDPAddr
	Msg        []byte
}

func NewServer(n3iwf n3iwf) (*Server, error) {
	s := &Server{
		n3iwf:       n3iwf,
		Listener:    make(map[int]*net.UDPConn),
		RcvIkePktCh: make(chan IkeReceivePacket, RECEIVE_IKEPACKET_CHANNEL_LEN),
		RcvEventCh:  make(chan n3iwf_context.IkeEvt, RECEIVE_IKEEVENT_CHANNEL_LEN),
		StopServer:  make(chan struct{}),
	}
	return s, nil
}

func (s *Server) Run(wg *sync.WaitGroup) error {
	cfg := s.Config()

	// Resolve UDP addresses
	ip := cfg.GetIKEBindAddr()
	udpAddrPort500, err := net.ResolveUDPAddr("udp", ip+":500")
	if err != nil {
		return errors.Wrapf(err, "ResolveUDPAddr (%s:500)", ip)
	}
	udpAddrPort4500, err := net.ResolveUDPAddr("udp", ip+":4500")
	if err != nil {
		return errors.Wrapf(err, "ResolveUDPAddr (%s:4500)", ip)
	}

	// Listen and serve
	var errChan chan error

	// Port 500
	wg.Add(1)
	errChan = make(chan error)
	go s.receiver(udpAddrPort500, errChan, wg)
	if err, ok := <-errChan; ok {
		return errors.Wrapf(err, "udp 500")
	}

	// Port 4500
	wg.Add(1)
	errChan = make(chan error)
	go s.receiver(udpAddrPort4500, errChan, wg)
	if err, ok := <-errChan; ok {
		return errors.Wrapf(err, "udp 4500")
	}

	wg.Add(1)
	go s.server(wg)

	return nil
}

func (s *Server) server(wg *sync.WaitGroup) {
	ikeLog := logger.IKELog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ikeLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		ikeLog.Infof("Ike server stopped")
		close(s.RcvIkePktCh)
		close(s.StopServer)
		wg.Done()
	}()

	for {
		select {
		case rcvPkt := <-s.RcvIkePktCh:
			msg, err := s.checkMessage(rcvPkt, handleESPPacket)
			if err != nil {
				ikeLog.Warnln(err)
				continue
			}
			ikeMsg, ikeSA, err := s.checkIKEMessage(msg, &rcvPkt.Listener, &rcvPkt.LocalAddr, &rcvPkt.RemoteAddr)
			if err != nil {
				ikeLog.Warnln(err)
				continue
			}
			if ikeMsg == nil {
				continue
			}
			s.Dispatch(&rcvPkt.Listener, &rcvPkt.LocalAddr, &rcvPkt.RemoteAddr,
				ikeMsg, rcvPkt.Msg, ikeSA)
		case rcvIkeEvent := <-s.RcvEventCh:
			s.HandleEvent(rcvIkeEvent)
		case <-s.StopServer:
			return
		}
	}
}

func (s *Server) receiver(
	localAddr *net.UDPAddr,
	errChan chan<- error,
	wg *sync.WaitGroup,
) {
	ikeLog := logger.IKELog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ikeLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		ikeLog.Infof("Ike receiver stopped")
		wg.Done()
	}()

	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		ikeLog.Errorf("Listen UDP failed: %+v", err)
		errChan <- errors.New("listenAndServe failed")
		return
	}

	close(errChan)

	s.Listener[localAddr.Port] = listener

	data := make([]byte, 65535)

	for {
		n, remoteAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			ikeLog.Errorf("ReadFromUDP failed: %+v", err)
			return
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])
		s.RcvIkePktCh <- IkeReceivePacket{
			RemoteAddr: *remoteAddr,
			Listener:   *listener,
			LocalAddr:  *localAddr,
			Msg:        forwardData,
		}
	}
}

func (s *Server) Stop() {
	ikeLog := logger.IKELog
	ikeLog.Infof("Close Ike server...")

	for _, ikeServerListener := range s.Listener {
		if err := ikeServerListener.Close(); err != nil {
			ikeLog.Errorf("Stop ike server : %s error : %+v", err, ikeServerListener.LocalAddr().String())
		}
	}

	s.StopServer <- struct{}{}
}

func (s *Server) checkMessage(
	rcvPkt IkeReceivePacket,
	espHandler EspHandler,
) ([]byte, error) {
	ikeLog := logger.IKELog
	localAddr := &rcvPkt.LocalAddr
	remoteAddr := &rcvPkt.RemoteAddr
	msg := rcvPkt.Msg
	marker := []byte{0, 0, 0, 0} // Non-ESP Marker

	if len(msg) == 1 && msg[0] == 0xff {
		ikeLog.Tracef("Get NAT-T Keepalive from IP: %v", remoteAddr.IP.String())
		return nil, nil
	} else if len(msg) < len(marker) {
		return nil, errors.Errorf("Received packet is too short from IP: %v", remoteAddr.IP.String())
	}

	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if localAddr.Port == 4500 {
		if !bytes.Equal(msg[:4], marker) {
			if espHandler != nil {
				err := espHandler(remoteAddr, localAddr, msg)
				if err != nil {
					return nil, errors.Wrapf(err, "Handle ESP")
				}
			}
			return nil, nil
		}
		msg = msg[4:]
	}

	return msg, nil
}

func (s *Server) checkIKEMessage(
	msg []byte, udpConn *net.UDPConn,
	localAddr, remoteAddr *net.UDPAddr,
) (*ike_message.IKEMessage,
	*n3iwf_context.IKESecurityAssociation, error,
) {
	var ikeHeader *ike_message.IKEHeader
	var ikeMessage *ike_message.IKEMessage
	var ikeSA *n3iwf_context.IKESecurityAssociation
	var err error

	// parse IKE header and setup IKE context
	ikeHeader, err = ike_message.ParseIkeHeader(msg)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "IKE msg decode header")
	}

	// check major version
	if ikeHeader.MajorVersion > 2 {
		// send INFORMATIONAL type message with INVALID_MAJOR_VERSION Notify payload
		// For response or needed data
		responseIKEMessage := new(ike_message.IKEMessage)
		responseIKEMessage.BuildIKEHeader(ikeHeader.InitiatorSPI, ikeHeader.ResponderSPI,
			ike_message.INFORMATIONAL, ike_message.ResponseBitCheck, ikeHeader.MessageID)
		responseIKEMessage.Payloads.BuildNotification(ike_message.TypeNone,
			ike_message.INVALID_MAJOR_VERSION, nil, nil)

		err = SendIKEMessageToUE(udpConn, localAddr, remoteAddr, responseIKEMessage, nil)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Received an IKE message with higher major version "+
				"(%d>2)", ikeHeader.MajorVersion)
		}
		return nil, nil, errors.Errorf("Received an IKE message with higher major version (%d>2)", ikeHeader.MajorVersion)
	}

	if ikeHeader.ExchangeType == ike_message.IKE_SA_INIT {
		ikeMessage, err = ike.DecodeDecrypt(msg, ikeHeader,
			nil, ike_message.Role_Responder)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Decrypt IkeMsg error")
		}
	} else if ikeHeader.ExchangeType != ike_message.IKE_SA_INIT {
		localSPI := ikeHeader.ResponderSPI
		var ok bool
		n3iwfCtx := s.Context()

		ikeSA, ok = n3iwfCtx.IKESALoad(localSPI)
		if !ok {
			responseIKEMessage := new(ike_message.IKEMessage)
			// send INFORMATIONAL type message with INVALID_IKE_SPI Notify payload ( OUTSIDE IKE SA )
			responseIKEMessage.BuildIKEHeader(ikeHeader.InitiatorSPI, 0, ike_message.INFORMATIONAL,
				ike_message.ResponseBitCheck, ikeHeader.MessageID)
			responseIKEMessage.Payloads.Reset()
			responseIKEMessage.Payloads.BuildNotification(ike_message.TypeNone, ike_message.INVALID_IKE_SPI, nil, nil)

			err = SendIKEMessageToUE(udpConn, localAddr, remoteAddr, responseIKEMessage, nil)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "checkIKEMessage():")
			}
			return nil, nil, errors.Errorf("Received an unrecognized SPI message: %d", localSPI)
		}

		ikeMessage, err = ike.DecodeDecrypt(msg, ikeHeader,
			ikeSA.IKESAKey, ike_message.Role_Responder)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Decrypt IkeMsg error")
		}
	}

	return ikeMessage, ikeSA, nil
}

func constructPacketWithESP(srcIP, dstIP *net.UDPAddr, espPacket []byte) ([]byte, error) {
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP.IP,
		DstIP:    dstIP.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolESP,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer,
		options,
		ipLayer,
		gopacket.Payload(espPacket),
	)
	if err != nil {
		return nil, errors.Errorf("Error serializing layers: %v", err)
	}

	packetData := buffer.Bytes()
	return packetData, nil
}

func handleESPPacket(srcIP, dstIP *net.UDPAddr, espPacket []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return errors.Errorf("socket error: %v", err)
	}

	defer func() {
		if err = syscall.Close(fd); err != nil {
			logger.IKELog.Errorf("Close fd error : %v", err)
		}
	}()

	ipPacket, err := constructPacketWithESP(srcIP, dstIP, espPacket)
	if err != nil {
		return err
	}

	addr := syscall.SockaddrInet4{
		Addr: [4]byte(dstIP.IP),
		Port: dstIP.Port,
	}

	err = syscall.Sendto(fd, ipPacket, 0, &addr)
	if err != nil {
		return errors.Errorf("sendto error: %v", err)
	}

	return nil
}
