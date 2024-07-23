package ike

import (
	"context"
	"net"
	"runtime/debug"
	"sync"

	"github.com/pkg/errors"

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
			ikeLog.Tracef("Receive IKE packet")
			s.Dispatch(&rcvPkt.Listener, &rcvPkt.LocalAddr, &rcvPkt.RemoteAddr, rcvPkt.Msg)
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
