package service

import (
	"errors"
	"net"
	"runtime/debug"
	"sync"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/ike"
	"github.com/free5gc/n3iwf/pkg/ike/handler"
)

var (
	RECEIVE_IKEPACKET_CHANNEL_LEN = 512
	RECEIVE_IKEEVENT_CHANNEL_LEN  = 512
)

func Run(wg *sync.WaitGroup) error {
	n3iwfSelf := context.N3IWFSelf()

	// Resolve UDP addresses
	ip := n3iwfSelf.IKEBindAddress
	udpAddrPort500, err := net.ResolveUDPAddr("udp", ip+":500")
	if err != nil {
		logger.IKELog.Errorf("Resolve UDP address failed: %+v", err)
		return errors.New("IKE service run failed")
	}
	udpAddrPort4500, err := net.ResolveUDPAddr("udp", ip+":4500")
	if err != nil {
		logger.IKELog.Errorf("Resolve UDP address failed: %+v", err)
		return errors.New("IKE service run failed")
	}

	n3iwfSelf.IKEServer = NewIKEServer()

	// Listen and serve
	var errChan chan error

	// Port 500
	wg.Add(1)
	errChan = make(chan error)
	go Receiver(udpAddrPort500, n3iwfSelf.IKEServer, errChan, wg)
	if err, ok := <-errChan; ok {
		logger.IKELog.Errorln(err)
		return errors.New("IKE service run failed")
	}

	// Port 4500
	wg.Add(1)
	errChan = make(chan error)
	go Receiver(udpAddrPort4500, n3iwfSelf.IKEServer, errChan, wg)
	if err, ok := <-errChan; ok {
		logger.IKELog.Errorln(err)
		return errors.New("IKE service run failed")
	}

	wg.Add(1)
	go server(n3iwfSelf.IKEServer, wg)

	return nil
}

func NewIKEServer() *context.IkeServer {
	return &context.IkeServer{
		Listener:    make(map[int]*net.UDPConn),
		RcvIkePktCh: make(chan context.IkeReceivePacket, RECEIVE_IKEPACKET_CHANNEL_LEN),
		RcvEventCh:  make(chan context.IkeEvt, RECEIVE_IKEEVENT_CHANNEL_LEN),
		StopServer:  make(chan struct{}),
	}
}

func server(ikeServer *context.IkeServer, wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.IKELog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		logger.IKELog.Infof("Ike server stopped")
		close(ikeServer.RcvIkePktCh)
		close(ikeServer.StopServer)
		wg.Done()
	}()

	for {
		select {
		case rcvPkt := <-ikeServer.RcvIkePktCh:
			logger.IKELog.Tracef("Receive IKE packet")
			ike.IkeDispatch(&rcvPkt.Listener, &rcvPkt.LocalAddr, &rcvPkt.RemoteAddr, rcvPkt.Msg)
		case rcvIkeEvent := <-ikeServer.RcvEventCh:
			handler.HandleEvent(rcvIkeEvent)
		case <-ikeServer.StopServer:
			return
		}
	}
}

func Receiver(localAddr *net.UDPAddr, ikeServer *context.IkeServer, errChan chan<- error, wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.IKELog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		logger.IKELog.Infof("Ike receiver stopped")
		wg.Done()
	}()

	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.IKELog.Errorf("Listen UDP failed: %+v", err)
		errChan <- errors.New("listenAndServe failed")
		return
	}

	close(errChan)

	ikeServer.Listener[localAddr.Port] = listener

	data := make([]byte, 65535)

	for {
		n, remoteAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			logger.IKELog.Errorf("ReadFromUDP failed: %+v", err)
			return
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])
		ikeServer.RcvIkePktCh <- context.IkeReceivePacket{
			RemoteAddr: *remoteAddr,
			Listener:   *listener,
			LocalAddr:  *localAddr,
			Msg:        forwardData,
		}
	}
}

func Stop(n3iwfContext *context.N3IWFContext) {
	logger.IKELog.Infof("Close Ike server...")

	for _, ikeServerListener := range n3iwfContext.IKEServer.Listener {
		if err := ikeServerListener.Close(); err != nil {
			logger.IKELog.Errorf("Stop ike server : %s error : %+v", err, ikeServerListener.LocalAddr().String())
		}
	}

	n3iwfContext.IKEServer.StopServer <- struct{}{}
}
