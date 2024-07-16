package service

import (
	"net"
	"runtime/debug"
	"sync"

	"github.com/pkg/errors"

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
		return errors.Wrapf(err, "ResolveUDPAddr (%s:500)", ip)
	}
	udpAddrPort4500, err := net.ResolveUDPAddr("udp", ip+":4500")
	if err != nil {
		return errors.Wrapf(err, "ResolveUDPAddr (%s:4500)", ip)
	}

	n3iwfSelf.IKEServer = NewIKEServer()

	// Listen and serve
	var errChan chan error

	// Port 500
	wg.Add(1)
	errChan = make(chan error)
	go Receiver(udpAddrPort500, n3iwfSelf.IKEServer, errChan, wg)
	if err, ok := <-errChan; ok {
		return errors.Wrapf(err, "udp 500")
	}

	// Port 4500
	wg.Add(1)
	errChan = make(chan error)
	go Receiver(udpAddrPort4500, n3iwfSelf.IKEServer, errChan, wg)
	if err, ok := <-errChan; ok {
		return errors.Wrapf(err, "udp 4500")
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
	ikeLog := logger.IKELog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ikeLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		ikeLog.Infof("Ike server stopped")
		close(ikeServer.RcvIkePktCh)
		close(ikeServer.StopServer)
		wg.Done()
	}()

	for {
		select {
		case rcvPkt := <-ikeServer.RcvIkePktCh:
			ikeLog.Tracef("Receive IKE packet")
			ike.IkeDispatch(&rcvPkt.Listener, &rcvPkt.LocalAddr, &rcvPkt.RemoteAddr, rcvPkt.Msg)
		case rcvIkeEvent := <-ikeServer.RcvEventCh:
			handler.HandleEvent(rcvIkeEvent)
		case <-ikeServer.StopServer:
			return
		}
	}
}

func Receiver(localAddr *net.UDPAddr, ikeServer *context.IkeServer, errChan chan<- error, wg *sync.WaitGroup) {
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

	ikeServer.Listener[localAddr.Port] = listener

	data := make([]byte, 65535)

	for {
		n, remoteAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			ikeLog.Errorf("ReadFromUDP failed: %+v", err)
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
	ikeLog := logger.IKELog
	ikeLog.Infof("Close Ike server...")

	for _, ikeServerListener := range n3iwfContext.IKEServer.Listener {
		if err := ikeServerListener.Close(); err != nil {
			ikeLog.Errorf("Stop ike server : %s error : %+v", err, ikeServerListener.LocalAddr().String())
		}
	}

	n3iwfContext.IKEServer.StopServer <- struct{}{}
}
