package service

import (
	"errors"
	"io"
	"runtime/debug"
	"sync"
	"time"

	"git.cs.nctu.edu.tw/calee/sctp"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/internal/ngap"
	"github.com/free5gc/n3iwf/internal/ngap/handler"
	"github.com/free5gc/n3iwf/internal/ngap/message"
	"github.com/free5gc/n3iwf/pkg/context"
	lib_ngap "github.com/free5gc/ngap"
)

var (
	RECEIVE_NGAPPACKET_CHANNEL_LEN = 512
	RECEIVE_NGAPEVENT_CHANNEL_LEN  = 512
)

// Run start the N3IWF SCTP process.
func Run(wg *sync.WaitGroup) error {
	// n3iwf context
	n3iwfSelf := context.N3IWFSelf()
	// load amf SCTP address slice
	amfSCTPAddresses := n3iwfSelf.AMFSCTPAddresses

	localAddr := new(sctp.SCTPAddr)

	n3iwfSelf.NGAPServer = NewNGAPServer()
	for _, remoteAddr := range amfSCTPAddresses {
		errChan := make(chan error)
		wg.Add(1)
		go Receiver(localAddr, remoteAddr, errChan, n3iwfSelf.NGAPServer, wg)
		if err, ok := <-errChan; ok {
			logger.NgapLog.Errorln(err)
			return errors.New("NGAP service run failed")
		}
	}

	wg.Add(1)
	go server(n3iwfSelf.NGAPServer, wg)

	return nil
}

func NewNGAPServer() *context.NGAPServer {
	return &context.NGAPServer{
		RcvNgapPktCh: make(chan context.ReceiveNGAPPacket, RECEIVE_NGAPPACKET_CHANNEL_LEN),
		RcvEventCh:   make(chan context.NgapEvt, RECEIVE_NGAPEVENT_CHANNEL_LEN),
	}
}

func server(ngapServer *context.NGAPServer, wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NgapLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		logger.NgapLog.Infof("NGAP server stopped")
		close(ngapServer.RcvEventCh)
		close(ngapServer.RcvNgapPktCh)
		wg.Done()
	}()

	for {
		select {
		case rcvPkt := <-ngapServer.RcvNgapPktCh:
			if len(rcvPkt.Buf) == 0 { // receiver closed
				return
			}
			ngap.NGAPDispatch(rcvPkt.Conn, rcvPkt.Buf)
		case rcvEvt := <-ngapServer.RcvEventCh:
			handler.HandleEvent(rcvEvt)
		}
	}
}

func Receiver(localAddr, remoteAddr *sctp.SCTPAddr, errChan chan<- error, ngapServer *context.NGAPServer,
	wg *sync.WaitGroup,
) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NgapLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		logger.NgapLog.Infof("NGAP receiver stopped")
		wg.Done()
	}()

	var conn *sctp.SCTPConn
	var err error
	// Connect the session
	for i := 0; i < 3; i++ {
		conn, err = sctp.DialSCTP("sctp", localAddr, remoteAddr)
		if err != nil {
			logger.NgapLog.Errorf("[SCTP] DialSCTP(): %+v", err)
		} else {
			break
		}

		if i != 2 {
			logger.NgapLog.Info("Retry to connect AMF after 1 second...")
			time.Sleep(1 * time.Second)
		} else {
			logger.NgapLog.Debugf("[SCTP] AMF SCTP address: %s", remoteAddr)
			errChan <- errors.New("Failed to connect to AMF.")
			return
		}
	}

	// Set default sender SCTP information sinfo_ppid = NGAP_PPID = 60
	info, err := conn.GetDefaultSentParam()
	if err != nil {
		logger.NgapLog.Errorf("[SCTP] GetDefaultSentParam(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			logger.NgapLog.Errorf("conn close error in GetDefaultSentParam(): %+v", errConn)
		}
		errChan <- errors.New("Get socket information failed.")
		return
	}
	info.PPID = lib_ngap.PPID
	err = conn.SetDefaultSentParam(info)
	if err != nil {
		logger.NgapLog.Errorf("[SCTP] SetDefaultSentParam(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			logger.NgapLog.Errorf("conn close error in SetDefaultSentParam(): %+v", errConn)
		}
		errChan <- errors.New("Set socket parameter failed.")
		return
	}

	// Subscribe receiver SCTP information
	err = conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
	if err != nil {
		logger.NgapLog.Errorf("[SCTP] SubscribeEvents(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			logger.NgapLog.Errorf("conn close error in SubscribeEvents(): %+v", errConn)
		}
		errChan <- errors.New("Subscribe SCTP event failed.")
		return
	}

	// Send NG setup request
	message.SendNGSetupRequest(conn)

	close(errChan)

	ngapServer.Conn = append(ngapServer.Conn, conn)

	data := make([]byte, 65535)
	for {
		n, info, _, err := conn.SCTPRead(data)

		if err != nil {
			logger.NgapLog.Debugf("[SCTP] AMF SCTP address: %s", remoteAddr)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				logger.NgapLog.Warn("[SCTP] Close connection.")
				errConn := conn.Close()
				if errConn != nil {
					logger.NgapLog.Errorf("conn close error: %+v", errConn)
				}
				ngapServer.RcvNgapPktCh <- context.ReceiveNGAPPacket{}
				return
			}
			logger.NgapLog.Errorf("[SCTP] Read from SCTP connection failed: %+v", err)
		} else {
			logger.NgapLog.Tracef("[SCTP] Successfully read %d bytes.", n)

			if info == nil || info.PPID != lib_ngap.PPID {
				logger.NgapLog.Warn("Received SCTP PPID != 60")
				continue
			}

			forwardData := make([]byte, n)
			copy(forwardData, data[:n])

			ngapServer.RcvNgapPktCh <- context.ReceiveNGAPPacket{
				Conn: conn,
				Buf:  forwardData[:n],
			}
		}
	}
}

func Stop(n3iwfContext *context.N3IWFContext) {
	logger.NgapLog.Infof("Close NGAP server....")

	for _, ngapServerConn := range n3iwfContext.NGAPServer.Conn {
		if err := ngapServerConn.Close(); err != nil {
			logger.NgapLog.Errorf("Stop ngap server error : %+v", err)
		}
	}
}
