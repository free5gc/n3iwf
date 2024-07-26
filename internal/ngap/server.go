package ngap

import (
	"context"
	"errors"
	"io"
	"runtime/debug"
	"sync"
	"time"

	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/internal/ngap/message"
	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	lib_ngap "github.com/free5gc/ngap"
	"github.com/free5gc/sctp"
)

var (
	RECEIVE_NGAPPACKET_CHANNEL_LEN = 512
	RECEIVE_NGAPEVENT_CHANNEL_LEN  = 512
)

type n3iwf interface {
	Config() *factory.Config
	Context() *n3iwf_context.N3IWFContext
	CancelContext() context.Context
	IkeEvtCh() chan n3iwf_context.IkeEvt
}

type Server struct {
	n3iwf

	Conn         []*sctp.SCTPConn
	RcvNgapPktCh chan ReceiveNGAPPacket
	RcvEventCh   chan n3iwf_context.NgapEvt
}

type ReceiveNGAPPacket struct {
	Conn *sctp.SCTPConn
	Buf  []byte
}

func NewServer(n3iwf n3iwf) (*Server, error) {
	s := &Server{
		n3iwf:        n3iwf,
		RcvNgapPktCh: make(chan ReceiveNGAPPacket, RECEIVE_NGAPPACKET_CHANNEL_LEN),
		RcvEventCh:   make(chan n3iwf_context.NgapEvt, RECEIVE_NGAPEVENT_CHANNEL_LEN),
	}
	return s, nil
}

// Run start the N3IWF SCTP process.
func (s *Server) Run(wg *sync.WaitGroup) error {
	// n3iwf context
	cfg := s.Config()

	localAddr := cfg.GetLocalSctpAddr()

	for _, remoteAddr := range cfg.GetAmfSctpAddrs() {
		errChan := make(chan error)
		wg.Add(1)
		go s.listenAndServe(localAddr, remoteAddr, errChan, wg)
		if err, ok := <-errChan; ok {
			return err
		}
	}

	wg.Add(1)
	go s.runNgapEventHandler(wg)

	return nil
}

func (s *Server) runNgapEventHandler(wg *sync.WaitGroup) {
	ngapLog := logger.NgapLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ngapLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		ngapLog.Infof("NGAP server stopped")
		close(s.RcvEventCh)
		close(s.RcvNgapPktCh)
		wg.Done()
	}()

	for {
		select {
		case rcvPkt := <-s.RcvNgapPktCh:
			if len(rcvPkt.Buf) == 0 { // receiver closed
				return
			}
			s.NGAPDispatch(rcvPkt.Conn, rcvPkt.Buf)
		case rcvEvt := <-s.RcvEventCh:
			s.HandleEvent(rcvEvt)
		}
	}
}

func (s *Server) listenAndServe(
	localAddr, remoteAddr *sctp.SCTPAddr,
	errChan chan<- error,
	wg *sync.WaitGroup,
) {
	ngapLog := logger.NgapLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ngapLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		ngapLog.Infof("NGAP receiver stopped")
		wg.Done()
	}()

	var conn *sctp.SCTPConn
	var err error
	// Connect the session
	for i := 0; i < 3; i++ {
		conn, err = sctp.DialSCTP("sctp", localAddr, remoteAddr)
		if err != nil {
			ngapLog.Errorf("[SCTP] DialSCTP(): %+v", err)
		} else {
			break
		}

		if i != 2 {
			ngapLog.Info("Retry to connect AMF after 1 second...")
			time.Sleep(1 * time.Second)
		} else {
			ngapLog.Debugf("[SCTP] AMF SCTP address: %s", remoteAddr)
			errChan <- errors.New("Failed to connect to AMF.")
			return
		}
	}

	// Set default sender SCTP information sinfo_ppid = NGAP_PPID = 60
	info, err := conn.GetDefaultSentParam()
	if err != nil {
		ngapLog.Errorf("[SCTP] GetDefaultSentParam(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			ngapLog.Errorf("conn close error in GetDefaultSentParam(): %+v", errConn)
		}
		errChan <- errors.New("Get socket information failed.")
		return
	}
	info.PPID = lib_ngap.PPID
	err = conn.SetDefaultSentParam(info)
	if err != nil {
		ngapLog.Errorf("[SCTP] SetDefaultSentParam(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			ngapLog.Errorf("conn close error in SetDefaultSentParam(): %+v", errConn)
		}
		errChan <- errors.New("Set socket parameter failed.")
		return
	}

	// Subscribe receiver SCTP information
	err = conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
	if err != nil {
		ngapLog.Errorf("[SCTP] SubscribeEvents(): %+v", err)
		errConn := conn.Close()
		if errConn != nil {
			ngapLog.Errorf("conn close error in SubscribeEvents(): %+v", errConn)
		}
		errChan <- errors.New("Subscribe SCTP event failed.")
		return
	}

	// Send NG setup request
	n3iwfCtx := s.Context()
	message.SendNGSetupRequest(conn, n3iwfCtx)

	close(errChan)

	s.Conn = append(s.Conn, conn)

	data := make([]byte, 65535)
	for {
		n, info, _, err := conn.SCTPRead(data)

		if err != nil {
			ngapLog.Debugf("[SCTP] AMF SCTP address: %s", remoteAddr)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				ngapLog.Warn("[SCTP] Close connection.")
				errConn := conn.Close()
				if errConn != nil {
					ngapLog.Errorf("conn close error: %+v", errConn)
				}
				s.RcvNgapPktCh <- ReceiveNGAPPacket{}
				return
			}
			ngapLog.Errorf("[SCTP] Read from SCTP connection failed: %+v", err)
		} else {
			ngapLog.Tracef("[SCTP] Successfully read %d bytes.", n)

			if info == nil || info.PPID != lib_ngap.PPID {
				ngapLog.Warn("Received SCTP PPID != 60")
				continue
			}

			forwardData := make([]byte, n)
			copy(forwardData, data[:n])

			s.RcvNgapPktCh <- ReceiveNGAPPacket{
				Conn: conn,
				Buf:  forwardData[:n],
			}
		}
	}
}

func (s *Server) Stop() {
	ngapLog := logger.NgapLog
	ngapLog.Infof("Close NGAP server....")

	for _, ngapServerConn := range s.Conn {
		if err := ngapServerConn.Close(); err != nil {
			ngapLog.Errorf("Stop ngap server error : %+v", err)
		}
	}
}
