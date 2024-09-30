package context

import "fmt"

type SafeEvtCh[chanType any] struct {
	rcvEvtCh  chan chanType
	stopSigCh chan struct{}
}

func (safeEvtCh *SafeEvtCh[chanType]) Init(rcvEvtCh chan chanType) {
	safeEvtCh.rcvEvtCh = rcvEvtCh
	safeEvtCh.stopSigCh = make(chan struct{})
}

func (safeEvtCh *SafeEvtCh[chanType]) SendEvt(evt chanType) error {
	select {
	case <-safeEvtCh.stopSigCh:
		return fmt.Errorf("event channel[%T] is closed", safeEvtCh.rcvEvtCh)
	default:
	}
	safeEvtCh.rcvEvtCh <- evt
	return nil
}

func (safeEvtCh *SafeEvtCh[chanType]) RecvEvtCh() chan chanType {
	return safeEvtCh.rcvEvtCh
}

func (safeEvtCh *SafeEvtCh[chanType]) Close() {
	close(safeEvtCh.stopSigCh)
}
