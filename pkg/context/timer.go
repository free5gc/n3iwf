package context

import (
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"
)

type Timer struct {
	ticker *time.Ticker
	done   chan bool
}

func NewDPDTimer(d time.Duration, maxRetryTimes int32, ikeSA *IKESecurityAssociation, cancelFunc func()) *Timer {
	t := &Timer{}
	t.done = make(chan bool, 1)
	t.ticker = time.NewTicker(d)

	go func(ticker *time.Ticker) {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				fmt.Errorf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		defer ticker.Stop()

		for {
			select {
			case <-t.done:
				return
			case <-ticker.C:
				atomic.AddInt32(&ikeSA.CurrentRetryTimes, 1)
				if atomic.LoadInt32(&ikeSA.CurrentRetryTimes) == maxRetryTimes {
					cancelFunc()
					return
				}
			}
		}
	}(t.ticker)

	return t
}

func (t *Timer) Stop() {
	t.done <- true
	close(t.done)
}
