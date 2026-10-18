package context

import (
	"sync/atomic"
	"time"
)

type Timer struct {
	ticker *time.Ticker
	done   chan bool
}

func NewDPDPeriodicTimer(d time.Duration, maxRetryTimes int32, ikeSA *IKESecurityAssociation,
	cancelFunc func(),
) *Timer {
	t := &Timer{}
	t.done = make(chan bool, 1)
	t.ticker = time.NewTicker(d)

	go func(ticker *time.Ticker) {
		defer ticker.Stop()

		for {
			select {
			case <-t.done:
				return
			case <-ticker.C:
				retryTimes := atomic.AddInt32(&ikeSA.CurrentRetryTimes, 1)
				// Only declare the peer dead once the number of consecutive
				// missed DPD responses reaches the operator-configured
				// maxRetryTimes budget. maxRetryTimes <= 0 preserves the
				// historical fail-fast behavior of giving up after the
				// first missed response.
				if retryTimes >= maxRetryTimes {
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
