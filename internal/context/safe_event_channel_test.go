package context_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

// Simulate 1 receiver and N(N=2) senders situation
func TestSafeEvtCh(t *testing.T) {
	safeEvtCh := new(n3iwf_context.SafeEvtCh[int])
	safeEvtCh.Init(make(chan int, 10))
	wg := sync.WaitGroup{}

	// Two senders
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			if i == 0 {
				// Case: send failed
				time.Sleep(1 * time.Second)
				err := safeEvtCh.SendEvt(1)
				t.Log(err)
				require.Error(t, err)
			} else {
				// Case: send successed
				err := safeEvtCh.SendEvt(1)
				require.NoError(t, err)
			}
			wg.Done()
		}(i)
	}

	// One receiver
	<-safeEvtCh.RecvEvtCh()
	safeEvtCh.Close()

	wg.Wait()
}
