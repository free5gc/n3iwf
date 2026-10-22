package context_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

// TestNewDPDPeriodicTimer_HonorsMaxRetryTimes verifies that the peer is not
// declared dead (cancelFunc is not invoked) until CurrentRetryTimes reaches
// the configured maxRetryTimes, and that it is declared dead exactly once
// that threshold is reached. This guards against a regression where every
// single missed DPD probe immediately tore down the peer regardless of the
// operator-configured retry budget.
//
// Timing bounds are intentionally asymmetric (tight lower bound via
// require.Never, generous upper bound via require.Eventually) so the test
// is robust on slow/loaded CI runners and does not depend on precise
// scheduling.
func TestNewDPDPeriodicTimer_HonorsMaxRetryTimes(t *testing.T) {
	const (
		maxRetryTimes = int32(3)
		tick          = 20 * time.Millisecond
	)

	ikeSA := &n3iwf_context.IKESecurityAssociation{}

	var cancelCount atomic.Int32
	cancelFunc := func() {
		cancelCount.Add(1)
	}

	timer := n3iwf_context.NewDPDPeriodicTimer(tick, maxRetryTimes, ikeSA, cancelFunc)
	defer timer.Stop()

	// Fewer than maxRetryTimes missed probes can have elapsed in 2 ticks,
	// so the peer must not yet be declared dead.
	require.Never(t, func() bool {
		return cancelCount.Load() > 0
	}, 2*tick, 2*time.Millisecond,
		"peer must not be declared dead before reaching maxRetryTimes missed probes")

	// Eventually (generous bound to tolerate slow/loaded environments),
	// once maxRetryTimes missed probes have accumulated, the peer must be
	// declared dead.
	require.Eventually(t, func() bool {
		return cancelCount.Load() == 1
	}, 5*time.Second, 2*time.Millisecond,
		"expected cancelFunc to be invoked once maxRetryTimes is reached")

	require.GreaterOrEqual(t, atomic.LoadInt32(&ikeSA.CurrentRetryTimes), maxRetryTimes)

	// The timer goroutine must stop after declaring the peer dead once;
	// cancelFunc must never be invoked a second time.
	require.Never(t, func() bool {
		return cancelCount.Load() > 1
	}, 5*tick, 2*time.Millisecond,
		"cancelFunc must be invoked exactly once; the timer goroutine must stop after declaring the peer dead")
}

// TestNewDPDPeriodicTimer_ZeroMaxRetryTimesFailsFast verifies the documented
// fallback: an unset/zero maxRetryTimes preserves the historical behavior
// of declaring the peer dead after the very first missed DPD probe (not
// after accumulating several).
func TestNewDPDPeriodicTimer_ZeroMaxRetryTimesFailsFast(t *testing.T) {
	const tick = 20 * time.Millisecond

	ikeSA := &n3iwf_context.IKESecurityAssociation{}

	var cancelCount atomic.Int32
	cancelFunc := func() {
		cancelCount.Add(1)
	}

	timer := n3iwf_context.NewDPDPeriodicTimer(tick, 0, ikeSA, cancelFunc)
	defer timer.Stop()

	require.Eventually(t, func() bool {
		return cancelCount.Load() == 1
	}, 5*time.Second, 2*time.Millisecond,
		"expected cancelFunc to be invoked after the first missed probe when maxRetryTimes is 0")

	// Must have fired on exactly the first missed probe, not after
	// accumulating more than one.
	require.Equal(t, int32(1), atomic.LoadInt32(&ikeSA.CurrentRetryTimes))
}

// TestNewDPDPeriodicTimer_ResetAfterSuccess verifies that resetting
// CurrentRetryTimes to 0 (as done in the real success path in
// internal/ike/handler.go's HandleInformational when a DPD response
// arrives) prevents the peer from being prematurely declared dead, and that
// the retry count resumes counting correctly afterward.
func TestNewDPDPeriodicTimer_ResetAfterSuccess(t *testing.T) {
	// A generous maxRetryTimes leaves slack for scheduling jitter between
	// observing the first missed probe and performing the reset below,
	// without weakening what this test demonstrates.
	const (
		maxRetryTimes = int32(5)
		tick          = 20 * time.Millisecond
	)

	ikeSA := &n3iwf_context.IKESecurityAssociation{}

	var cancelCount atomic.Int32
	cancelFunc := func() {
		cancelCount.Add(1)
	}

	timer := n3iwf_context.NewDPDPeriodicTimer(tick, maxRetryTimes, ikeSA, cancelFunc)
	defer timer.Stop()

	// Wait for at least one missed probe to register.
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&ikeSA.CurrentRetryTimes) >= 1
	}, 5*time.Second, 2*time.Millisecond)

	require.Equal(t, int32(0), cancelCount.Load(),
		"peer must not be declared dead before reaching maxRetryTimes missed probes")

	// Simulate a successful DPD response arriving: reset the counter as
	// HandleInformational does.
	atomic.StoreInt32(&ikeSA.CurrentRetryTimes, 0)
	require.Equal(t, int32(0), cancelCount.Load())

	// Counting must resume correctly from 0 after the reset: the peer is
	// eventually declared dead again once maxRetryTimes new missed probes
	// accumulate.
	require.Eventually(t, func() bool {
		return cancelCount.Load() == 1
	}, 5*time.Second, 2*time.Millisecond,
		"expected cancelFunc to be invoked once maxRetryTimes is reached after reset")
}
