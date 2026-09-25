// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/utils/syncx"
	"go.uber.org/goleak"
)

type TestConnection struct {
	id       uint32
	parentId uint32
}

func newTestConnection(id uint32) *TestConnection {
	return &TestConnection{id: id}
}

func (c *TestConnection) ID() uint32 {
	return c.id
}

func (c *TestConnection) ParentID() uint32 {
	return c.parentId
}

func TestMain(m *testing.M) {
	// A re-execution of this binary as a go-plugin plugin serves and exits
	// instead of running tests; see transport_test.go.
	if servePluginForTransportTests() {
		return
	}

	// Prevent "goleak: Errors on successful test run: found unexpected goroutines"
	opts := []goleak.Option{
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	}
	goleak.VerifyTestMain(m, opts...)
}

type TestConnectionWithClose struct {
	*TestConnection
	closed bool
}

func newTestConnectionWithClose(id uint32) *TestConnectionWithClose {
	return &TestConnectionWithClose{TestConnection: newTestConnection(id)}
}

func (c *TestConnectionWithClose) Close() {
	c.closed = true
}

type TestResource struct{}

func (r *TestResource) MqlID() string {
	return "test.resource"
}

func (r *TestResource) MqlName() string {
	return "Test Resource"
}

func TestAddRuntime(t *testing.T) {
	s := NewService()
	wg := sync.WaitGroup{}
	wg.Add(4)
	addRuntimes := func(j int) {
		defer wg.Done()
		for i := 1; i < 51; i++ {
			idStr := fmt.Sprintf("%d%d", i, j)
			id, err := strconv.Atoi(idStr)
			require.NoError(t, err)
			_, err = s.AddRuntime(&inventory.Config{Id: uint32(id)}, func(connId uint32) (*Runtime, error) {
				return &Runtime{}, nil
			})
			require.NoError(t, err)
		}
	}

	// Add runtimes concurrently
	for i := 1; i < 5; i++ {
		go addRuntimes(i)
	}

	// Wait until all runtimes are added
	wg.Wait()

	// Verify that all runtimes are added and the last connection ID is correct
	assert.Len(t, s.runtimes, 200)
	assert.Equal(t, s.lastConnectionID, uint32(0))
}

func TestAddRuntime_Existing(t *testing.T) {
	s := NewService()

	inv := &inventory.Config{Id: 1}
	createRuntime := func(connId uint32) (*Runtime, error) {
		resMap := &syncx.Map[Resource]{}
		resMap.Set("test.resource", &TestResource{})

		return &Runtime{
			Resources:  resMap,
			Connection: newTestConnection(connId),
		}, nil
	}
	runtime1, err := s.AddRuntime(inv, createRuntime)
	require.NoError(t, err)

	runtime2, err := s.AddRuntime(inv, createRuntime)
	require.NoError(t, err)
	assert.Equal(t, runtime1, runtime2)
}

func TestDeprecatedAddRuntime(t *testing.T) {
	s := NewService()
	wg := sync.WaitGroup{}
	wg.Add(4)
	addRuntimes := func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
				return &Runtime{}, nil
			})
			require.NoError(t, err)
		}
	}

	// Add runtimes concurrently
	for i := 0; i < 4; i++ {
		go addRuntimes()
	}

	// Wait until all runtimes are added
	wg.Wait()

	// Verify that all runtimes are added and the last connection ID is correct
	assert.Len(t, s.runtimes, 200)
	assert.Equal(t, s.lastConnectionID, uint32(200))
}

func TestDeprecatedAddRuntime_DisableDelayedDiscovery(t *testing.T) {
	s := NewService()
	inv := &inventory.Config{}
	_, err := s.AddRuntime(inv, func(connId uint32) (*Runtime, error) {
		c := newTestConnection(connId)
		return &Runtime{
			Connection: c,
		}, nil
	})
	require.NoError(t, err)
	require.Contains(t, inv.Options, DISABLE_DELAYED_DISCOVERY_OPTION)
	assert.Equal(t, "true", inv.Options[DISABLE_DELAYED_DISCOVERY_OPTION])
}

func TestAddRuntime_ParentNotExist(t *testing.T) {
	s := NewService()
	parentId := uint32(10)
	runtime, err := s.AddRuntime(&inventory.Config{Id: 1}, func(connId uint32) (*Runtime, error) {
		c := newTestConnection(connId)
		c.parentId = parentId
		return &Runtime{
			Connection: c,
		}, nil
	})
	require.NoError(t, err, "missing parent should not cause an error")
	require.NotNil(t, runtime)
}

func TestDeprecatedAddRuntime_ParentNotExist(t *testing.T) {
	s := NewService()
	parentId := uint32(10)
	runtime, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
		c := newTestConnection(connId)
		c.parentId = parentId
		return &Runtime{
			Connection: c,
		}, nil
	})
	require.NoError(t, err, "missing parent should not cause an error")
	require.NotNil(t, runtime)
}

func TestAddRuntime_Parent(t *testing.T) {
	s := NewService()

	parent, err := s.AddRuntime(&inventory.Config{Id: 1}, func(connId uint32) (*Runtime, error) {
		resMap := &syncx.Map[Resource]{}
		resMap.Set("test.resource", &TestResource{})

		return &Runtime{
			Resources:  resMap,
			Connection: newTestConnection(connId),
		}, nil
	})
	require.NoError(t, err)

	parentId := parent.Connection.ID()
	child, err := s.AddRuntime(&inventory.Config{Id: 2}, func(connId uint32) (*Runtime, error) {
		c := newTestConnection(connId)
		c.parentId = parentId
		return &Runtime{
			Connection: c,
		}, nil
	})
	require.NoError(t, err)

	// Check that the resources for the parent and the child are the same
	assert.Equal(t, parent.Resources, child.Resources)

	// Add another resource and check that it appears in the child runtime
	parent.Resources.Set("test.resource2", &TestResource{})
	assert.Equal(t, parent.Resources, child.Resources)
}

func TestDeprecatedAddRuntime_Parent(t *testing.T) {
	s := NewService()

	parent, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
		resMap := &syncx.Map[Resource]{}
		resMap.Set("test.resource", &TestResource{})

		return &Runtime{
			Resources:  resMap,
			Connection: newTestConnection(connId),
		}, nil
	})
	require.NoError(t, err)

	parentId := parent.Connection.ID()
	child, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
		c := newTestConnection(connId)
		c.parentId = parentId
		return &Runtime{
			Connection: c,
		}, nil
	})
	require.NoError(t, err)

	// Check that the resources for the parent and the child are the same
	assert.Equal(t, parent.Resources, child.Resources)

	// Add another resource and check that it appears in the child runtime
	parent.Resources.Set("test.resource2", &TestResource{})
	assert.Equal(t, parent.Resources, child.Resources)
}

func TestGetRuntime(t *testing.T) {
	s := NewService()

	runtime, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
		return &Runtime{
			Connection: newTestConnection(connId),
		}, nil
	})
	require.NoError(t, err)

	// Add some more runtimes
	for i := 0; i < 5; i++ {
		_, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
			return &Runtime{
				Connection: newTestConnection(connId),
			}, nil
		})
		require.NoError(t, err)
	}

	// Retrieve the first runtime
	retrievedRuntime, err := s.GetRuntime(runtime.Connection.ID())
	require.NoError(t, err)
	assert.Equal(t, runtime, retrievedRuntime)
}

func TestGetRuntime_DoesNotExist(t *testing.T) {
	s := NewService()

	_, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
		return &Runtime{
			Connection: newTestConnection(connId),
		}, nil
	})
	require.NoError(t, err)

	_, err = s.GetRuntime(10)
	assert.Error(t, err)
	assert.Equal(t, "connection 10 not found", err.Error())
}

func TestDisconnect(t *testing.T) {
	s := NewService()

	runtime, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
		return &Runtime{
			Connection: newTestConnection(connId),
		}, nil
	})
	require.NoError(t, err)

	assert.Len(t, s.runtimes, 1)

	_, err = s.Disconnect(&DisconnectReq{Connection: runtime.Connection.ID()})
	require.NoError(t, err)
	assert.Empty(t, s.runtimes)
}

func TestDisconnect_Closer(t *testing.T) {
	s := NewService()

	runtime, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
		return &Runtime{
			Connection: newTestConnectionWithClose(connId),
		}, nil
	})
	require.NoError(t, err)

	assert.False(t, runtime.Connection.(*TestConnectionWithClose).closed)
	assert.Len(t, s.runtimes, 1)

	_, err = s.Disconnect(&DisconnectReq{Connection: runtime.Connection.ID()})
	require.NoError(t, err)
	assert.Empty(t, s.runtimes)

	assert.True(t, runtime.Connection.(*TestConnectionWithClose).closed)
}

func TestShutdown(t *testing.T) {
	s := NewService()

	// Add some more runtimes
	for i := 0; i < 50; i++ {
		_, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
			return &Runtime{
				Connection: newTestConnection(connId),
			}, nil
		})
		require.NoError(t, err)
	}

	// Shutdown and verify all runtimes are gone
	_, err := s.Shutdown(&ShutdownReq{})
	require.NoError(t, err)
	assert.Empty(t, s.runtimes)
}

func TestShutdown_Closer(t *testing.T) {
	s := NewService()

	// Add some more runtimes
	runtimes := []*Runtime{}
	for i := 0; i < 50; i++ {
		runtime, err := s.AddRuntime(&inventory.Config{}, func(connId uint32) (*Runtime, error) {
			return &Runtime{
				Connection: newTestConnectionWithClose(connId),
			}, nil
		})
		require.NoError(t, err)
		runtimes = append(runtimes, runtime)
	}

	// Shutdown and verify all runtimes are gone
	_, err := s.Shutdown(&ShutdownReq{})
	require.NoError(t, err)
	assert.Empty(t, s.runtimes)

	// Verify that all runtimes are closed
	for _, runtime := range runtimes {
		assert.True(t, runtime.Connection.(*TestConnectionWithClose).closed)
	}
}

// The provider used to exit on the first missed heartbeat window. On a loaded
// host that window is routinely missed by a provider that is perfectly healthy,
// and the exit throws away the whole scan's in-flight work.
func TestWatchdogShouldExit(t *testing.T) {
	window := 5 * time.Second

	t.Run("idle", func(t *testing.T) {
		assert.False(t, watchdogShouldExit(window+time.Second, window, 0), "one missed window is not death")
		assert.False(t, watchdogShouldExit(heartbeatMissesBeforeExit*window, window, 0))
		assert.True(t, watchdogShouldExit(heartbeatMissesBeforeExit*window+time.Second, window, 0))
	})

	t.Run("serving requests", func(t *testing.T) {
		// a request in flight proves the parent was there to send it
		assert.False(t, watchdogShouldExit(heartbeatMissesBeforeExit*window+time.Second, window, 1))
		assert.False(t, watchdogShouldExit(heartbeatBusyMissesBeforeExit*window, window, 3))
		assert.True(t, watchdogShouldExit(heartbeatBusyMissesBeforeExit*window+time.Second, window, 3))
	})
}

func TestHeartbeat(t *testing.T) {
	s := NewService()
	t.Cleanup(s.stopWatchdog)

	_, err := s.Heartbeat(&HeartbeatReq{})
	require.Error(t, err, "an interval of 0 has no tolerance to apply")

	before := int64(s.sinceClockBase(time.Now()))
	_, err = s.Heartbeat(&HeartbeatReq{Interval: uint64(time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, int64(time.Hour), s.heartbeatWindow.Load())
	assert.GreaterOrEqual(t, s.lastHeartbeat.Load(), before)
}

func TestTrackRequest(t *testing.T) {
	s := NewService()
	done := s.TrackRequest()
	assert.Equal(t, int64(1), s.inflightRequests.Load())
	done()
	assert.Equal(t, int64(0), s.inflightRequests.Load())
}

// captureWatchdogExit replaces the process exit with a recorder. The fake exit
// parks its goroutine like a real exit would, so the watchdog cannot loop and
// report twice.
func captureWatchdogExit(t *testing.T) <-chan int {
	t.Helper()
	exited := make(chan int, 1)
	parked := make(chan struct{})
	original := watchdogExit
	watchdogExit = func(code int) {
		select {
		case exited <- code:
		default:
		}
		<-parked
	}
	t.Cleanup(func() {
		watchdogExit = original
		close(parked)
	})
	return exited
}

func TestHeartbeatWatchdog_ExitsWhenParentIsGone(t *testing.T) {
	exited := captureWatchdogExit(t)

	s := NewService()
	t.Cleanup(s.stopWatchdog)
	// poll interval is floored, so the effective tolerance here is
	// heartbeatMissesBeforeExit * 100ms, noticed on the next poll
	_, err := s.Heartbeat(&HeartbeatReq{Interval: uint64(100 * time.Millisecond)})
	require.NoError(t, err)

	select {
	case code := <-exited:
		assert.Equal(t, 4, code)
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not reap an abandoned provider")
	}
}

func TestHeartbeatWatchdog_HoldsOutWhileServingRequests(t *testing.T) {
	exited := captureWatchdogExit(t)

	s := NewService()
	t.Cleanup(s.stopWatchdog)
	done := s.TrackRequest()

	// A 300ms window puts the idle tolerance at 900ms and the busy tolerance at
	// 1.8s, so surviving 1.3s of silence can only come from the in-flight request.
	const window = 300 * time.Millisecond
	_, err := s.Heartbeat(&HeartbeatReq{Interval: uint64(window)})
	require.NoError(t, err)

	select {
	case <-exited:
		t.Fatal("watchdog reaped a provider that was serving a request")
	case <-time.After(heartbeatMissesBeforeExit*window + 400*time.Millisecond):
	}

	// once the request is done, the same silence is fatal
	done()
	select {
	case code := <-exited:
		assert.Equal(t, 4, code)
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not reap an abandoned provider")
	}
}

func TestHeartbeatWatchdog_SurvivesSuspend(t *testing.T) {
	exited := captureWatchdogExit(t)

	// the whole process tree freezes: when the watchdog next runs, an hour has
	// passed for it just as much as for the heartbeat it last saw
	var frozen, calls atomic.Int64
	armed := make(chan struct{})
	original := watchdogNow
	watchdogNow = func() time.Time {
		// NewService reads the clock, then Heartbeat, then the watchdog it
		// starts: the third read is the watchdog's own first reading
		if calls.Add(1) == 3 {
			close(armed)
		}
		return time.Now().Add(time.Duration(frozen.Load()))
	}
	t.Cleanup(func() { watchdogNow = original })

	s := NewService()
	t.Cleanup(s.stopWatchdog)
	// idle tolerance is heartbeatMissesBeforeExit * 100ms, polled every 250ms
	_, err := s.Heartbeat(&HeartbeatReq{Interval: uint64(100 * time.Millisecond)})
	require.NoError(t, err)
	<-armed // the watchdog has taken its first reading, now freeze
	frozen.Store(int64(time.Hour))

	select {
	case <-exited:
		t.Fatal("watchdog reaped a provider for silence it slept through itself")
	case <-time.After(minHeartbeatPollInterval + 150*time.Millisecond):
	}

	// after waking up, a parent that stays silent is still gone
	select {
	case code := <-exited:
		assert.Equal(t, 4, code)
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not reap an abandoned provider after a suspend")
	}
}

func TestHeartbeatWatchdog_StopsOnShutdown(t *testing.T) {
	exited := captureWatchdogExit(t)

	s := NewService()
	_, err := s.Heartbeat(&HeartbeatReq{Interval: uint64(10 * time.Millisecond)})
	require.NoError(t, err)

	_, err = s.Shutdown(&ShutdownReq{})
	require.NoError(t, err)

	select {
	case <-exited:
		t.Fatal("watchdog reported a crash during a graceful shutdown")
	case <-time.After(minHeartbeatPollInterval * 3):
	}
}
