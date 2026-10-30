// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	pp "go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestConnectionGraph(t *testing.T) {
	g := newConnectionGraph()
	g.addNode(1, connectReq{})
	g.addNode(2, connectReq{})
	g.addNode(3, connectReq{})
	g.addNode(4, connectReq{})

	g.setEdge(4, 2)
	g.setEdge(2, 1)
	g.setEdge(3, 1)

	sorted := g.topoSort()

	require.Len(t, sorted, 4)

	requireComesBefore := func(t *testing.T, sorted []uint32, before, after uint32) {
		beforeIdx := -1
		afterIdx := -1
		for i, n := range sorted {
			if n == before {
				beforeIdx = i
			}
			if n == after {
				afterIdx = i
			}
		}
		require.True(t, beforeIdx >= 0, "before node not found")
		require.True(t, afterIdx >= 0, "after node not found")
		require.True(t, beforeIdx < afterIdx, "before node does not come before after node")
	}

	requireComesBefore(t, sorted, 2, 4)
	requireComesBefore(t, sorted, 1, 2)
	requireComesBefore(t, sorted, 1, 3)

	g.markDisconnected(1)
	g.garbageCollect()

	sorted = g.topoSort()
	require.Len(t, sorted, 4)
	requireComesBefore(t, sorted, 2, 4)
	requireComesBefore(t, sorted, 1, 2)
	requireComesBefore(t, sorted, 1, 3)

	g.markDisconnected(2)
	g.garbageCollect()

	sorted = g.topoSort()
	require.Len(t, sorted, 4)
	requireComesBefore(t, sorted, 2, 4)
	requireComesBefore(t, sorted, 1, 2)
	requireComesBefore(t, sorted, 1, 3)

	g.markDisconnected(4)
	g.garbageCollect()

	sorted = g.topoSort()
	require.Len(t, sorted, 2)
	requireComesBefore(t, sorted, 1, 3)
	require.NotContains(t, g.nodes, uint32(2))
	require.NotContains(t, g.nodes, uint32(4))

	g.markDisconnected(3)
	g.garbageCollect()

	sorted = g.topoSort()
	require.Len(t, sorted, 0)
	require.Empty(t, g.nodes)
	require.Empty(t, g.edges)
}

func TestConnectionGraph_CollectedDataPreserved(t *testing.T) {
	g := newConnectionGraph()

	parentData := connectReq{req: &pp.ConnectReq{}}
	g.addNode(1, parentData)
	g.addNode(2, connectReq{})
	g.setEdge(2, 1)

	// Disconnect both — parent first, then child. GC after child
	// disconnect should collect both.
	g.markDisconnected(1)
	g.markDisconnected(2)
	collected := g.garbageCollect()
	require.Len(t, collected, 2)
	require.NotContains(t, g.nodes, uint32(1))
	require.NotContains(t, g.nodes, uint32(2))

	// Collected data should be preserved for reconnection.
	cr, ok := g.getCollectedNode(1)
	require.True(t, ok, "collected parent data should be preserved")
	assert.Equal(t, parentData.req, cr.req)

	cr2, ok := g.getCollectedNode(2)
	require.True(t, ok, "collected child data should be preserved")
	_ = cr2

	// Re-adding a node should clear its collected entry.
	g.addNode(1, parentData)
	_, ok = g.getCollectedNode(1)
	assert.False(t, ok, "collected data should be cleared after re-add")
}

func TestConnectionGraph_ReconnectedParentKeptByChild(t *testing.T) {
	g := newConnectionGraph()

	// Simulate: parent=1 connected, child=2 connected with edge to 1
	g.addNode(1, connectReq{})
	g.addNode(2, connectReq{})
	g.setEdge(2, 1)

	// Disconnect parent, then child — both get GC'd.
	g.markDisconnected(1)
	g.markDisconnected(2)
	g.garbageCollect()
	require.Empty(t, g.nodes)

	// New child=3 arrives. Reconnect parent as implicit node.
	g.addImplicitNode(1, connectReq{})
	g.addNode(3, connectReq{})
	g.setEdge(3, 1)

	// GC should NOT collect the implicit parent — child 3 keeps it alive.
	collected := g.garbageCollect()
	require.Empty(t, collected)
	require.Contains(t, g.nodes, uint32(1))
	require.Contains(t, g.nodes, uint32(3))

	// Disconnect child 3 — now parent should be collected.
	g.markDisconnected(3)
	collected = g.garbageCollect()
	require.Len(t, collected, 2)
	require.NotContains(t, g.nodes, uint32(1))
	require.NotContains(t, g.nodes, uint32(3))
}

// --- End-to-end simulation of the K8s scan pipeline race condition ---

// mockPlugin tracks which connection IDs are currently alive (have a
// runtime) inside the provider process. It mirrors the real Service's
// runtimes map closely enough to reproduce the bug.
type mockPlugin struct {
	mu       sync.Mutex
	runtimes map[uint32]bool // true = runtime alive
	connects int             // total Connect calls (for assertions)
}

func newMockPlugin() *mockPlugin {
	return &mockPlugin{runtimes: make(map[uint32]bool)}
}

func (m *mockPlugin) Connect(req *pp.ConnectReq, _ pp.ProviderCallback) (*pp.ConnectRes, error) {
	if len(req.Asset.GetConnections()) == 0 {
		return &pp.ConnectRes{}, nil
	}
	conf := req.Asset.Connections[0]

	m.mu.Lock()
	defer m.mu.Unlock()
	m.connects++

	// Already alive? Return early (idempotent, like Service.AddRuntime).
	if m.runtimes[conf.Id] {
		return &pp.ConnectRes{}, nil
	}

	// Check parent, mimicking real AddRuntime before our safety-net fix.
	if conf.ParentConnectionId > 0 {
		if !m.runtimes[conf.ParentConnectionId] {
			return nil, fmt.Errorf("parent connection %d not found", conf.ParentConnectionId)
		}
	}

	m.runtimes[conf.Id] = true
	return &pp.ConnectRes{}, nil
}

func (m *mockPlugin) Disconnect(req *pp.DisconnectReq) (*pp.DisconnectRes, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.runtimes, req.Connection)
	return &pp.DisconnectRes{}, nil
}

func (m *mockPlugin) alive(id uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runtimes[id]
}

// Stubs — not exercised by these tests.
func (m *mockPlugin) Heartbeat(*pp.HeartbeatReq) (*pp.HeartbeatRes, error) {
	return &pp.HeartbeatRes{}, nil
}
func (m *mockPlugin) ParseCLI(*pp.ParseCLIReq) (*pp.ParseCLIRes, error) { return nil, nil }
func (m *mockPlugin) Translations(*pp.TranslationsReq) (*pp.TranslationsRes, error) {
	return &pp.TranslationsRes{}, nil
}
func (m *mockPlugin) ResolveAsset(*pp.ResolveAssetReq) (*pp.ResolveAssetRes, error) {
	return &pp.ResolveAssetRes{}, nil
}
func (m *mockPlugin) MockConnect(*pp.ConnectReq, pp.ProviderCallback) (*pp.ConnectRes, error) {
	return nil, nil
}

func (m *mockPlugin) Shutdown(*pp.ShutdownReq) (*pp.ShutdownRes, error) {
	return &pp.ShutdownRes{}, nil
}
func (m *mockPlugin) GetData(*pp.DataReq) (*pp.DataRes, error)     { return nil, nil }
func (m *mockPlugin) StoreData(*pp.StoreReq) (*pp.StoreRes, error) { return nil, nil }

// connectReqFor builds a ConnectReq for a connection with the given ID
// and optional parent.
func connectReqFor(id, parentId uint32) *pp.ConnectReq {
	return &pp.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{{
				Id:                 id,
				ParentConnectionId: parentId,
			}},
		},
	}
}

// TestRestartableProvider_ParentReconnectsAfterGC reproduces the exact
// K8s scan pipeline race:
//
//  1. Namespace connections (parents) are created during stage-2 discovery.
//  2. Discovery finishes → namespace connections are disconnected → GC'd.
//  3. Workload connections (children) arrive in a later batch with
//     ParentConnectionId pointing at the GC'd namespace.
//
// Before the fix, step 3 fails with "parent connection N not found".
// After the fix, the parent is transparently reconnected from preserved
// data.
func TestRestartableProvider_ParentReconnectsAfterGC(t *testing.T) {
	mock := newMockPlugin()
	rp := &RestartableProvider{
		plugin:          mock,
		connectionGraph: newConnectionGraph(),
	}

	const (
		nsConn         = uint32(2)  // namespace connection (parent)
		workloadBatch1 = uint32(10) // first batch child
		workloadBatch2 = uint32(20) // second batch child (arrives after GC)
	)

	// --- Stage 2 discovery: connect namespace ---
	_, err := rp.Connect(connectReqFor(nsConn, 0), nil)
	require.NoError(t, err)
	require.True(t, mock.alive(nsConn))

	// --- Discovery done: disconnect namespace ---
	// This is the real flow: discovery finishes and the namespace is
	// disconnected BEFORE any workloads connect. Since no children
	// exist in the graph, GC immediately collects the namespace.
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: nsConn})
	require.NoError(t, err)
	require.False(t, mock.alive(nsConn), "namespace runtime should be disconnected")

	// --- First batch: connect a workload child ---
	// The parent was GC'd — our fix should reconnect it transparently.
	_, err = rp.Connect(connectReqFor(workloadBatch1, nsConn), nil)
	require.NoError(t, err, "first child should connect after parent is reconnected")
	require.True(t, mock.alive(nsConn), "parent should be alive after reconnection")

	// --- First batch done: disconnect workload ---
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: workloadBatch1})
	require.NoError(t, err)
	// The implicitly reconnected parent should be GC'd again.
	require.False(t, mock.alive(nsConn), "parent should be GC'd after all children disconnect")

	// --- Second batch arrives: another reconnection cycle ---
	_, err = rp.Connect(connectReqFor(workloadBatch2, nsConn), nil)
	require.NoError(t, err, "second child should also connect after parent is re-reconnected")
	require.True(t, mock.alive(nsConn), "parent should be alive again")
	require.True(t, mock.alive(workloadBatch2))
}

// TestRestartableProvider_ParentDisconnectedWhileChildrenActive reproduces
// the bug where a parent is disconnected while children still reference it.
// GC keeps the parent in the graph (children hold it alive), but the
// unconditional r.plugin.Disconnect call removes its Service-layer runtime.
// A subsequent child then finds the parent in the graph (no reconnection),
// but Service.AddRuntime fails to find the parent runtime → warning.
func TestRestartableProvider_ParentDisconnectedWhileChildrenActive(t *testing.T) {
	mock := newMockPlugin()
	rp := &RestartableProvider{
		plugin:          mock,
		connectionGraph: newConnectionGraph(),
	}

	const (
		nsConn = uint32(2)
		child1 = uint32(10)
		child2 = uint32(11)
		child3 = uint32(12)
	)

	// Connect namespace.
	_, err := rp.Connect(connectReqFor(nsConn, 0), nil)
	require.NoError(t, err)
	require.True(t, mock.alive(nsConn))

	// Connect first child (workload).
	_, err = rp.Connect(connectReqFor(child1, nsConn), nil)
	require.NoError(t, err)
	require.True(t, mock.alive(child1))

	// Disconnect namespace while child1 is still connected.
	// GC should keep node nsConn (child1 references it).
	// The Service-layer runtime for nsConn must stay alive.
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: nsConn})
	require.NoError(t, err)
	require.True(t, mock.alive(nsConn),
		"parent runtime must stay alive while children reference it")

	// Connect second child — parent is in graph, no reconnection needed.
	// This MUST succeed because the parent runtime is still alive.
	_, err = rp.Connect(connectReqFor(child2, nsConn), nil)
	require.NoError(t, err, "child2 should connect with parent still alive in Service")

	// Disconnect child1 — parent still needed by child2.
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: child1})
	require.NoError(t, err)
	require.True(t, mock.alive(nsConn), "parent still needed by child2")

	// Disconnect child2 — parent no longer needed, should be GC'd.
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: child2})
	require.NoError(t, err)
	require.False(t, mock.alive(nsConn), "parent should be GC'd when all children disconnect")

	// A third child arrives after full GC — should reconnect via collectedNodes.
	_, err = rp.Connect(connectReqFor(child3, nsConn), nil)
	require.NoError(t, err, "child3 should connect after parent is re-reconnected from collectedNodes")
	require.True(t, mock.alive(nsConn))
}

// TestRestartableProvider_OverlappingBatchesWithParentDisconnect simulates
// the realistic scanner pattern where batches overlap: some children from
// batch 1 are still connected when the parent is disconnected, and new
// children from batch 2 arrive afterward.
func TestRestartableProvider_OverlappingBatchesWithParentDisconnect(t *testing.T) {
	mock := newMockPlugin()
	rp := &RestartableProvider{
		plugin:          mock,
		connectionGraph: newConnectionGraph(),
	}

	const nsConn = uint32(2)

	// Connect namespace.
	_, err := rp.Connect(connectReqFor(nsConn, 0), nil)
	require.NoError(t, err)

	// Batch 1: connect children 10, 11, 12.
	for _, id := range []uint32{10, 11, 12} {
		_, err := rp.Connect(connectReqFor(id, nsConn), nil)
		require.NoError(t, err)
	}

	// Scanner closes namespace (done scanning it as an asset).
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: nsConn})
	require.NoError(t, err)
	require.True(t, mock.alive(nsConn), "parent kept alive by batch 1 children")

	// Batch 1 children finish one by one.
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: 10})
	require.NoError(t, err)
	require.True(t, mock.alive(nsConn), "parent kept alive by children 11, 12")

	// Batch 2 arrives while batch 1 isn't fully done yet.
	for _, id := range []uint32{13, 14} {
		_, err := rp.Connect(connectReqFor(id, nsConn), nil)
		require.NoError(t, err, "batch 2 child %d should connect", id)
	}

	// Finish remaining batch 1 children.
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: 11})
	require.NoError(t, err)
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: 12})
	require.NoError(t, err)
	require.True(t, mock.alive(nsConn), "parent kept alive by batch 2 children")

	// Finish batch 2.
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: 13})
	require.NoError(t, err)
	_, err = rp.Disconnect(&pp.DisconnectReq{Connection: 14})
	require.NoError(t, err)
	require.False(t, mock.alive(nsConn), "parent GC'd after all children disconnect")

	// Batch 3 arrives after full GC — reconnection from collectedNodes.
	_, err = rp.Connect(connectReqFor(15, nsConn), nil)
	require.NoError(t, err, "batch 3 child should reconnect parent from collectedNodes")
	require.True(t, mock.alive(nsConn))
}

// TestRestartableProvider_MultiNamespaceMultiBatch simulates a realistic
// K8s cluster scan: 5 namespaces × 10 workloads each, processed in
// batches of 15. This catches ordering-dependent bugs that single-pair
// tests miss.
func TestRestartableProvider_MultiNamespaceMultiBatch(t *testing.T) {
	mock := newMockPlugin()
	rp := &RestartableProvider{
		plugin:          mock,
		connectionGraph: newConnectionGraph(),
	}

	const (
		numNamespaces  = 5
		workloadsPerNs = 10
		batchSize      = 15
	)

	// Assign connection IDs the way the coordinator would: namespaces get
	// low IDs, workloads get higher IDs interleaved with namespace discovery.
	nsID := func(ns int) uint32 { return uint32(ns + 1) }
	wlID := func(ns, wl int) uint32 { return uint32(100 + ns*workloadsPerNs + wl) }

	// --- Discovery phase: connect all namespaces (stage 2) ---
	for ns := range numNamespaces {
		_, err := rp.Connect(connectReqFor(nsID(ns), 0), nil)
		require.NoError(t, err)
	}

	// --- Discovery done: disconnect all namespaces ---
	for ns := range numNamespaces {
		_, err := rp.Disconnect(&pp.DisconnectReq{Connection: nsID(ns)})
		require.NoError(t, err)
	}

	// All namespaces should be GC'd now (no children yet).
	for ns := range numNamespaces {
		require.False(t, mock.alive(nsID(ns)), "namespace %d should be GC'd", ns)
	}

	// --- Scan phase: connect workloads in batches ---
	// Build the full workload list.
	type workload struct{ id, parent uint32 }
	var allWorkloads []workload
	for ns := range numNamespaces {
		for wl := range workloadsPerNs {
			allWorkloads = append(allWorkloads, workload{wlID(ns, wl), nsID(ns)})
		}
	}

	// Process in batches: connect batch, disconnect batch, repeat.
	for batchStart := 0; batchStart < len(allWorkloads); batchStart += batchSize {
		batchEnd := min(batchStart+batchSize, len(allWorkloads))
		batch := allWorkloads[batchStart:batchEnd]

		// Connect entire batch.
		for _, wl := range batch {
			_, err := rp.Connect(connectReqFor(wl.id, wl.parent), nil)
			require.NoError(t, err, "workload %d (parent %d) should connect", wl.id, wl.parent)
		}

		// Disconnect entire batch.
		for _, wl := range batch {
			_, err := rp.Disconnect(&pp.DisconnectReq{Connection: wl.id})
			require.NoError(t, err)
		}
	}

	// All workloads processed successfully — no "parent connection N not
	// found" errors. Verify the provider is clean.
	for ns := range numNamespaces {
		assert.False(t, mock.alive(nsID(ns)), "namespace %d should be GC'd after scan", ns)
	}
}

// heartbeatPlugin answers heartbeats according to a script keyed on the call
// number, so a test can describe a provider that is late, recovering, or gone.
type heartbeatPlugin struct {
	*mockPlugin
	mu     sync.Mutex
	calls  int
	script func(call int) error
}

func (h *heartbeatPlugin) Heartbeat(*pp.HeartbeatReq) (*pp.HeartbeatRes, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	if err := h.script(h.calls); err != nil {
		return nil, err
	}
	return &pp.HeartbeatRes{}, nil
}

func (h *heartbeatPlugin) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func newHeartbeatProvider(plugin pp.ProviderPlugin) *RunningProvider {
	return &RunningProvider{
		Name:        "test",
		Plugin:      plugin,
		startedAt:   time.Now(),
		interval:    10 * time.Millisecond,
		gracePeriod: 10 * time.Millisecond,
	}
}

// A provider that answers late is slow, not dead. Shutting it down on the first
// late beat is what turns a momentarily starved host into a crash report, so we
// hold out for maxLateHeartbeats before giving up.
func TestHeartbeat_ToleratesLateBeats(t *testing.T) {
	lateBeat := status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	mock := &heartbeatPlugin{
		mockPlugin: newMockPlugin(),
		script: func(call int) error {
			if call == 1 {
				return nil
			}
			return lateBeat
		},
	}
	rp := newHeartbeatProvider(mock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, rp.heartbeat(ctx, cancel))

	// still alive while it is merely late
	require.Eventually(t, func() bool { return mock.callCount() >= 1+maxLateHeartbeats }, 5*time.Second, 5*time.Millisecond)
	// and gone once the whole budget is used up
	require.Eventually(t, rp.isCloseOrShutdown, 5*time.Second, 5*time.Millisecond)
	assert.True(t, rp.hadHeartbeatFailure())
	assert.GreaterOrEqual(t, mock.callCount(), 1+maxLateHeartbeats+1)
}

// Intermittent lateness must not accumulate into a shutdown: every answered beat
// proves the provider is there.
func TestHeartbeat_RecoveryResetsLateBudget(t *testing.T) {
	lateBeat := status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	mock := &heartbeatPlugin{
		mockPlugin: newMockPlugin(),
		script: func(call int) error {
			if call%2 == 0 {
				return lateBeat
			}
			return nil
		},
	}
	rp := newHeartbeatProvider(mock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, rp.heartbeat(ctx, cancel))

	require.Eventually(t, func() bool { return mock.callCount() > 4*maxLateHeartbeats }, 5*time.Second, 5*time.Millisecond)
	assert.False(t, rp.isCloseOrShutdown())
	assert.False(t, rp.hadHeartbeatFailure())
}

// A broken connection is different: the provider is gone, so there is nothing to
// wait for and we report it right away.
func TestHeartbeat_DeadProviderFailsImmediately(t *testing.T) {
	mock := &heartbeatPlugin{
		mockPlugin: newMockPlugin(),
		script: func(call int) error {
			if call == 1 {
				return nil
			}
			return status.Error(codes.Unavailable, "connection refused")
		},
	}
	rp := newHeartbeatProvider(mock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, rp.heartbeat(ctx, cancel))

	require.Eventually(t, rp.isCloseOrShutdown, 5*time.Second, 5*time.Millisecond)
	assert.True(t, rp.hadHeartbeatFailure())
	assert.Equal(t, 2, mock.callCount(), "a dead provider is not retried")
}

// TestRunningProvider_CrashErrorBeforeCrash covers the alive state: nothing
// is recorded yet, so crashError must return nil rather than a zero-value
// error, and every RPC call site treats a nil return as "still worth trying".
func TestRunningProvider_CrashErrorBeforeCrash(t *testing.T) {
	rp := &RunningProvider{Name: "os"}
	assert.NoError(t, rp.crashError())
}

// TestRunningProvider_RecordCrash_StoresOnceAndMarksClosed covers the
// single-caller path: the first recordCrash call builds and stores the
// diagnostic and marks the provider closed; crashError then returns that
// same error to every later caller.
func TestRunningProvider_RecordCrash_StoresOnceAndMarksClosed(t *testing.T) {
	rp := &RunningProvider{Name: "os"}
	built := 0

	stored, first := rp.recordCrash(func() error {
		built++
		return errors.New("the 'os' provider crashed: connection refused")
	})

	require.Error(t, stored)
	assert.True(t, first)
	assert.Equal(t, 1, built)
	assert.True(t, rp.isClosed)
	assert.Equal(t, stored, rp.crashError())
}

// TestRunningProvider_RecordCrash_BuildErrPanicIsRecovered covers a panic
// inside buildErr (e.g. a nil crashLog or an unexpected nil somewhere in
// buildCrashDiagnostics): recordCrash must still leave the provider marked
// crashed with a non-nil, non-panicking diagnostic stored, rather than the
// panic unwinding out of recordCrash with the provider left neither
// known-crashed nor able to record one on retry.
func TestRunningProvider_RecordCrash_BuildErrPanicIsRecovered(t *testing.T) {
	rp := &RunningProvider{Name: "os"}

	var stored error
	var first bool
	require.NotPanics(t, func() {
		stored, first = rp.recordCrash(func() error {
			panic("boom: nil pointer in buildCrashDiagnostics")
		})
	})

	require.Error(t, stored)
	assert.True(t, first)
	assert.Contains(t, stored.Error(), "os")
	assert.Contains(t, stored.Error(), "boom: nil pointer in buildCrashDiagnostics")
	assert.True(t, rp.isClosed)
	// The recovered diagnostic is what every later caller gets back too.
	assert.Equal(t, stored, rp.crashError())

	// A later call must not panic or rebuild -- it gets the same stored
	// diagnostic back, same as the non-panicking path.
	second, secondFirst := rp.recordCrash(func() error {
		t.Fatal("buildErr must not be called again once a diagnostic is stored")
		return nil
	})
	assert.False(t, secondFirst)
	assert.Equal(t, stored, second)
}

// TestRunningProvider_RecordCrash_DoesNotDeadlockOnHadHeartbeatFailure is the
// regression test for a deadlock this PR introduced and then fixed:
// recordCrash used to hold shutdownLock while calling buildErr(), and
// buildCrashDiagnostics (a realistic buildErr) calls hadHeartbeatFailure,
// which takes the same non-reentrant lock. Run under `go test -timeout` so a
// reintroduced deadlock fails the test instead of hanging the suite.
func TestRunningProvider_RecordCrash_DoesNotDeadlockOnHadHeartbeatFailure(t *testing.T) {
	rp := &RunningProvider{Name: "os", heartbeatFailed: true}

	done := make(chan struct{})
	var crashErr error
	go func() {
		defer close(done)
		crashErr, _ = rp.recordCrash(func() error {
			return errors.New(buildCrashDiagnostics(rp))
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recordCrash deadlocked calling into a buildErr that also takes shutdownLock")
	}
	if crashErr == nil {
		t.Fatal("recordCrash returned a nil crash error")
	}
}

// TestRunningProvider_RecordCrash_ConcurrentCallersAgreeOnOneDiagnostic
// exercises the double-checked-locking race window directly: several
// goroutines race to be the one that records the crash. Exactly one must see
// first=true, and every goroutine must get back the same stored error even
// though each built its own candidate concurrently.
func TestRunningProvider_RecordCrash_ConcurrentCallersAgreeOnOneDiagnostic(t *testing.T) {
	rp := &RunningProvider{Name: "os"}

	const n = 20
	var wg sync.WaitGroup
	results := make([]error, n)
	firsts := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], firsts[i] = rp.recordCrash(func() error {
				return fmt.Errorf("candidate diagnostic %d", i)
			})
		}(i)
	}
	wg.Wait()

	firstCount := 0
	for _, f := range firsts {
		if f {
			firstCount++
		}
	}
	assert.Equal(t, 1, firstCount, "exactly one caller records the crash")

	for i := 1; i < n; i++ {
		assert.Equal(t, results[0].Error(), results[i].Error(), "every caller sees the same stored diagnostic")
	}
}
