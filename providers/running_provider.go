// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/rs/zerolog/log"
	pp "go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// connectionGraphNode is a node in the connection graph. It represents a connection.
type connectionGraphNode struct {
	// explicitlyConnected is true if the connection was explicitly connected
	// it is set to false when explicitly disconnected.
	// When reconnecting, disconnected connections are not set to explicitly connected,
	// even if we require the connection to connect another connection.
	explicitlyConnected bool
	// data is the connect request data for the connection
	data connectReq
}

// connectionGraph is a directed graph of connections.
// Each node represents a connection. It can have one edge to its parent connection.
//
// When a connection is first connected, addNode is called to add the connection to the graph
// and keep track of the connect request data. This is also when setEdge is called to set the
// edge to the parent connection.
//
// When a connection is disconnected, markDisconnected is called to mark the connection as disconnected.
// When a connection is marked as disconnected, it indicates that the connection is not explicitly required.
// It is still possible that the connection needs to be reconnected if another connection has it set as its
// parent.
// This is also when garbageCollect is called to remove connections from the graph is they are not explicitly
// connected and are not required by any other connection.
type connectionGraph struct {
	// nodes is a map of connection id to connectionGraphNode. We store data to
	// reestablish the connection when reconnecting. We also store if the connection
	// has been disconnected.
	nodes map[uint32]connectionGraphNode
	// edges is a map of connection id to parent connection id
	edges map[uint32]uint32
	// collectedNodes preserves connect request data for nodes removed by
	// garbageCollect. A later Connect() call with a ParentConnectionId
	// pointing to a collected node can use this data to transparently
	// reconnect the parent before connecting the child.
	//
	// Bounded by: addNode/addImplicitNode remove entries for re-added
	// IDs, and Reconnect() clears this map since stale data from before
	// a provider restart is no longer meaningful.
	collectedNodes map[uint32]connectReq
}

func newConnectionGraph() *connectionGraph {
	return &connectionGraph{
		nodes:          map[uint32]connectionGraphNode{},
		edges:          map[uint32]uint32{},
		collectedNodes: map[uint32]connectReq{},
	}
}

// addNode adds a node to the graph with the given data.
// If the node was previously garbage-collected, its stale entry in
// collectedNodes is removed since the fresh data supersedes it.
func (c *connectionGraph) addNode(node uint32, data connectReq) {
	c.nodes[node] = connectionGraphNode{
		explicitlyConnected: true,
		data:                data,
	}
	delete(c.collectedNodes, node)
}

// addImplicitNode adds a node that is NOT explicitly connected — it was
// reconnected on behalf of a child, not by a direct user request. The node
// will be kept alive by topoSort as long as an explicitly-connected child
// references it, and garbage-collected once all such children disconnect.
func (c *connectionGraph) addImplicitNode(node uint32, data connectReq) {
	c.nodes[node] = connectionGraphNode{
		explicitlyConnected: false,
		data:                data,
	}
	delete(c.collectedNodes, node)
}

// getNode returns the connect request data for the given node.
func (c *connectionGraph) getNode(node uint32) (connectReq, bool) {
	n, ok := c.nodes[node]
	if !ok {
		return connectReq{}, false
	}
	return n.data, ok
}

// setEdge sets the edge from the from node to the to node.
// from is the child node and to is the parent node.
func (c *connectionGraph) setEdge(from, to uint32) {
	c.edges[from] = to
}

// markDisconnected marks the connection as disconnected. It may still be needed by other connections.
func (c *connectionGraph) markDisconnected(id uint32) {
	if node, ok := c.nodes[id]; ok {
		node.explicitlyConnected = false
		c.nodes[id] = node
	}
}

// topoSort returns a topological sorted list of the nodes in the graph. Connecting in this order
// will ensure that all connections are connected in the correct order.
func (c *connectionGraph) topoSort() []uint32 {
	var sorted []uint32
	var visit func(node uint32, visited map[uint32]bool, sorted *[]uint32)
	visit = func(node uint32, visited map[uint32]bool, sorted *[]uint32) {
		if visited[node] {
			return
		}
		visited[node] = true
		if connected, ok := c.edges[node]; ok {
			if connected != 0 {
				visit(connected, visited, sorted)
			}
		}
		*sorted = append(*sorted, node)
	}
	visited := map[uint32]bool{}
	for nodeId, node := range c.nodes {
		if !node.explicitlyConnected {
			continue
		}
		visit(nodeId, visited, &sorted)
	}
	return sorted
}

// garbageCollect removes nodes from the graph that are not explicitly
// connected and are not required by any other connection.
// The connect request data of collected nodes is preserved in
// collectedNodes so that a future child connection can transparently
// reconnect a garbage-collected parent.
func (c *connectionGraph) garbageCollect() []uint32 {
	sorted := c.topoSort()

	keep := map[uint32]struct{}{}
	for _, node := range sorted {
		keep[node] = struct{}{}
	}

	collected := []uint32{}
	for node := range c.nodes {
		if _, ok := keep[node]; !ok {
			collected = append(collected, node)
			c.collectedNodes[node] = c.nodes[node].data
			delete(c.nodes, node)
			delete(c.edges, node)
		}
	}

	return collected
}

// getCollectedNode returns the preserved connect request data for a
// node that was previously removed by garbageCollect.
func (c *connectionGraph) getCollectedNode(id uint32) (connectReq, bool) {
	cr, ok := c.collectedNodes[id]
	return cr, ok
}

type (
	ReconnectFunc func() (pp.ProviderPlugin, *plugin.Client, error)
	connectReq    struct {
		req *pp.ConnectReq
		cb  pp.ProviderCallback
	}
)

const maxRestartCount = 3

type RestartableProvider struct {
	plugin          pp.ProviderPlugin
	client          *plugin.Client
	connectionGraph *connectionGraph
	reconnectFunc   ReconnectFunc
	restartCount    int
	lock            sync.Mutex
}

func (r *RestartableProvider) Client() *plugin.Client {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.client
}

// Connect implements plugin.ProviderPlugin.
func (r *RestartableProvider) Connect(req *pp.ConnectReq, cb pp.ProviderCallback) (*pp.ConnectRes, error) {
	var parentToReconnect *connectReq

	if len(req.Asset.GetConnections()) > 0 {
		reqClone := req.CloneVT()
		r.lock.Lock()
		connectionId := req.Asset.Connections[0].Id
		parentId := req.Asset.Connections[0].ParentConnectionId
		if _, ok := r.connectionGraph.getNode(connectionId); !ok {
			r.connectionGraph.addNode(connectionId, connectReq{
				req: reqClone,
				cb:  cb,
			})
			r.connectionGraph.setEdge(connectionId, parentId)
		}

		// If the parent was garbage-collected (its runtime was disconnected
		// because all previous children finished), we need to reconnect it
		// before connecting this child. The preserved connect data lets us
		// re-establish the parent's runtime transparently.
		if parentId > 0 {
			if _, inGraph := r.connectionGraph.getNode(parentId); !inGraph {
				if cr, ok := r.connectionGraph.getCollectedNode(parentId); ok {
					parentToReconnect = &cr
				}
			}
		}

		r.lock.Unlock()
	}

	if parentToReconnect != nil {
		parentId := req.Asset.Connections[0].ParentConnectionId

		// Re-check under lock: a concurrent Connect for a sibling child
		// may have already reconnected this parent.
		r.lock.Lock()
		_, alreadyBack := r.connectionGraph.getNode(parentId)
		r.lock.Unlock()

		if !alreadyBack {
			if _, err := r.plugin.Connect(parentToReconnect.req, parentToReconnect.cb); err != nil {
				return nil, fmt.Errorf("failed to reconnect garbage-collected parent %d: %w", parentId, err)
			} else {
				r.lock.Lock()
				if _, ok := r.connectionGraph.getNode(parentId); !ok {
					r.connectionGraph.addImplicitNode(parentId, *parentToReconnect)
					if parentToReconnect.req != nil && len(parentToReconnect.req.Asset.GetConnections()) > 0 {
						r.connectionGraph.setEdge(parentId, parentToReconnect.req.Asset.Connections[0].ParentConnectionId)
					}
				}
				r.lock.Unlock()
			}
		}
	}

	resp, err := r.plugin.Connect(req, cb)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (r *RestartableProvider) Reconnect() error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.restartCount >= maxRestartCount {
		return errors.New("reached maximum provider restart count")
	}
	r.restartCount++

	p, c, err := r.reconnectFunc()
	if err != nil {
		return fmt.Errorf("failed to reconnect: %w", err)
	}
	r.plugin = p
	r.client = c
	clear(r.connectionGraph.collectedNodes)

	connectRequestOrder := r.connectionGraph.topoSort()

	for _, connect := range connectRequestOrder {
		cr, ok := r.connectionGraph.getNode(connect)
		if !ok {
			continue
		}

		if _, err := r.plugin.Connect(cr.req, cr.cb); err != nil {
			return fmt.Errorf("failed to reconnect connection %d: %w", connect, err)
		}
	}

	return nil
}

// Disconnect implements plugin.ProviderPlugin.
func (r *RestartableProvider) Disconnect(req *pp.DisconnectReq) (*pp.DisconnectRes, error) {
	r.lock.Lock()
	r.connectionGraph.markDisconnected(req.Connection)
	collected := r.connectionGraph.garbageCollect()
	// Check whether the requested connection survived GC (children keep it
	// alive). Must be checked under the lock since another goroutine's
	// Connect/Disconnect can mutate the graph concurrently.
	requestedCollected := slices.Contains(collected, req.Connection)
	keptByChildren := false
	if !requestedCollected {
		_, keptByChildren = r.connectionGraph.getNode(req.Connection)
	}
	r.lock.Unlock()

	// Only disconnect the requested connection from the provider if GC
	// actually collected it. When children still reference this connection
	// (GC kept it in the graph), the Service-layer runtime must stay alive
	// so children can share its resource cache. GC will disconnect it later
	// once all children are done.
	//
	// The else branch also covers double-disconnect (node absent from graph
	// entirely); the plugin handles unknown connection IDs as a no-op.
	var resp *pp.DisconnectRes
	var err error
	if keptByChildren {
		resp = &pp.DisconnectRes{}
	} else {
		resp, err = r.plugin.Disconnect(req)
	}

	for _, c := range collected {
		if c == req.Connection {
			continue
		}
		_, disconnectErr := r.plugin.Disconnect(&pp.DisconnectReq{
			Connection: c,
		})
		if disconnectErr != nil {
			log.Warn().Err(disconnectErr).Uint32("connection", c).Msg("failed to disconnect garbage collected connection")
		}
	}

	return resp, err
}

// GetData implements plugin.ProviderPlugin.
func (r *RestartableProvider) GetData(req *pp.DataReq) (*pp.DataRes, error) {
	return r.plugin.GetData(req)
}

// Heartbeat implements plugin.ProviderPlugin.
func (r *RestartableProvider) Heartbeat(req *pp.HeartbeatReq) (*pp.HeartbeatRes, error) {
	return r.plugin.Heartbeat(req)
}

// Translations implements plugin.ProviderPlugin.
func (r *RestartableProvider) Translations(req *pp.TranslationsReq) (*pp.TranslationsRes, error) {
	return r.plugin.Translations(req)
}

// ResolveAsset implements plugin.ProviderPlugin.
func (r *RestartableProvider) ResolveAsset(req *pp.ResolveAssetReq) (*pp.ResolveAssetRes, error) {
	return r.plugin.ResolveAsset(req)
}

// MockConnect implements plugin.ProviderPlugin.
func (r *RestartableProvider) MockConnect(req *pp.ConnectReq, callback pp.ProviderCallback) (*pp.ConnectRes, error) {
	return r.plugin.MockConnect(req, callback)
}

// ParseCLI implements plugin.ProviderPlugin.
func (r *RestartableProvider) ParseCLI(req *pp.ParseCLIReq) (*pp.ParseCLIRes, error) {
	return r.plugin.ParseCLI(req)
}

// Shutdown implements plugin.ProviderPlugin.
func (r *RestartableProvider) Shutdown(req *pp.ShutdownReq) (*pp.ShutdownRes, error) {
	return r.plugin.Shutdown(req)
}

// StoreData implements plugin.ProviderPlugin.
func (r *RestartableProvider) StoreData(req *pp.StoreReq) (*pp.StoreRes, error) {
	return r.plugin.StoreData(req)
}

var _ pp.ProviderPlugin = &RestartableProvider{}

type RunningProvider struct {
	Name    string
	ID      string
	Version string
	Plugin  pp.ProviderPlugin
	Schema  resources.ResourcesSchema
	// Requires are the peers this provider declares (ADR 042). Carried on the
	// running provider so the cross-provider gate can read the caller's own
	// declarations without asking the coordinator for a cloned provider map on
	// every foreign field access.
	Requires []pp.ProviderDep
	// Root is the resource that roots this provider's asset tree (ADR 031),
	// carried here for the same reason as Requires: the compiler asks for it on
	// every compile, and it must not cost a coordinator lookup.
	Root string

	// isClosed is true for any provider that is not running anymore,
	// either via shutdown or via crash
	isClosed bool
	// isShutdown is only used once during provider shutdown
	isShutdown bool
	// heartbeatFailed is set when a heartbeat probe fails and triggers
	// Shutdown(). It distinguishes "we proactively closed the connection
	// because the plugin stopped responding" from "the plugin process
	// crashed on its own" — both surface as gRPC Unavailable downstream.
	heartbeatFailed bool
	// startedAt records when SupervisedRunningProvider returned; used to
	// report uptime in crash messages so we can tell quick startup crashes
	// apart from after-N-minutes failures.
	startedAt time.Time
	// crashLog captures the plugin subprocess's stderr in a ring buffer so
	// we can include the most recent stderr (typically a runtime fatal or
	// panic stack trace) in the error attached to Runtime.CriticalErrors.
	crashLog *crashLogBuffer
	// proc tracks the plugin subprocess so crash diagnostics can report its
	// exit disposition (exit code vs. signal, peak RSS) after it dies. Nil
	// for builtin providers and providers constructed without a subprocess.
	proc *processTracker
	// exitGraceExpired memoizes that awaitExit already waited a full grace
	// period without the subprocess exiting, so subsequent crash-diagnostic
	// builds don't each re-pay the wait for a hung-but-alive provider.
	// Reset on successful reconnect.
	exitGraceExpired atomic.Bool
	// killedSelf records that we sent the kill signal to the subprocess
	// ourselves (shutdown, heartbeat-triggered or otherwise). It lets crash
	// diagnostics distinguish our own SIGKILL from an external one — the
	// latter, with an empty stderr tail, is the OOM-killer fingerprint.
	killedSelf atomic.Bool
	// provider errors which are evaluated and printed during shutdown of the provider
	err          error
	lock         sync.Mutex
	shutdownLock sync.Mutex
	interval     time.Duration
	gracePeriod  time.Duration
	hbCancelFunc context.CancelFunc
}

func SupervisedRunningProvider(name string, id string, plugin pp.ProviderPlugin, client *plugin.Client, schema resources.ResourcesSchema, reconnectFunc ReconnectFunc) (*RunningProvider, error) {
	hbCtx, hbCancelFunc := context.WithCancel(context.Background())

	rp := &RunningProvider{
		Name:      name,
		ID:        id,
		Schema:    schema,
		isClosed:  false,
		startedAt: time.Now(),
		Plugin: &RestartableProvider{
			plugin:          plugin,
			client:          client,
			connectionGraph: newConnectionGraph(),
			reconnectFunc:   reconnectFunc,
		},
		hbCancelFunc: hbCancelFunc,
		interval:     2 * time.Second,
		gracePeriod:  3 * time.Second,
	}

	if err := rp.heartbeat(hbCtx, hbCancelFunc); err != nil {
		return nil, err
	}

	return rp, nil
}

// initialize the heartbeat with the provider
func (p *RunningProvider) heartbeat(ctx context.Context, cancelFunc context.CancelFunc) error {
	// The first beat is synchronous: a provider we cannot reach at all is a
	// startup failure. Lateness is not — retry it just like the loop below does.
	err := p.doOneHeartbeat(p.interval + p.gracePeriod)
	for late := 1; errors.Is(err, errHeartbeatLate) && late <= maxLateHeartbeats; late++ {
		log.Warn().Str("plugin", p.Name).Int("consecutive", late).
			Msg("plugin heartbeat is late, provider is not answering in time")
		err = p.doOneHeartbeat(p.interval + p.gracePeriod)
	}
	if err != nil {
		log.Error().Err(err).Str("plugin", p.Name).Msg("error in plugin heartbeat")
		p.shutdownLock.Lock()
		p.heartbeatFailed = true
		p.shutdownLock.Unlock()
		if err := p.Shutdown(); err != nil {
			log.Error().Err(err).Str("plugin", p.Name).Msg("error in plugin shutdown")
		}
		return err
	}

	go func() {
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()
		late := 0
		for !p.isCloseOrShutdown() {
			err := p.doOneHeartbeat(p.interval + p.gracePeriod)
			switch {
			case err == nil:
				late = 0
			case errors.Is(err, errHeartbeatLate) && late < maxLateHeartbeats:
				// The provider is alive but did not answer in time. That is a
				// loaded host, not a dead plugin: killing it here would throw
				// away the whole scan's work and report it as a crash.
				late++
				log.Warn().Str("plugin", p.Name).Int("consecutive", late).
					Msg("plugin heartbeat is late, provider is not answering in time")
			default:
				log.Error().Err(err).Str("plugin", p.Name).Msg("error in plugin heartbeat")
				p.shutdownLock.Lock()
				p.heartbeatFailed = true
				p.shutdownLock.Unlock()
				if err := p.Shutdown(); err != nil {
					log.Error().Err(err).Str("plugin", p.Name).Msg("error in plugin shutdown")
				}
				return
			}

			select {
			case <-ctx.Done():
				cancelFunc()
				return
			case <-ticker.C:

			}
		}
	}()

	return nil
}

// maxLateHeartbeats is how many consecutive heartbeats may time out before we
// treat the provider as dead. The provider's own watchdog holds out for several
// windows while it is serving requests, and we have to be at least as patient:
// both sides exiting on the first missed beat is what turns a momentarily
// starved host into a crash report.
const maxLateHeartbeats = 6

// errHeartbeatLate marks a heartbeat that did not complete within its window.
// Unlike a transport error it does not imply the provider is gone.
var errHeartbeatLate = errors.New("heartbeat did not complete in time")

func (p *RunningProvider) doOneHeartbeat(t time.Duration) error {
	_, err := p.Plugin.Heartbeat(&pp.HeartbeatReq{
		Interval: uint64(t),
	})
	if err != nil {
		switch status.Code(err) {
		case codes.DeadlineExceeded:
			return fmt.Errorf("%w for %s after %s", errHeartbeatLate, p.Name, t)
		case codes.Unimplemented:
			return errors.New("please update the provider plugin for " + p.Name)
		}
		log.Err(err).Str("plugin", p.Name).Msg("error in plugin heartbeat")
		return errors.New("cannot establish heartbeat with the provider plugin for " + p.Name)
	}
	return nil
}

func (p *RunningProvider) isCloseOrShutdown() bool {
	p.shutdownLock.Lock()
	defer p.shutdownLock.Unlock()
	return p.isClosed || p.isShutdown
}

func (p *RunningProvider) Reconnect() error {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.shutdownLock.Lock()
	defer p.shutdownLock.Unlock()
	if !p.isClosed && !p.isShutdown {
		return nil
	}

	// we can only restart if it is a restartable provider
	if rp, ok := p.Plugin.(*RestartableProvider); ok {
		log.Warn().Str("plugin", p.Name).Msg("reconnecting provider")
		if err := rp.Reconnect(); err != nil {
			log.Error().Err(err).Str("plugin", p.Name).Msg("error in plugin reconnect")
			return err
		}
		p.isClosed = false
		p.isShutdown = false
		p.exitGraceExpired.Store(false)
		p.killedSelf.Store(false)
		hbCtx, hbCancelFunc := context.WithCancel(context.Background())
		if p.hbCancelFunc != nil {
			p.hbCancelFunc()
		}
		p.hbCancelFunc = hbCancelFunc
		return p.heartbeat(hbCtx, hbCancelFunc)
	}

	return errors.New("provider is not restartable")
}

func (p *RunningProvider) Shutdown() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.isShutdown {
		return nil
	}

	// This is an error that happened earlier, so we print it directly.
	// The error this function returns is about failing to shutdown.
	if p.err != nil {
		log.Error().Msg(p.err.Error())
	}

	var err error
	if !p.isClosed {
		_, err = p.Plugin.Shutdown(&pp.ShutdownReq{})
		if err != nil {
			log.Debug().Err(err).Str("plugin", p.Name).Msg("error in plugin shutdown")
		}

		// If the plugin was not in active use, we may not have a client at this
		// point. Since all of this is run within a sync-lock, we can check the
		// client and if it exists use it to send the kill signal.
		if rp, ok := p.Plugin.(*RestartableProvider); ok {
			c := rp.Client()
			if c != nil {
				p.killedSelf.Store(true)
				c.Kill()
			}
		}
		p.shutdownLock.Lock()
		p.isClosed = true
		p.isShutdown = true
		p.shutdownLock.Unlock()
	} else {
		p.shutdownLock.Lock()
		p.isShutdown = true
		p.shutdownLock.Unlock()
	}

	return err
}

func (p *RunningProvider) KillClient() {
	if rp, ok := p.Plugin.(*RestartableProvider); ok {
		c := rp.Client()
		if c != nil {
			p.killedSelf.Store(true)
			c.Kill()
		}
	}
}

// wasKilledLocally reports whether we sent the subprocess its kill signal
// ourselves, so crash diagnostics don't misread our own SIGKILL as the
// OOM killer's.
func (p *RunningProvider) wasKilledLocally() bool {
	return p.killedSelf.Load()
}

// awaitExit waits up to grace for the plugin subprocess to be reaped,
// reporting whether it exited and, if so, its exit state. An in-flight RPC
// fails the instant the child's socket dies — usually before go-plugin's
// exit-watcher goroutine has waited on the process — so crash diagnostics
// built immediately would see "still running" and miss the exit
// disposition. Reaping a dead direct child settles within milliseconds; the
// grace bound only matters for the true-hang case, where the process really
// is still running.
//
// It reads exclusively from the process tracker: consulting the
// RestartableProvider's client here would block on its lock, which
// Reconnect() holds for the full duration of re-establishing every tracked
// connection. The wait is also memoized — handlePluginError builds
// diagnostics once per failed RPC, and a hung-but-alive provider must stall
// the first of them at most, not every one.
// Returns immediately when no subprocess is tracked (builtin providers).
func (p *RunningProvider) awaitExit(grace time.Duration) (bool, *os.ProcessState) {
	if p.proc == nil {
		return false, nil
	}
	if exited, ps := p.proc.exitInfo(); exited {
		return true, ps
	}
	if p.exitGraceExpired.Load() {
		return false, nil
	}
	deadline := time.Now().Add(grace)
	for {
		time.Sleep(25 * time.Millisecond)
		if exited, ps := p.proc.exitInfo(); exited {
			return true, ps
		}
		if time.Now().After(deadline) {
			p.exitGraceExpired.Store(true)
			return false, nil
		}
	}
}

// uptime reports how long the provider has been running. Zero if startedAt
// was never set (e.g. for builtin providers constructed directly).
func (p *RunningProvider) uptime() time.Duration {
	if p.startedAt.IsZero() {
		return 0
	}
	return time.Since(p.startedAt)
}

// crashTail returns the most recent stderr lines that look like a Go runtime
// fatal or panic stack trace, or nil if no panic-like marker was captured.
func (p *RunningProvider) crashTail() []string {
	if p.crashLog == nil {
		return nil
	}
	return p.crashLog.CrashTail()
}

// stderrSnapshot returns the full ring-buffer contents of recent plugin stderr.
// Used as a fallback when crashTail returns nothing — for OS-level kills
// (SIGKILL by OOM, etc.) the process may not write anything panic-shaped before
// dying, but earlier debug logs can still hint at what was happening.
func (p *RunningProvider) stderrSnapshot() []string {
	if p.crashLog == nil {
		return nil
	}
	return p.crashLog.Snapshot()
}

// hadHeartbeatFailure reports whether this provider was Shutdown by the
// heartbeat watcher rather than dying on its own. Used to distinguish "plugin
// stopped responding to heartbeats" from "plugin process crashed."
func (p *RunningProvider) hadHeartbeatFailure() bool {
	p.shutdownLock.Lock()
	defer p.shutdownLock.Unlock()
	return p.heartbeatFailed
}

// crashError returns the diagnostic error already recorded for this provider
// if it is known dead, or nil while it is still considered alive. Callers use
// it to short-circuit before making an RPC to a plugin process that is not
// coming back — e.g. a dead loopback port on Windows just answers "connection
// refused" for every further call, so there is nothing to gain by dialing it
// again for each remaining field.
func (p *RunningProvider) crashError() error {
	p.shutdownLock.Lock()
	defer p.shutdownLock.Unlock()
	if p.isClosed && p.err != nil {
		return p.err
	}
	return nil
}

// recordCrash marks the provider closed and stores buildErr() as its crash
// diagnostic, unless a diagnostic is already stored for it — in which case
// the existing one is returned unchanged and first is false. This collapses
// every field that fails after a single crash into the one diagnostic (and
// one critical-error entry) recorded for the failure that discovered it,
// instead of rebuilding buildCrashDiagnostics and adding a fresh critical
// error per field.
//
// buildErr is called without shutdownLock held: it is normally
// buildCrashDiagnostics, which itself calls hadHeartbeatFailure and would
// deadlock on a non-reentrant lock. That means two callers can race to build
// a diagnostic concurrently for the same crash; the loser's error is
// discarded and it returns the winner's instead, so exactly one diagnostic
// ever gets stored.
//
// buildErr runs outside the lock and is caller-supplied (buildCrashDiagnostics
// today, but recordCrash doesn't know that), so it's treated as fallible: a
// panic inside it (e.g. a nil crashLog, an unexpected nil somewhere in the
// diagnostic assembly) is recovered by callBuildErr below and turned into a
// plain error carrying the panic value. Without that, the panic would
// unwind straight out of recordCrash with shutdownLock already released from
// the first check above but isClosed/err never set — the provider would be
// left neither known-crashed nor able to record one on retry, and the panic
// itself would propagate to whatever called handlePluginError instead of
// producing a crash diagnostic. Recovering keeps the guarantee this function
// exists for: a crash is always recorded, exactly once.
func (p *RunningProvider) recordCrash(buildErr func() error) (crashErr error, first bool) {
	p.shutdownLock.Lock()
	if p.isClosed && p.err != nil {
		defer p.shutdownLock.Unlock()
		return p.err, false
	}
	p.shutdownLock.Unlock()

	built := callBuildErr(p.Name, buildErr)

	p.shutdownLock.Lock()
	defer p.shutdownLock.Unlock()
	if p.isClosed && p.err != nil {
		return p.err, false
	}
	p.isClosed = true
	p.err = built
	return p.err, true
}

// callBuildErr runs buildErr and recovers a panic inside it, falling back to
// a plain error that includes the panic value so recordCrash's caller still
// gets a non-nil diagnostic (and the provider still ends up marked crashed)
// even when assembling the "real" diagnostic itself failed.
func callBuildErr(providerName string, buildErr func() error) (result error) {
	defer func() {
		if r := recover(); r != nil {
			result = fmt.Errorf("the '%s' provider crashed, but building its crash diagnostic panicked: %v", providerName, r)
		}
	}()
	return buildErr()
}
