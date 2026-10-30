// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"io/fs"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// iacProber connects candidates in the providers they belong to, on one runtime
// that serves the whole walk (ADR 045 §2).
//
// Two properties of this shape are load-bearing, and both come from how the
// coordinator accounts for runtimes:
//
// One runtime, not one per candidate. Runtime.Close ends in
// coordinator.RemoveRuntime, which stops every provider no runtime still
// references, and a probe runtime is the only holder of the provider it
// started. Closing one per candidate would therefore be a provider spawn and
// teardown per candidate -- rejected candidates included, since the provider is
// started before Connect can say no. On a monorepo where every *.yaml is a
// candidate for k8s, cloudformation and ansible, that is hundreds of spawns.
//
// Never through Runtime.Connect. That sets Provider.Connection, and
// unsafeRefreshRuntimes -- which runs under any RuntimeFor or RemoveRuntime,
// from any goroutine -- indexes a runtime under its current asset's platform
// IDs. A reused probe runtime connected to a child at that moment would be
// indexed under the child, the entry would outlive the Disconnect, and
// discovery's later RuntimeFor would hand back this runtime instead of a fresh
// one: createRuntimeForAsset would see a foreign connection and silently drop
// the asset as a duplicate. Calling the plugin directly keeps rt.asset() nil
// for the runtime's whole life, so it is never indexed and Close leaves nothing
// stale behind. It also skips registering each probe with the recording and
// running the provider-switch stopgap, neither of which a probe wants.
type iacProber struct {
	parent   *Runtime
	rt       *Runtime
	features []byte
}

func newIacProber(parent *Runtime, features []byte) *iacProber {
	// NewRuntime, not NewRuntimeFrom: NewRuntimeFrom copies the parent's
	// *ConnectedProvider pointers, and tryShutdown disconnects every one of
	// them that carries a connection -- the parent's own. It would also share
	// the parent's recording, so closing the probe runtime would save it
	// mid-walk.
	rt := parent.coordinator.NewRuntime()
	rt.AutoUpdate = parent.AutoUpdate
	rt.UpstreamConfig = parent.UpstreamConfig

	return &iacProber{parent: parent, rt: rt, features: features}
}

// Probe implements walk.Prober.
func (p *iacProber) Probe(child *inventory.Asset) (*plugin.ConnectRes, error) {
	// DetectProvider resolves the connection type to a provider, installing it
	// on demand under the parent's AutoUpdate, and starts it. The coordinator
	// hands back the already-running instance for every probe after the first.
	if err := p.rt.DetectProvider(child); err != nil {
		return nil, err
	}

	child.Connections[0].Id = Coordinator.NextConnectionId()

	callbacks := providerCallbacks{runtime: p.rt}
	res, err := p.rt.Provider.Instance.Plugin.Connect(&plugin.ConnectReq{
		Asset:    child,
		Features: p.features,
		// Upstream is deliberately absent: every provider's connect calls
		// InitClient on it, which parses a service-account key, and no provider
		// needs upstream to decide whether a folder is its own. The real
		// connect in discovery/ supplies it.
	}, &callbacks)

	// Keyed off the connection id rather than off a nil error, because a
	// provider can hand back a live connection alongside a failure. Each probe
	// is disconnected as soon as its answer is read: UseProvider builds a fresh
	// ConnectedProvider every time, so the previous one is orphaned out of the
	// map where tryShutdown can no longer reach it, and the connections would
	// accumulate inside the child process for the whole scan.
	if res != nil && res.Id != 0 {
		if _, derr := p.rt.Provider.Instance.Plugin.Disconnect(&plugin.DisconnectReq{Connection: res.Id}); derr != nil {
			log.Debug().Err(derr).Str("provider", p.rt.Provider.Instance.Name).
				Msg("iac: could not disconnect a probe")
		}
	}

	if err != nil {
		return nil, err
	}
	return res, nil
}

// Close is called once, after the walk. Whatever providers the walk started
// stay up until here, so a monorepo costs one start per provider rather than
// one per candidate.
func (p *iacProber) Close() {
	p.rt.Close()
}

// singleFileFS is the tree of a scan that targeted one file: the file's own
// directory, holding only that file.
//
// It exists so a file target reaches both kinds of opt-in -- a PerFile one
// takes the file, a directory one takes the containing folder -- without the
// rest of that folder joining the scan, which the user did not ask for.
type singleFileFS struct {
	dir  fs.FS
	name string
}

func (f singleFileFS) Open(name string) (fs.File, error) {
	if name == "." || name == f.name {
		return f.dir.Open(name)
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (f singleFileFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	entries, err := fs.ReadDir(f.dir, ".")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() == f.name {
			return []fs.DirEntry{entry}, nil
		}
	}
	return nil, nil
}
