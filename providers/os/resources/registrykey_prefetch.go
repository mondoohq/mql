// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io"
	goruntime "runtime"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// registryPrefetchKey is where a runtime keeps its registry prefetch, among
// its resources. No resource id starts with a NUL, so it can't collide.
const registryPrefetchKey = "registrykey\x00\x00prefetch"

// registryPrefetchResource keeps a connection's registry.Prefetch with the
// runtime, so it lives and ends with the connection.
type registryPrefetchResource struct {
	prefetch *registry.Prefetch
}

func (r *registryPrefetchResource) MqlID() string   { return "\x00prefetch" }
func (r *registryPrefetchResource) MqlName() string { return "registrykey" }

var registryPrefetchLock sync.Mutex

// registryPrefetch returns the runtime's registry prefetch, creating it on
// first use, or nil when reads on this connection are not prefetched.
func registryPrefetch(runtime *plugin.Runtime) *registry.Prefetch {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil
	}
	// Recordings and mocks replay the commands they hold, one per key.
	if _, isMock := conn.(*mock.Connection); isMock {
		return nil
	}
	// On the machine itself keys are read natively; PowerShell is only the
	// fallback after a native error, which a prefetch should not turn into a
	// read of whole roots.
	if conn.Type() == shared.Type_Local && goruntime.GOOS == "windows" {
		return nil
	}

	if p := storedRegistryPrefetch(runtime); p != nil {
		return p
	}
	// the lock only guards creating it, so two reads don't both create one
	registryPrefetchLock.Lock()
	defer registryPrefetchLock.Unlock()
	if p := storedRegistryPrefetch(runtime); p != nil {
		return p
	}
	p := registry.NewPrefetch(func(script string) (io.Reader, int, error) {
		cmd, err := conn.RunCommand(powershell.Encode(script))
		if err != nil {
			return nil, 0, err
		}
		return cmd.Stdout, cmd.ExitStatus, nil
	}, nil)
	runtime.Resources.Set(registryPrefetchKey, &registryPrefetchResource{prefetch: p})
	return p
}

func storedRegistryPrefetch(runtime *plugin.Runtime) *registry.Prefetch {
	if r, ok := runtime.Resources.Get(registryPrefetchKey); ok {
		if pr, ok := r.(*registryPrefetchResource); ok {
			return pr.prefetch
		}
	}
	return nil
}

// prefetchedItems answers a PowerShell read of the key at path from the
// connection's registry prefetch. ok is false when the prefetch cannot answer
// and the key must be read alone.
func (k *mqlRegistrykey) prefetchedItems(path string) (items []registry.RegistryKeyItem, exists bool, ok bool) {
	p := registryPrefetch(k.MqlRuntime)
	if p == nil {
		return nil, false, false
	}
	switch res, items := p.Lookup(path); res {
	case registry.PrefetchFound:
		return items, true, true
	case registry.PrefetchMissing:
		return nil, false, true
	}
	return nil, false, false
}
