// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"sync"

	"github.com/cockroachdb/errors"
)

var DefaultOsIDs = []string{
	"go.mondoo.com/mql/providers/os",
	// DEPRECATED, remove in v15.0 vv
	// We specify providers without versions now, so as of v14 the os provider
	// built from this tree only ever reports the ID above. These two are kept
	// for os provider binaries released before the ID change: providers are
	// versioned independently of the engine, so a v14+ engine still meets them,
	// and without these the CLI loses its default local connector.
	// Remove them (and the providers GetFirstID function, which exists only for
	// this use-case) once v13 providers are out of support.
	"go.mondoo.com/cnquery/v9/providers/os",
	"go.mondoo.com/mql/providers/os",
	// ^^
}

var (
	defaultRuntime      *Runtime
	defaultRuntimeMutex sync.Mutex
)

func DefaultRuntime() *Runtime {
	defaultRuntimeMutex.Lock()
	defer defaultRuntimeMutex.Unlock()
	if defaultRuntime == nil {
		defaultRuntime = Coordinator.NewRuntime()
	}
	return defaultRuntime
}

func SetDefaultRuntime(rt *Runtime) error {
	if rt == nil {
		return errors.New("attempted to set default runtime to null")
	}
	defaultRuntimeMutex.Lock()
	defaultRuntime = rt
	defaultRuntimeMutex.Unlock()
	return nil
}
