// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !darwin && !linux && !windows

// This file stubs out the Darwin route detection for every other unix build
// (freebsd, netbsd, openbsd, dragonfly, solaris, aix).
package networkinterface

import (
	"github.com/cockroachdb/errors"
)

// The real implementation lives in darwin_routes.go behind a darwin build tag,
// because golang.org/x/net/route only builds on the targets Go supports it on.
// linux and windows each carry their own stub; without one here the package
// does not compile at all on any other platform, since routes.go references
// *darwinRouteDetector in a switch case that is compiled on every platform.
// The case never runs off darwin, but the method still has to exist for the
// type to satisfy operatingSystemRouteDetector.
func (*darwinRouteDetector) List() ([]Route, error) {
	return nil, errors.New("Darwin route detection is not available on this platform")
}
