// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/docker"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

type detect func(r *PlatformResolver, pf *inventory.Platform, conn shared.Connection) (bool, error)

type PlatformResolver struct {
	Name     string
	IsFamily bool
	Children []*PlatformResolver
	Detect   detect

	// Emits lists every platform name this resolver can set, and defaults to
	// the resolver's own Name when it is nil. A resolver does not always emit
	// the name it is registered under: "oracle" only ever emits "oraclelinux",
	// and "centos" also claims Rocky and AlmaLinux.
	//
	// Every name detection can produce has to reach osTree, or the platform has
	// no family chain and the provider catalog does not list it, which degrades
	// it to "unknown" in plugin.PlatformInfo.Apply. Listing the names instead of
	// assuming Name also keeps the reverse out: a registered name that nothing
	// can emit would sit in the tree and the catalog as a platform that never
	// appears on any asset.
	//
	// A resolver that names nothing, such as the unknown-os fallback, declares
	// an empty, non-nil list.
	Emits []string
}

// isUnidentifiedPlatform reports whether detection could not pin down which
// system this actually is. Container images in that state are reported as
// "scratch" instead of by a derived or generic name.
//
// This keys off the resolver that matched rather than the platform name,
// because a resolver does not always emit the name it is registered under (the
// "oracle" resolver emits "oraclelinux", for example).
//
// The generic resolver claiming a system is not on its own enough to call it
// unidentified. It leaves whatever name os-release supplied, and a
// distribution that states ID= has told us exactly what it is even though the
// provider has no resolver for it. Reporting "scratch" there discards an
// identity the image gives outright, which is how Slackware, Deepin and Anolis
// OS images were coming back. An image that names nothing still has no
// distro-id recorded, so it stays unidentified.
func isUnidentifiedPlatform(pf *inventory.Platform, leaf *PlatformResolver) bool {
	if pf.Name == "" {
		return true
	}
	if leaf != defaultLinux {
		return false
	}

	_, namedByOsRelease := pf.Metadata[LabelDistroID]
	return !namedByOsRelease
}

func (r *PlatformResolver) Resolve(conn shared.Connection) (*inventory.Platform, bool) {
	// prepare detect info object
	platform := &inventory.Platform{}
	platform.Family = make([]string, 0)

	// start recursive platform resolution
	pi, leaf, resolved := r.resolvePlatform(platform, conn)

	// if we have a container image use the architecture specified in the transport as it is resolved
	// using the container image properties
	tarConn, ok := conn.(*tar.Connection)
	if resolved && ok {
		pi.Arch = tarConn.PlatformArchitecture
		platform.Runtime = "docker-image"
		platform.Kind = "container-image"

		// if we could not identify the system, we should fallback to the scratch operating system
		if isUnidentifiedPlatform(pi, leaf) {
			platform.Name = "scratch"
			platform.Arch = tarConn.PlatformArchitecture
			return platform, true
		}
	}

	containerConn, ok := conn.(*docker.ContainerConnection)
	if resolved && ok {
		pi.Arch = containerConn.PlatformArchitecture
		platform.Runtime = string(containerConn.Type())
		platform.Kind = "container"

		// if we could not identify the system, we should fallback to the scratch operating system
		if isUnidentifiedPlatform(pi, leaf) {
			platform.Name = "scratch"
			platform.Arch = pi.Arch
			return platform, true
		}
	}

	// If architecture could not be determined via command-based detection
	// (e.g. a filesystem-only scan with no command capability), fall back to
	// inspecting the ELF header of a well-known binary on the target.
	if resolved && pi.Arch == "" {
		if arch := archFromELF(conn.FileSystem()); arch != "" {
			pi.Arch = arch
		}
	}

	log.Debug().Str("platform", pi.Name).Strs("family", pi.Family).Msg("platform> detected os")
	return pi, resolved
}

// Resolve tries to find recursively all
// platforms until a leaf (operating systems) detect
// mechanism is returning true. It also returns the leaf resolver that claimed
// the platform, so callers can tell an identified system apart from one that
// only matched a generic fallback.
func (r *PlatformResolver) resolvePlatform(pf *inventory.Platform, conn shared.Connection) (*inventory.Platform, *PlatformResolver, bool) {
	detected, err := r.Detect(r, pf, conn)
	if err != nil {
		return pf, nil, false
	}

	// if detection is true but we have a family
	if detected && r.IsFamily {
		// we are a family and we may have children to try
		for _, c := range r.Children {
			detected, leaf, resolved := c.resolvePlatform(pf, conn)
			if resolved {
				// add family hierarchy
				detected.Family = append(pf.Family, r.Name)
				return detected, leaf, resolved
			}
		}

		// we reached this point, we know it is the platform but we could not
		// identify the system
		// TODO: add generic platform instance
		// TODO: should we return an error?
	}

	// return if the detect is true and we have a leaf
	if detected && !r.IsFamily {
		return pf, r, true
	}

	// could not find it
	return pf, nil, false
}
