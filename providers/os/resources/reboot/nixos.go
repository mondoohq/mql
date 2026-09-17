// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

const (
	nixosBootedSystemBootJSON  = "/run/booted-system/boot.json"
	nixosCurrentSystemBootJSON = "/run/current-system/boot.json"

	// nixosBootspecV1Key is the namespace a generation records its boot
	// details under (NixOS RFC 125). The document is a map of namespaces, so
	// extensions such as org.nixos.nixos-init.v1 sit beside this one and a
	// later revision of the spec would arrive under its own key rather than
	// changing this one.
	nixosBootspecV1Key = "org.nixos.bootspec.v1"
)

// NixosReboot reports whether the running system boots what the activated
// system boots.
//
// The other implementations here look for a marker a package manager leaves
// behind, which NixOS has no equivalent of. It activates a whole system
// generation at once and switches /run/current-system to it, while
// /run/booted-system keeps pointing at the generation that was booted. Most of
// a new generation takes effect during activation: services restart, /etc is
// relinked, packages are already in the store. A kernel or an initrd cannot,
// so those two are what a reboot is for, and each generation records them in
// its boot.json.
//
// Comparing the generations themselves would be wrong: a config-only change
// makes a new generation that boots the same kernel, and that change is
// already in effect.
type NixosReboot struct {
	fs afero.Fs
}

// nixosBootJSON is a generation's boot.json, a map keyed by bootspec
// namespace.
type nixosBootJSON struct {
	V1 *nixosBootSpec `json:"org.nixos.bootspec.v1"`
}

// nixosBootSpec is the part of a generation's bootspec that a reboot decides.
// The namespace also records the kernel command line, the boot label and the
// generation's own store path, none of which needs one.
type nixosBootSpec struct {
	Kernel string `json:"kernel"`
	Initrd string `json:"initrd"`
}

func (s *NixosReboot) Name() string {
	return "NixOS Reboot"
}

func (s *NixosReboot) RebootPending() (bool, error) {
	booted, err := readNixosBootSpec(s.fs, nixosBootedSystemBootJSON)
	if err != nil {
		return false, err
	}

	current, err := readNixosBootSpec(s.fs, nixosCurrentSystemBootJSON)
	if err != nil {
		return false, err
	}

	// Two empty kernels would compare equal and report no reboot pending
	// without either generation having been read.
	if booted.Kernel == "" {
		return false, fmt.Errorf("%s names no kernel", nixosBootedSystemBootJSON)
	}
	if current.Kernel == "" {
		return false, fmt.Errorf("%s names no kernel", nixosCurrentSystemBootJSON)
	}

	return booted.Kernel != current.Kernel || booted.Initrd != current.Initrd, nil
}

// readNixosBootSpec reads one generation's boot.json. /run is a tmpfs the
// running system populates, so an offline scan of a NixOS disk or image has
// neither file; the error says which one was missing rather than letting the
// comparison report a system that boots what it already boots.
func readNixosBootSpec(fs afero.Fs, path string) (*nixosBootSpec, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", path, err)
	}

	var doc nixosBootJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", path, err)
	}
	if doc.V1 == nil {
		return nil, fmt.Errorf("%s carries no %s", path, nixosBootspecV1Key)
	}

	return doc.V1, nil
}

func newNixosReboot(conn shared.Connection) *NixosReboot {
	return &NixosReboot{fs: conn.FileSystem()}
}
