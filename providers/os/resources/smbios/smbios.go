// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type SmBiosInfo struct {
	BIOS          BiosInfo
	SysInfo       SysInfo
	BaseBoardInfo BaseBoardInfo
	ChassisInfo   ChassisInfo
}

type BiosInfo struct {
	Vendor      string
	Version     string
	ReleaseDate string
}

type SysInfo struct {
	Vendor       string
	Model        string
	Version      string
	SerialNumber string
	UUID         string
	Family       string
	SKU          string
}

type BaseBoardInfo struct {
	Vendor       string
	Model        string
	Version      string
	SerialNumber string
	AssetTag     string
}

type ChassisInfo struct {
	Vendor       string
	Model        string
	Version      string
	SerialNumber string
	AssetTag     string
	Type         string
}

// https://en.wikipedia.org/wiki/System_Management_BIOS
// https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0.pdf
// There are also tools (https://github.com/digitalocean/go-smbios) out there to parse
// the memory dump directly, but this would require to transfer large amount of data \
// for remove access, therefore we restrict the data to what is exposed in /sys/class/dmi/id/
type SmBiosManager interface {
	Name() string
	Info() (*SmBiosInfo, error)
}

// managerCache caches SmBiosManager instances per connection ID so that repeated
// calls to ResolveManager (from machine subresources, platform ID detectors,
// cloud detectors, etc.) reuse the same manager and its cached SMBIOS data
// instead of spawning a new heavy command (e.g. PowerShell on Windows) each time.
//
// The cache lives for the process lifetime. Entries are not evicted on disconnect
// because the os provider has no Disconnect lifecycle hook. In practice this is
// fine: connections are short-lived (one per scan) and the process exits after.
var managerCache sync.Map // map[uint32]SmBiosManager

func ResolveManager(conn shared.Connection, pf *inventory.Platform) (SmBiosManager, error) {
	connID := conn.ID()

	// Fast path: return cached manager without allocating a new one.
	if mgr, ok := managerCache.Load(connID); ok {
		return mgr.(SmBiosManager), nil
	}

	var biosM SmBiosManager

	// check darwin before unix since darwin is also a unix
	if pf.IsFamily("darwin") {
		biosM = &OSXSmbiosManager{provider: conn, platform: pf}
	} else if pf.IsFamily(inventory.FAMILY_UNIX) {
		if pf.Name == "aix" {
			biosM = &AIXSmbiosManager{provider: conn}
		} else {
			biosM = &LinuxSmbiosManager{provider: conn}
		}
	} else if pf.IsFamily("windows") {
		biosM = &WindowsSmbiosManager{provider: conn}
	}

	if biosM == nil {
		return nil, errors.New("could not detect suitable smbios manager for platform: " + pf.Name)
	}

	// Wrap in the memo here rather than in each platform manager, so that every
	// platform gets it and none can be added without it.
	mgr, _ := managerCache.LoadOrStore(connID, &cachingManager{inner: biosM})
	return mgr.(SmBiosManager), nil
}
