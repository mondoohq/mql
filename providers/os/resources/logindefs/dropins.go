// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logindefs

import (
	"path"
	"sort"
	"strings"
)

const (
	// EtcDropInDir holds administrator drop-ins for login.defs.
	EtcDropInDir = "/etc/login.defs.d"
	// VendorDropInDir holds distribution drop-ins on systems whose shadow is
	// built with a vendor directory (/usr/etc).
	VendorDropInDir = "/usr/etc/login.defs.d"
)

// DropInPaths returns the login.defs drop-ins that a libeconf-linked shadow
// (useradd, chage, login) reads after the main login.defs, in the order it
// applies them; a key set by a later file replaces an earlier one.
//
// vendorNames and etcNames are the entry names of VendorDropInDir and
// EtcDropInDir. Only names ending in ".defs" count. Every vendor drop-in is
// applied before every /etc drop-in, each directory sorted by name, and an
// /etc file shadows the vendor file of the same name. This was measured with
// useradd on SLES 16 and openSUSE Leap 16 (shadow 4.17, libeconf 0.7): an
// /etc 10-x.defs still overrides a vendor 90-y.defs.
func DropInPaths(vendorNames []string, etcNames []string) []string {
	etc := defsNames(etcNames)
	shadowed := make(map[string]struct{}, len(etc))
	for _, name := range etc {
		shadowed[name] = struct{}{}
	}

	var res []string
	for _, name := range defsNames(vendorNames) {
		if _, ok := shadowed[name]; ok {
			continue
		}
		res = append(res, path.Join(VendorDropInDir, name))
	}
	for _, name := range etc {
		res = append(res, path.Join(EtcDropInDir, name))
	}
	return res
}

func defsNames(names []string) []string {
	res := make([]string, 0, len(names))
	for _, name := range names {
		if strings.HasSuffix(name, ".defs") && len(name) > len(".defs") {
			res = append(res, name)
		}
	}
	sort.Strings(res)
	return res
}

// Overlay copies every key of the later maps over the earlier ones and returns
// the merged result, the way shadow applies drop-ins over the main file.
func Overlay(layers ...map[string]string) map[string]string {
	res := map[string]string{}
	for _, layer := range layers {
		for k, v := range layer {
			res[k] = v
		}
	}
	return res
}
