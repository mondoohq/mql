// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mvd

import "go.mondoo.com/mql/providers-sdk/v1/inventory"

//go:generate protoc --plugin=protoc-gen-go=../../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-rangerrpc=../../../../scripts/protoc/protoc-gen-rangerrpc --plugin=protoc-gen-go-vtproto=../../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=../../../../:. --go_out=. --go_opt=paths=source_relative --rangerrpc_out=. --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size mvd.proto

// Determine all Cves of all Advisories
func (r *VulnReport) Cves() []*CVE {
	cveMap := map[string]*CVE{}

	for i := range r.Advisories {
		advisory := r.Advisories[i]
		for j := range advisory.Cves {
			cve := advisory.Cves[j]
			cveMap[cve.ID] = cve
		}
	}

	cveList := []*CVE{}
	for _, v := range cveMap {
		cveList = append(cveList, v)
	}
	return cveList
}

// MvdPlatform converts the inventory.Platform to the
// platform object we use for MVD
func NewMvdPlatform(pf *inventory.Platform) *Platform {
	if pf == nil {
		return nil
	}
	return &Platform{
		Name:    pf.Name,
		Release: pf.Version,
		Build:   pf.Build,
		Arch:    pf.Arch,
		Title:   pf.Title,
		Labels:  pf.Labels,
	}
}
