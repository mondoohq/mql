// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbomscan

import (
	"testing"

	"go.mondoo.com/mql/sbom"
)

func TestNewExtendedVulnMgmtClient(t *testing.T) {
	c, err := NewExtendedVulnMgmtClient("https://us.api.mondoo.com", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if c.prefix != "https://us.api.mondoo.com/ExtendedVulnMgmt" {
		t.Errorf("prefix = %q", c.prefix)
	}
}

func TestScanUploadedSbomRequestRoundTrip(t *testing.T) {
	in := &ScanUploadedSbomRequest{
		AssetMrn: "//captain.api.mondoo.app/spaces/space-1",
		Sbom:     &sbom.Sbom{Packages: []*sbom.Package{{Name: "openssl", Version: "1.1.1"}}},
	}
	data, err := in.MarshalVT()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := &ScanUploadedSbomRequest{}
	if err := out.UnmarshalVT(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.AssetMrn != in.AssetMrn || len(out.Sbom.Packages) != 1 {
		t.Errorf("round-trip mismatch: %+v", out)
	}
}
