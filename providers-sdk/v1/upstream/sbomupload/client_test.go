// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbomupload

import (
	"testing"

	"go.mondoo.com/mql/sbom"
)

func TestNewSbomClient(t *testing.T) {
	c, err := NewSbomClient("https://us.api.mondoo.com", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if c.prefix != "https://us.api.mondoo.com/Sbom" {
		t.Errorf("prefix = %q", c.prefix)
	}
}

func TestBulkUploadSbomRequestRoundTrip(t *testing.T) {
	in := &BulkUploadSbomRequest{
		SpaceMrn:     "//captain.api.mondoo.app/spaces/s1",
		CreateAssets: true,
		Sboms:        []*sbom.Sbom{{Packages: []*sbom.Package{{Name: "openssl", Version: "1.1.1"}}}},
	}
	data, err := in.MarshalVT()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := &BulkUploadSbomRequest{}
	if err := out.UnmarshalVT(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.SpaceMrn != in.SpaceMrn || !out.CreateAssets || len(out.Sboms) != 1 {
		t.Errorf("round-trip mismatch: %+v", out)
	}
}
