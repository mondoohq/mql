// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/llx"
)

// TestInitAristaEosNtpKeepsGivenStatus covers the path the root ntp field
// takes: it has already read the status and passes it in, so init must not
// fetch it a second time or replace it. A nil runtime proves no device call is
// made, since one would dereference it.
func TestInitAristaEosNtpKeepsGivenStatus(t *testing.T) {
	args := map[string]*llx.RawData{"status": llx.StringData("synchronised")}
	got, res, err := initAristaEosNtp(nil, args)
	if err != nil {
		t.Fatalf("init returned an error: %v", err)
	}
	if res != nil {
		t.Fatalf("init returned a resource, want args only")
	}
	if v, _ := got["status"].Value.(string); v != "synchronised" {
		t.Fatalf("status = %q, want %q", v, "synchronised")
	}
}
