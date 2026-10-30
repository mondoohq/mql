// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	logme "github.com/stackitcloud/stackit-sdk-go/services/logme/v2api"
)

// TestLogMeInstanceArgs pins instanceStatus to the response's instanceStatus
// key, kept apart from the lifecycle `status` key that feeds `state`, and
// reads it null when the response omits it.
func TestLogMeInstanceArgs(t *testing.T) {
	decode := func(payload string) *logme.Instance {
		var inst logme.Instance
		if err := json.Unmarshal([]byte(payload), &inst); err != nil {
			t.Fatalf("decoding instance: %v", err)
		}
		return &inst
	}
	base := `"instanceId":"i1","name":"logs","cfGuid":"cf-1","cfOrganizationGuid":"o","cfSpaceGuid":"s","dashboardUrl":"","imageUrl":"","offeringName":"logme2","offeringVersion":"2","planId":"p","planName":"stackit-logme2-1.2.50-single","parameters":{},"lastOperation":{"type":"create","state":"succeeded","description":""}`

	// Synthetic: the two status keys disagree, so a mapper reading the wrong
	// one fails; no target was scanned for this change.
	args := logMeInstanceArgs("eu01", decode(`{`+base+`,"status":"active","instanceStatus":"deploying"}`))
	if got := args["instanceStatus"].Value; got != "deploying" {
		t.Fatalf("instanceStatus = %v, want deploying", got)
	}
	if got := args["state"].Value; got != "active" {
		t.Fatalf("state = %v, want active", got)
	}
	if got := args["status"].Value; got != "succeeded" {
		t.Fatalf("status = %v, want succeeded", got)
	}

	// Synthetic: a response without instanceStatus, as returned before the
	// field was added to the API.
	args = logMeInstanceArgs("eu01", decode(`{`+base+`}`))
	if args["instanceStatus"].Value != nil {
		t.Fatalf("instanceStatus = %v, want null when the response omits it", args["instanceStatus"].Value)
	}
}
