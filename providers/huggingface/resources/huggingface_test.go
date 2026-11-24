// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	hfmodels "go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
)

func TestNormalizeModelID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain owner/model", "meta-llama/Llama-3.1-8B", "meta-llama/Llama-3.1-8B", false},
		{"plain canonical", "gpt2", "gpt2", false},
		{"url owner/model", "https://huggingface.co/meta-llama/Llama-3.1-8B", "meta-llama/Llama-3.1-8B", false},
		{"url with trailing path", "https://huggingface.co/meta-llama/Llama-3.1-8B/tree/main", "meta-llama/Llama-3.1-8B", false},
		{"url canonical single segment", "https://huggingface.co/gpt2", "gpt2", false},
		{"url trailing slash", "https://huggingface.co/gpt2/", "gpt2", false},
		{"url no path", "https://huggingface.co", "", true},
		{"url root only", "https://huggingface.co/", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeModelID(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseHFTime(t *testing.T) {
	// RFC3339Nano (the common form, with and without fractional seconds).
	got := parseHFTime("2024-01-02T03:04:05.123456789Z")
	require.NotNil(t, got)
	assert.True(t, got.Equal(time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)))

	got = parseHFTime("2024-01-02T03:04:05Z")
	require.NotNil(t, got)
	assert.True(t, got.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)))

	// Millisecond "Z" form handled by the fallback layout.
	got = parseHFTime("2024-01-02T03:04:05.000Z")
	require.NotNil(t, got)
	assert.True(t, got.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)))

	// Empty and unparseable inputs yield nil (null time), never a panic.
	assert.Nil(t, parseHFTime(""))
	assert.Nil(t, parseHFTime("not-a-timestamp"))
}

// gatedMode has to keep "auto" (anyone accepting the terms is admitted) apart
// from "manual" (an owner approves each request), and has to stay null when the
// Hub never reported the field. Returning the mode unconditionally would turn an
// unread setting into the claim that the repository is ungated.
func TestGatedModeValue(t *testing.T) {
	tests := []struct {
		name string
		in   hfmodels.GatedValue
		want *string
	}{
		{"ungated", hfmodels.GatedValue{IsGated: false, Mode: "false"}, new("false")},
		{"auto", hfmodels.GatedValue{IsGated: true, Mode: "auto"}, new("auto")},
		{"manual", hfmodels.GatedValue{IsGated: true, Mode: "manual"}, new("manual")},
		{"legacy bool true", hfmodels.GatedValue{IsGated: true, Mode: "true"}, new("true")},
		{"never reported", hfmodels.GatedValue{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gatedModeValue(tt.in)
			if tt.want == nil {
				assert.Nil(t, got, "an unreported gated field must resolve to null, not to \"false\"")
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tt.want, *got)
		})
	}
}

//go:fix inline
func ptr(s string) *string { return new(s) }

func TestStringsToInterface(t *testing.T) {
	assert.Equal(t, []any{}, stringsToInterface(nil))
	assert.Equal(t, []any{"a", "b"}, stringsToInterface([]string{"a", "b"}))
}

// Synthetic: an endpoint record shaped after the Inference Endpoints v2
// OpenAPI document; no live account was checked.
//
// The API returns no endpoint id, so the id is namespace/name. Two
// namespaces' endpoints of the same name must not share a cache id.
func TestInferenceEndpointArgs(t *testing.T) {
	ep := hfmodels.InferenceEndpoint{
		Name:  "chat",
		Model: hfmodels.InferenceEndpointModel{Repository: "acme/llm", Framework: "pytorch"},
		Status: hfmodels.InferenceEndpointState{
			State: "running", URL: "https://chat.endpoints.huggingface.cloud",
			CreatedAt: "2026-01-02T03:04:05Z",
		},
	}

	args := inferenceEndpointArgs("acme", ep)
	assert.Equal(t, "acme/chat", args["id"].Value)
	assert.Equal(t, "acme/llm", args["model"].Value)
	assert.Equal(t, "pytorch", args["framework"].Value)
	assert.Equal(t, "running", args["status"].Value)
	assert.Equal(t, "https://chat.endpoints.huggingface.cloud", args["endpointUrl"].Value)

	other := inferenceEndpointArgs("other-org", ep)
	assert.NotEqual(t, args["__id"].Value, other["__id"].Value)
}

// Synthetic: an endpoint shaped after EndpointWithStatus in the Inference
// Endpoints OpenAPI document; no live account was checked.
func TestInferenceEndpointArgsSecurityFields(t *testing.T) {
	minR, maxR := int64(0), int64(3)
	rev, last := "abc123", "2026-01-04T03:04:05Z"
	ep := hfmodels.InferenceEndpoint{
		Name: "chat",
		Type: "public",
		Model: hfmodels.InferenceEndpointModel{
			Repository: "acme/llm", Revision: &rev,
			Secrets: hfmodels.SecretNames{"API_KEY", "HF_TOKEN"},
		},
		Provider: hfmodels.InferenceEndpointProvider{Vendor: "aws", Region: "us-east-1"},
		Compute: hfmodels.InferenceEndpointCompute{
			InstanceType: "nvidia-a10g",
			Scaling:      hfmodels.InferenceEndpointScaling{MinReplica: &minR, MaxReplica: &maxR},
		},
		Status: hfmodels.InferenceEndpointState{
			LastUsedAt: &last,
			CreatedBy:  hfmodels.InferenceEndpointAccount{ID: "u1", Name: "alice"},
			UpdatedBy:  hfmodels.InferenceEndpointAccount{ID: "u2", Name: "bob"},
		},
	}

	args := inferenceEndpointArgs("acme", ep)
	assert.Equal(t, "public", args["type"].Value)
	assert.Equal(t, "abc123", args["revision"].Value)
	assert.Equal(t, "aws", args["vendor"].Value)
	assert.Equal(t, "us-east-1", args["region"].Value)
	assert.Equal(t, "nvidia-a10g", args["instanceType"].Value)
	assert.Equal(t, int64(0), args["minReplica"].Value)
	assert.Equal(t, int64(3), args["maxReplica"].Value)
	assert.Equal(t, new(time.Date(2026, 1, 4, 3, 4, 5, 0, time.UTC)), args["lastUsedAt"].Value)
	assert.Equal(t, "alice", args["createdBy"].Value)
	assert.Equal(t, "bob", args["updatedBy"].Value)
	assert.Equal(t, []any{"API_KEY", "HF_TOKEN"}, args["secretNames"].Value)
}

// Synthetic: an endpoint record with every optional field absent; no live
// account showed this. A missing replica minimum must not read as zero, which
// would claim the endpoint scales to zero.
func TestInferenceEndpointArgsAbsentFields(t *testing.T) {
	args := inferenceEndpointArgs("acme", hfmodels.InferenceEndpoint{Name: "bare"})
	for _, f := range []string{"type", "revision", "vendor", "region", "instanceType", "minReplica", "maxReplica", "lastUsedAt", "createdBy", "updatedBy", "secretNames"} {
		assert.Nil(t, args[f].Value, f)
	}
}

// Synthetic: webhook records shaped after GET /api/settings/webhooks in the Hub
// OpenAPI document; no live account was checked.
func TestWebhookArgs(t *testing.T) {
	yes := true
	w := hfmodels.Webhook{
		ID: "w1", Disabled: true, HasSecret: &yes,
		LastTriggerAt: "2026-03-04T05:06:07.000Z",
		Job:           &hfmodels.WebhookJob{DockerImage: "python:3.12"},
	}
	args := webhookArgs(w, []any{})
	assert.Equal(t, true, args["disabled"].Value)
	assert.Equal(t, true, args["hasSecret"].Value)
	assert.Equal(t, new(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)), args["lastTriggerAt"].Value)
	assert.Equal(t, "python:3.12", args["jobDockerImage"].Value)

	// A job that runs from a Space has no image; a webhook with no secret flag
	// reported stays null rather than reading as "no secret".
	spaceJob := webhookArgs(hfmodels.Webhook{ID: "w2", Job: &hfmodels.WebhookJob{SpaceID: "acme/runner"}}, []any{})
	assert.Nil(t, spaceJob["jobDockerImage"].Value)
	assert.Nil(t, spaceJob["hasSecret"].Value)
	assert.Nil(t, spaceJob["lastTriggerAt"].Value)

	noJob := webhookArgs(hfmodels.Webhook{ID: "w3"}, []any{})
	assert.Nil(t, noJob["jobDockerImage"].Value)
}

// Synthetic: absent, empty and present inputs to the null helpers; no live
// account was checked. An empty list the Hub sent must stay apart from one it
// left out.
func TestOptionalValues(t *testing.T) {
	assert.Nil(t, optionalString("").Value)
	assert.Equal(t, "x", optionalString("x").Value)

	assert.Nil(t, stringListOrNull(nil).Value)
	assert.Equal(t, []any{}, stringListOrNull([]string{}).Value)

	assert.Nil(t, stringListPtrOrNull(nil).Value)
	assert.Equal(t, []any{"mfa"}, stringListPtrOrNull(&[]string{"mfa"}).Value)
}
