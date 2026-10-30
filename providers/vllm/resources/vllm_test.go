// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/vllm/connection"
)

func TestModelCreatedTime(t *testing.T) {
	tests := []struct {
		name string
		unix int64
		want *time.Time
	}{
		{name: "zero is null", unix: 0, want: nil},
		{name: "negative is null", unix: -1, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := modelCreatedTime(tt.unix); got != tt.want {
				t.Fatalf("modelCreatedTime(%d) = %v, want %v", tt.unix, got, tt.want)
			}
		})
	}

	t.Run("positive returns unix time", func(t *testing.T) {
		got := modelCreatedTime(1700000000)
		if got == nil {
			t.Fatal("expected non-nil time")
		}
		if !got.Equal(time.Unix(1700000000, 0)) {
			t.Fatalf("modelCreatedTime = %v, want %v", got, time.Unix(1700000000, 0))
		}
	})
}

func TestInitVllmEndpoint(t *testing.T) {
	t.Run("requires path", func(t *testing.T) {
		_, _, err := initVllmEndpoint(nil, map[string]*llx.RawData{})
		if err == nil {
			t.Fatal("expected error when path is missing")
		}
	})

	t.Run("defaults method to GET", func(t *testing.T) {
		args, _, err := initVllmEndpoint(nil, map[string]*llx.RawData{
			"path": llx.StringData("/docs"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := args["method"].Value.(string); got != http.MethodGet {
			t.Fatalf("method = %q, want GET", got)
		}
	})

	t.Run("uppercases method", func(t *testing.T) {
		args, _, err := initVllmEndpoint(nil, map[string]*llx.RawData{
			"path":   llx.StringData("/v1/models"),
			"method": llx.StringData("get"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := args["method"].Value.(string); got != http.MethodGet {
			t.Fatalf("method = %q, want GET", got)
		}
	})

	// Regression: a null (non-string) method arg must not panic on the
	// type assertion, and should fall back to GET.
	t.Run("null method falls back to GET without panicking", func(t *testing.T) {
		args, _, err := initVllmEndpoint(nil, map[string]*llx.RawData{
			"path":   llx.StringData("/docs"),
			"method": llx.NilData,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := args["method"].Value.(string); got != http.MethodGet {
			t.Fatalf("method = %q, want GET", got)
		}
	})
}

func TestEndpointSpecFor(t *testing.T) {
	t.Run("known spec keeps its category", func(t *testing.T) {
		spec := endpointSpecFor(http.MethodGet, "/docs")
		if spec.Category != "documentation" {
			t.Fatalf("category = %q, want documentation", spec.Category)
		}
		if spec.Body != "" {
			t.Fatalf("body = %q, want empty", spec.Body)
		}
	})

	t.Run("lowercase method matches known spec", func(t *testing.T) {
		spec := endpointSpecFor("get", "/docs")
		if spec.Method != http.MethodGet || spec.Category != "documentation" {
			t.Fatalf("spec = %+v, want GET/documentation", spec)
		}
	})

	t.Run("unknown GET is a custom spec without body", func(t *testing.T) {
		spec := endpointSpecFor(http.MethodGet, "/private/route")
		if spec.Category != "custom" {
			t.Fatalf("category = %q, want custom", spec.Category)
		}
		if spec.Body != "" {
			t.Fatalf("body = %q, want empty", spec.Body)
		}
	})

	t.Run("unknown POST is a custom spec with body", func(t *testing.T) {
		spec := endpointSpecFor(http.MethodPost, "/private/route")
		if spec.Category != "custom" {
			t.Fatalf("category = %q, want custom", spec.Category)
		}
		if spec.Body != connection.NewPostBody() {
			t.Fatalf("body = %q, want %q", spec.Body, connection.NewPostBody())
		}
	})
}
