// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

// servedModel builds a listed model the way models() leaves it: the id field
// set and the parent id stashed on the internal cache field.
func servedModel(id, parent string) *mqlVllmModel {
	m := &mqlVllmModel{}
	m.Id = plugin.TValue[string]{Data: id, State: plugin.StateIsSet}
	m.cacheParentID = parent
	return m
}

func TestFindModelByID(t *testing.T) {
	// Synthetic: a base model listed with two adapters; no live server was checked.
	base := servedModel("meta-llama/Llama-3.1-8B-Instruct", "")
	sql := servedModel("sql-lora", "meta-llama/Llama-3.1-8B-Instruct")
	chat := servedModel("chat-lora", "meta-llama/Llama-3.1-8B-Instruct")
	// Synthetic: an adapter whose base model is not in the list; no live server was checked.
	orphan := servedModel("orphan-lora", "not-served")
	models := []any{base, sql, chat, orphan}

	t.Run("adapter resolves to its served base model", func(t *testing.T) {
		if got := findModelByID(models, sql.cacheParentID); got != base {
			t.Fatalf("got %v want base model", got)
		}
	})

	t.Run("adapter whose base model is not served resolves to nil", func(t *testing.T) {
		if got := findModelByID(models, orphan.cacheParentID); got != nil {
			t.Fatalf("got %q want nil", got.Id.Data)
		}
	})
}

func TestAdaptersOf(t *testing.T) {
	// Synthetic: a base model listed with two adapters; no live server was checked.
	base := servedModel("base", "")
	sql := servedModel("sql-lora", "base")
	chat := servedModel("chat-lora", "base")
	other := servedModel("other-lora", "other-base")
	models := []any{base, sql, chat, other}

	t.Run("base model lists both of its adapters", func(t *testing.T) {
		got := adaptersOf(models, "base")
		if len(got) != 2 || got[0] != sql || got[1] != chat {
			t.Fatalf("got %v want [sql-lora chat-lora]", got)
		}
	})

	t.Run("adapter has no adapters of its own", func(t *testing.T) {
		got := adaptersOf(models, "sql-lora")
		if got == nil || len(got) != 0 {
			t.Fatalf("got %v want empty list", got)
		}
	})

	t.Run("empty id never matches base models", func(t *testing.T) {
		if got := adaptersOf(models, ""); len(got) != 0 {
			t.Fatalf("got %v want empty list", got)
		}
	})
}

// The deprecated parent field keeps reporting the raw parent id.
func TestModelArgsKeepsParent(t *testing.T) {
	// Synthetic: an adapter card shaped after vLLM's /v1/models LoRA entries; no live server was checked.
	args := modelArgs("http://vllm:8000", connection.ModelCard{
		ID:     "sql-lora",
		Root:   "/adapters/sql",
		Parent: "meta-llama/Llama-3.1-8B-Instruct",
	})
	if got := args["parent"].Value.(string); got != "meta-llama/Llama-3.1-8B-Instruct" {
		t.Fatalf("parent got %q", got)
	}
	if got := args["__id"].Value.(string); got != "http://vllm:8000/model/sql-lora" {
		t.Fatalf("__id got %q", got)
	}
}
