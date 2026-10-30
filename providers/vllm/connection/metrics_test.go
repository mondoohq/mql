// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// metricsBody is shaped after a vLLM Prometheus scrape. vLLM labels its own
// series with the served model name, and reports the running and waiting LoRA
// adapters as comma-joined label values on vllm:lora_requests_info.
const metricsBody = `# HELP vllm:num_requests_running Number of requests currently running.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{engine="0",model_name="meta-llama/Llama-3.1-8B-Instruct"} 2.0
vllm:num_requests_waiting{engine="0",model_name="meta-llama/Llama-3.1-8B-Instruct"} 0.0
vllm:cache_config_info{block_size="16",engine="0",enable_prefix_caching="True",gpu_memory_utilization="0.9"} 1.0
# HELP vllm:lora_requests_info Running stats on lora requests.
vllm:lora_requests_info{max_lora="4",running_lora_adapters="finance-tuned,support-tuned",waiting_lora_adapters="legal-tuned"} 1.76e+09
python_gc_objects_collected_total{generation="0",model_name="not-a-vllm-model"} 917.0
`

func TestParseMetrics(t *testing.T) {
	snapshot := ParseMetrics([]byte(metricsBody))
	if !snapshot.Fetched {
		t.Fatal("expected a fetched snapshot")
	}
	if !snapshot.CacheConfigExposed {
		t.Fatal("expected the engine configuration info series to be seen")
	}

	wantModels := []string{"meta-llama/Llama-3.1-8B-Instruct"}
	if !slices.Equal(snapshot.ModelNames, wantModels) {
		t.Fatalf("modelNames got %v want %v", snapshot.ModelNames, wantModels)
	}

	// Both the running and the waiting adapter labels name adapters the server
	// is serving through, and both are sorted and deduplicated.
	wantAdapters := []string{"finance-tuned", "legal-tuned", "support-tuned"}
	if !slices.Equal(snapshot.LoraAdapters, wantAdapters) {
		t.Fatalf("loraAdapters got %v want %v", snapshot.LoraAdapters, wantAdapters)
	}
}

// A sidecar exporter scraped through the same endpoint uses its own metric
// names, and its labels say nothing about what this server serves.
func TestParseMetricsIgnoresForeignSeries(t *testing.T) {
	snapshot := ParseMetrics([]byte(`node_exporter_build_info{model_name="borrowed"} 1.0` + "\n"))
	if len(snapshot.ModelNames) != 0 {
		t.Fatalf("modelNames got %v want empty", snapshot.ModelNames)
	}
}

// A scrape that answered but carried no adapter series is a real answer: no
// adapters are disclosed. It must render as an empty list, never as null.
func TestParseMetricsWithoutLoraSeries(t *testing.T) {
	snapshot := ParseMetrics([]byte(`vllm:num_requests_running{model_name="m"} 0.0` + "\n"))
	if snapshot.LoraAdapters == nil {
		t.Fatal("loraAdapters must be an empty list, not null, after a successful scrape")
	}
	if len(snapshot.LoraAdapters) != 0 {
		t.Fatalf("loraAdapters got %v want empty", snapshot.LoraAdapters)
	}
	if snapshot.CacheConfigExposed {
		t.Fatal("cacheConfigExposed must be false when the series is absent")
	}
}

// Prometheus escapes quotes and backslashes inside label values. A parser that
// stops at the first inner quote truncates a model path.
func TestParseMetricsUnescapesLabelValues(t *testing.T) {
	line := `vllm:num_requests_running{model_name="odd\"name\\path",engine="0"} 1.0` + "\n"
	snapshot := ParseMetrics([]byte(line))
	want := []string{`odd"name\path`}
	if !slices.Equal(snapshot.ModelNames, want) {
		t.Fatalf("modelNames got %v want %v", snapshot.ModelNames, want)
	}
}

func TestParseMetricLine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		metric string
		labels map[string]string
		ok     bool
	}{
		{
			name:   "labelled sample",
			line:   `vllm:x{a="1",b="two"} 3.0`,
			metric: "vllm:x",
			labels: map[string]string{"a": "1", "b": "two"},
			ok:     true,
		},
		{
			name:   "unlabelled sample",
			line:   `vllm:y 4.0`,
			metric: "vllm:y",
			labels: map[string]string{},
			ok:     true,
		},
		{
			name:   "empty label value",
			line:   `vllm:z{a=""} 1`,
			metric: "vllm:z",
			labels: map[string]string{"a": ""},
			ok:     true,
		},
		{name: "empty line", line: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metric, labels, ok := parseMetricLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok got %v want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if metric != tt.metric {
				t.Fatalf("metric got %q want %q", metric, tt.metric)
			}
			if len(labels) != len(tt.labels) {
				t.Fatalf("labels got %v want %v", labels, tt.labels)
			}
			for key, want := range tt.labels {
				if labels[key] != want {
					t.Fatalf("label %q got %q want %q", key, labels[key], want)
				}
			}
		})
	}
}

// The scrape answers the question "what does an unauthenticated scraper
// learn", so it must not carry the configured API key.
func TestMetricsSnapshotScrapesAnonymously(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("metrics scrape sent credentials: %q", got)
		}
		_, _ = w.Write([]byte(metricsBody))
	}))
	defer server.Close()

	conn := &VllmConnection{client: server.Client(), baseURL: server.URL, apiKey: "secret-token"}
	snapshot, err := conn.MetricsSnapshot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snapshot == nil || len(snapshot.ModelNames) != 1 {
		t.Fatalf("got %+v", snapshot)
	}
}

// A refused or missing endpoint leaves the label lists unobserved, so the
// snapshot must report itself as not fetched rather than as empty.
func TestMetricsSnapshotRefusedScrapeIsNotFetched(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		conn := &VllmConnection{client: server.Client(), baseURL: server.URL}
		snapshot, err := conn.MetricsSnapshot(context.Background())
		server.Close()
		if err != nil {
			t.Fatalf("status %d: unexpected error: %v", status, err)
		}
		if snapshot == nil || snapshot.Fetched {
			t.Fatalf("status %d: got %+v want an unfetched snapshot", status, snapshot)
		}
	}
}

// The cache configuration series carries the engine settings as its labels,
// and those labels are the only thing harvested from it.
func TestParseMetricsHarvestsCacheConfigLabels(t *testing.T) {
	snapshot := ParseMetrics([]byte(metricsBody))

	want := map[string]string{
		"block_size":             "16",
		"engine":                 "0",
		"enable_prefix_caching":  "True",
		"gpu_memory_utilization": "0.9",
	}
	if len(snapshot.CacheConfig) != len(want) {
		t.Fatalf("cacheConfig got %v want %v", snapshot.CacheConfig, want)
	}
	for key, value := range want {
		if got := snapshot.CacheConfig[key]; got != value {
			t.Fatalf("cacheConfig[%q] got %q want %q", key, got, value)
		}
	}

	// model_name rides on the request-count series, not on the configuration
	// one. Harvesting labels off every vLLM series would pull it in here.
	if _, ok := snapshot.CacheConfig["model_name"]; ok {
		t.Fatal("cacheConfig carries a label from another series")
	}
	// No sample value is ever retained, so the series value must not appear.
	for key, value := range snapshot.CacheConfig {
		if value == "1.0" {
			t.Fatalf("cacheConfig[%q] carries the sample value", key)
		}
	}
}

// A scrape that answered but carried no configuration series is a real answer:
// nothing is disclosed. It must render as an empty map, never as null, and the
// boolean must be false rather than unknown.
func TestParseMetricsWithoutCacheConfigSeries(t *testing.T) {
	snapshot := ParseMetrics([]byte("vllm:num_requests_running{model_name=\"m\"} 2.0\n"))
	if snapshot.CacheConfigExposed {
		t.Fatal("cacheConfigExposed is true without the configuration series")
	}
	if snapshot.CacheConfig == nil {
		t.Fatal("cacheConfig is null on a scrape that answered")
	}
	if len(snapshot.CacheConfig) != 0 {
		t.Fatalf("cacheConfig got %v want empty", snapshot.CacheConfig)
	}
}

// A configuration series emitted by something other than vLLM is not vLLM's
// engine configuration, and the metric-name prefix is what keeps it out.
func TestParseMetricsIgnoresForeignCacheConfigSeries(t *testing.T) {
	snapshot := ParseMetrics([]byte("other:cache_config_info{block_size=\"32\"} 1.0\n"))
	if snapshot.CacheConfigExposed {
		t.Fatal("cacheConfigExposed is true for a series vLLM did not emit")
	}
	if len(snapshot.CacheConfig) != 0 {
		t.Fatalf("cacheConfig got %v want empty", snapshot.CacheConfig)
	}
}
