// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serverInfoJSON is shaped after the /server_info payload vLLM returns with
// config_format=json: a vllm_config object of per-subsystem config blocks, the
// VLLM_* process environment, and the collected system environment.
const serverInfoJSON = `{
  "vllm_config": {
    "model_config": {
      "model": "meta-llama/Llama-3.1-8B-Instruct",
      "tokenizer": "meta-llama/Llama-3.1-8B-Instruct",
      "tokenizer_mode": "auto",
      "trust_remote_code": true,
      "max_model_len": 8192,
      "quantization": "awq",
      "enforce_eager": false,
      "served_model_name": ["prod-llama", "llama"]
    },
    "cache_config": {
      "enable_prefix_caching": true,
      "block_size": 16
    },
    "lora_config": {
      "max_loras": 4,
      "max_lora_rank": 32,
      "fully_sharded_loras": false
    },
    "parallel_config": {
      "tensor_parallel_size": 2,
      "pipeline_parallel_size": 1,
      "data_parallel_size": 1
    },
    "observability_config": {
      "otlp_traces_endpoint": "http://collector.internal:4317",
      "collect_detailed_traces": ["all"],
      "enable_logging_iteration_details": true
    }
  },
  "vllm_env": {
    "VLLM_ALLOW_RUNTIME_LORA_UPDATING": true,
    "VLLM_SERVER_DEV_MODE": "1"
  },
  "system_env": {"os": "Linux"}
}`

func TestParseServerInfoStructured(t *testing.T) {
	info, err := ParseServerInfo([]byte(serverInfoJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Structured {
		t.Fatal("expected a structured configuration")
	}

	// trust_remote_code is the highest-consequence setting the server reports.
	// A mistyped struct tag would silently report false on a server that
	// executes repository code, so pin it explicitly.
	if info.TrustRemoteCode == nil || !*info.TrustRemoteCode {
		t.Fatalf("trustRemoteCode got %v want true", info.TrustRemoteCode)
	}
	if got := derefString(info.Model); got != "meta-llama/Llama-3.1-8B-Instruct" {
		t.Fatalf("model got %q", got)
	}
	if got := derefString(info.Tokenizer); got != "meta-llama/Llama-3.1-8B-Instruct" {
		t.Fatalf("tokenizer got %q", got)
	}
	if got := derefString(info.TokenizerMode); got != "auto" {
		t.Fatalf("tokenizerMode got %q", got)
	}
	if got := derefString(info.Quantization); got != "awq" {
		t.Fatalf("quantization got %q", got)
	}
	if info.EnforceEager == nil || *info.EnforceEager {
		t.Fatalf("enforceEager got %v want false", info.EnforceEager)
	}
	if got := derefInt(info.MaxModelLen); got != 8192 {
		t.Fatalf("maxModelLen got %d", got)
	}
	if len(info.ServedModelNames) != 2 || info.ServedModelNames[0] != "prod-llama" {
		t.Fatalf("servedModelNames got %v", info.ServedModelNames)
	}
	if info.EnablePrefixCaching == nil || !*info.EnablePrefixCaching {
		t.Fatalf("enablePrefixCaching got %v want true", info.EnablePrefixCaching)
	}
	if info.LoraEnabled == nil || !*info.LoraEnabled {
		t.Fatalf("loraEnabled got %v want true", info.LoraEnabled)
	}
	if got := derefInt(info.MaxLoras); got != 4 {
		t.Fatalf("maxLoras got %d", got)
	}
	if got := derefInt(info.MaxLoraRank); got != 32 {
		t.Fatalf("maxLoraRank got %d", got)
	}
	if info.LoraConfig["fully_sharded_loras"] != false {
		t.Fatalf("loraConfig got %v", info.LoraConfig)
	}
	if got := derefInt(info.TensorParallelSize); got != 2 {
		t.Fatalf("tensorParallelSize got %d", got)
	}
	if info.ParallelConfig["pipeline_parallel_size"] != float64(1) {
		t.Fatalf("parallelConfig got %v", info.ParallelConfig)
	}
	if got := derefString(info.OtlpTracesEndpoint); got != "http://collector.internal:4317" {
		t.Fatalf("otlpTracesEndpoint got %q", got)
	}
	if len(info.CollectDetailedTraces) != 1 || info.CollectDetailedTraces[0] != "all" {
		t.Fatalf("collectDetailedTraces got %v", info.CollectDetailedTraces)
	}
	if info.LoggingIterationDetails == nil || !*info.LoggingIterationDetails {
		t.Fatalf("loggingIterationDetails got %v want true", info.LoggingIterationDetails)
	}
	if info.AllowRuntimeLoraUpdating == nil || !*info.AllowRuntimeLoraUpdating {
		t.Fatalf("allowRuntimeLoraUpdating got %v want true", info.AllowRuntimeLoraUpdating)
	}
	if info.ServerDevMode == nil || !*info.ServerDevMode {
		t.Fatalf("serverDevMode got %v want true", info.ServerDevMode)
	}
}

// An absent flag must stay null. Reporting it as false would tell an auditor
// the server disabled something it never mentioned.
func TestParseServerInfoAbsentValuesStayNull(t *testing.T) {
	info, err := ParseServerInfo([]byte(`{"vllm_config":{"model_config":{"model":"m"}},"vllm_env":{}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Structured {
		t.Fatal("expected a structured configuration")
	}
	if info.TrustRemoteCode != nil {
		t.Fatalf("trustRemoteCode got %v want null", *info.TrustRemoteCode)
	}
	if info.EnablePrefixCaching != nil {
		t.Fatalf("enablePrefixCaching got %v want null", *info.EnablePrefixCaching)
	}
	if info.AllowRuntimeLoraUpdating != nil {
		t.Fatalf("allowRuntimeLoraUpdating got %v want null", *info.AllowRuntimeLoraUpdating)
	}
	if info.MaxModelLen != nil {
		t.Fatalf("maxModelLen got %v want null", *info.MaxModelLen)
	}
	// lora_config absent means the engine cannot serve adapters at all, which
	// is an observation rather than an unknown.
	if info.LoraEnabled == nil || *info.LoraEnabled {
		t.Fatalf("loraEnabled got %v want false", info.LoraEnabled)
	}
	if info.LoraConfig != nil {
		t.Fatalf("loraConfig got %v want nil", info.LoraConfig)
	}
}

// Servers that predate config_format ignore the parameter and answer with the
// Python repr of the config. That string is not scraped: every field stays
// null and Structured reports why.
func TestParseServerInfoTextFormatIsNotScraped(t *testing.T) {
	body := `{"vllm_config":"VllmConfig(model_config=ModelConfig(trust_remote_code=True))","vllm_env":{"VLLM_SERVER_DEV_MODE":"1"}}`
	info, err := ParseServerInfo([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Structured {
		t.Fatal("a string repr must not be reported as structured configuration")
	}
	if info.TrustRemoteCode != nil {
		t.Fatal("trustRemoteCode must stay null when the repr was not parsed")
	}
	// The environment block is still a real JSON object, so it is still read.
	if info.ServerDevMode == nil || !*info.ServerDevMode {
		t.Fatalf("serverDevMode got %v want true", info.ServerDevMode)
	}
}

func TestParseServerInfoServedModelNameScalar(t *testing.T) {
	info, err := ParseServerInfo([]byte(`{"vllm_config":{"model_config":{"served_model_name":"solo"}}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.ServedModelNames) != 1 || info.ServedModelNames[0] != "solo" {
		t.Fatalf("servedModelNames got %v", info.ServedModelNames)
	}
}

// A block whose individual field renderings differ from the expected types
// must not discard the whole configuration.
func TestParseServerInfoToleratesFieldTypeMismatch(t *testing.T) {
	body := `{"vllm_config":{"model_config":{"trust_remote_code":true,"max_model_len":"not-a-number"}}}`
	info, err := ParseServerInfo([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.TrustRemoteCode == nil || !*info.TrustRemoteCode {
		t.Fatalf("trustRemoteCode got %v want true", info.TrustRemoteCode)
	}
	if info.MaxModelLen != nil {
		t.Fatalf("maxModelLen got %v want null", *info.MaxModelLen)
	}
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  *bool
	}{
		{name: "absent", value: nil, want: nil},
		{name: "json bool", value: true, want: new(true)},
		{name: "json false", value: false, want: new(false)},
		{name: "numeric one", value: float64(1), want: new(true)},
		{name: "numeric zero", value: float64(0), want: new(false)},
		{name: "string one", value: "1", want: new(true)},
		{name: "string zero", value: "0", want: new(false)},
		{name: "string true", value: "True", want: new(true)},
		{name: "empty string", value: "", want: nil},
		{name: "unparseable string", value: "maybe", want: nil},
		{name: "unexpected type", value: []any{1}, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := envBool(tt.value)
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("got %v want null", *got)
			case tt.want != nil && got == nil:
				t.Fatalf("got null want %v", *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Fatalf("got %v want %v", *got, *tt.want)
			}
		})
	}
}

// Tokenizer configs carry sentinel lengths far beyond int64. Converting one
// wraps to a meaningless number, so it must report null instead.
func TestJSONInt64PtrRejectsOutOfRangeFloats(t *testing.T) {
	if got := jsonInt64Ptr(1e30); got != nil {
		t.Fatalf("got %d want null", *got)
	}
	if got := jsonInt64Ptr(float64(4096)); got == nil || *got != 4096 {
		t.Fatalf("got %v want 4096", got)
	}
	if got := jsonInt64Ptr("4096"); got == nil || *got != 4096 {
		t.Fatalf("got %v want 4096", got)
	}
	if got := jsonInt64Ptr(true); got != nil {
		t.Fatalf("got %d want null", *got)
	}
}

func TestServerInfoRequestsMachineReadableConfig(t *testing.T) {
	var sawQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/server_info" {
			t.Fatalf("path got %s", r.URL.Path)
		}
		sawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(serverInfoJSON))
	}))
	defer server.Close()

	conn := &VllmConnection{client: server.Client(), baseURL: server.URL}
	info, err := conn.ServerInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawQuery != "config_format=json" {
		t.Fatalf("query got %q want config_format=json", sawQuery)
	}
	if info == nil || info.TrustRemoteCode == nil || !*info.TrustRemoteCode {
		t.Fatalf("expected trustRemoteCode true, got %+v", info)
	}
}

// /server_info is registered only in development mode. Its absence is normal
// and must not surface as an error on every other field of the asset.
func TestServerInfoAbsentRouteIsNotAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	conn := &VllmConnection{client: server.Client(), baseURL: server.URL}
	info, err := conn.ServerInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Fatalf("got %+v want nil", info)
	}
}

//go:fix inline
func boolPtr(v bool) *bool { return new(v) }

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func derefInt(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
