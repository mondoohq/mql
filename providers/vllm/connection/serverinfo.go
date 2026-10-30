// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
)

const (
	// serverInfoPath asks for the machine-readable rendering of the engine
	// configuration. Servers that predate the parameter ignore it and return
	// the string repr instead, which decodes to an unstructured ServerInfo.
	serverInfoPath = "/server_info?config_format=json"

	maxServerInfoBody = 8 << 20

	envAllowRuntimeLoraUpdating = "VLLM_ALLOW_RUNTIME_LORA_UPDATING"
	envServerDevMode            = "VLLM_SERVER_DEV_MODE"
)

// ServerInfo is the engine configuration a vLLM server reports on
// /server_info. Every value is a pointer or a nil-able slice so a field the
// server did not report stays null instead of collapsing into a Go zero value
// that would read as a deliberate setting.
type ServerInfo struct {
	// Structured reports whether the server returned engine configuration this
	// provider could decode. It is false when the route answered with the
	// human-readable string repr, which carries no reliable field boundaries.
	Structured bool

	Model            *string
	Tokenizer        *string
	TokenizerMode    *string
	TrustRemoteCode  *bool
	ServedModelNames []string
	MaxModelLen      *int64
	Quantization     *string
	EnforceEager     *bool

	EnablePrefixCaching *bool

	LoraEnabled *bool
	MaxLoras    *int64
	MaxLoraRank *int64
	LoraConfig  map[string]any

	TensorParallelSize   *int64
	PipelineParallelSize *int64
	DataParallelSize     *int64
	ParallelConfig       map[string]any

	OtlpTracesEndpoint      *string
	CollectDetailedTraces   []string
	LoggingIterationDetails *bool

	AllowRuntimeLoraUpdating *bool
	ServerDevMode            *bool
}

type serverInfoDoc struct {
	VllmConfig json.RawMessage `json:"vllm_config"`
	VllmEnv    map[string]any  `json:"vllm_env"`
}

// vllmConfigDoc keeps every configuration block as a loose map. The blocks
// gain, lose, and re-render fields between vLLM releases, and decoding
// straight into typed pointers turns any rendering the struct did not expect
// into a Go zero value: a mistyped max_model_len would report 0, and a
// mistyped trust_remote_code would report false on a server that executes
// repository code. Reading each value through a tolerant accessor keeps an
// unexpected rendering null.
type vllmConfigDoc struct {
	ModelConfig         map[string]any `json:"model_config"`
	CacheConfig         map[string]any `json:"cache_config"`
	LoRAConfig          map[string]any `json:"lora_config"`
	ParallelConfig      map[string]any `json:"parallel_config"`
	ObservabilityConfig map[string]any `json:"observability_config"`
}

// ServerInfo fetches and decodes /server_info once per connection. The route is
// registered only when the server runs in development mode, so a production
// server answers 404 and this returns a nil ServerInfo with no error.
func (c *VllmConnection) ServerInfo(ctx context.Context) (*ServerInfo, error) {
	c.serverInfoOnce.Do(func() {
		resp, err := c.Request(ctx, http.MethodGet, serverInfoPath, true, "")
		if err != nil {
			c.serverInfoErr = err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNotImplemented {
			discardProbeBody(resp.Body)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			discardProbeBody(resp.Body)
			c.serverInfoErr = fmt.Errorf("vllm: /server_info returned HTTP %d", resp.StatusCode)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxServerInfoBody))
		if err != nil {
			c.serverInfoErr = err
			return
		}
		info, err := ParseServerInfo(raw)
		if err != nil {
			c.serverInfoErr = err
			return
		}
		c.serverInfo = info
	})
	return c.serverInfo, c.serverInfoErr
}

// ParseServerInfo decodes a /server_info payload. A payload whose vllm_config
// is the human-readable string repr yields a ServerInfo with Structured false
// and every configuration field null: the repr is not parsed, because a
// best-effort scrape of it would report guesses as facts.
func ParseServerInfo(raw []byte) (*ServerInfo, error) {
	var doc serverInfoDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("vllm: failed to parse /server_info response: %w", err)
	}

	info := &ServerInfo{}
	info.AllowRuntimeLoraUpdating = envBool(doc.VllmEnv[envAllowRuntimeLoraUpdating])
	info.ServerDevMode = envBool(doc.VllmEnv[envServerDevMode])

	if !isJSONObject(doc.VllmConfig) {
		return info, nil
	}
	info.Structured = true

	var config vllmConfigDoc
	if err := json.Unmarshal(doc.VllmConfig, &config); err != nil {
		return info, nil
	}

	m := config.ModelConfig
	info.Model = jsonStringPtr(m["model"])
	info.Tokenizer = jsonStringPtr(m["tokenizer"])
	info.TokenizerMode = jsonStringPtr(m["tokenizer_mode"])
	info.TrustRemoteCode = jsonBoolPtr(m["trust_remote_code"])
	info.MaxModelLen = jsonInt64Ptr(m["max_model_len"])
	info.Quantization = jsonStringPtr(m["quantization"])
	info.EnforceEager = jsonBoolPtr(m["enforce_eager"])
	info.ServedModelNames = jsonStringList(m["served_model_name"])

	info.EnablePrefixCaching = jsonBoolPtr(config.CacheConfig["enable_prefix_caching"])

	o := config.ObservabilityConfig
	info.OtlpTracesEndpoint = jsonStringPtr(o["otlp_traces_endpoint"])
	info.CollectDetailedTraces = jsonStringList(o["collect_detailed_traces"])
	info.LoggingIterationDetails = jsonBoolPtr(o["enable_logging_iteration_details"])

	// lora_config is null on a server that was not started with LoRA support,
	// which is itself the answer to "can this server serve adapters at all".
	enabled := config.LoRAConfig != nil
	info.LoraEnabled = &enabled
	if enabled {
		info.LoraConfig = config.LoRAConfig
		info.MaxLoras = jsonInt64Ptr(config.LoRAConfig["max_loras"])
		info.MaxLoraRank = jsonInt64Ptr(config.LoRAConfig["max_lora_rank"])
	}

	if config.ParallelConfig != nil {
		info.ParallelConfig = config.ParallelConfig
		info.TensorParallelSize = jsonInt64Ptr(config.ParallelConfig["tensor_parallel_size"])
		info.PipelineParallelSize = jsonInt64Ptr(config.ParallelConfig["pipeline_parallel_size"])
		info.DataParallelSize = jsonInt64Ptr(config.ParallelConfig["data_parallel_size"])
	}

	return info, nil
}

// envBool reads a VLLM_* environment value out of the vllm_env block. vLLM
// canonicalizes those values before serializing them, so the same flag can
// arrive as a JSON bool, as a number, or as the string form it had in the
// process environment.
func envBool(value any) *bool {
	switch v := value.(type) {
	case nil:
		return nil
	case bool:
		return &v
	case float64:
		out := v != 0
		return &out
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		if parsed, err := strconv.ParseBool(trimmed); err == nil {
			return &parsed
		}
		if parsed, err := strconv.ParseFloat(trimmed, 64); err == nil {
			out := parsed != 0
			return &out
		}
		return nil
	default:
		return nil
	}
}

// isJSONObject reports whether a raw JSON value is an object. A /server_info
// payload rendered with the default text format puts a Python repr string here
// instead, and that is the signal that no field is machine-readable.
func isJSONObject(raw json.RawMessage) bool {
	return strings.HasPrefix(strings.TrimSpace(string(raw)), "{")
}

// jsonStringPtr reads a string out of a decoded JSON value. Anything that is
// not a string, including an absent key and an explicit null, reads as null so
// no value is invented for a field the server did not report as text.
func jsonStringPtr(value any) *string {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	return &text
}

// jsonBoolPtr reads a boolean out of a decoded JSON value. A value rendered as
// something other than a JSON bool reads as null rather than as false: a
// fabricated false on a field such as trust_remote_code would report a
// safeguard the server never claimed.
func jsonBoolPtr(value any) *bool {
	switch v := value.(type) {
	case bool:
		return &v
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return nil
		}
		return &parsed
	default:
		return nil
	}
}

// jsonStringList reads a value vLLM types as `str | list[str] | None`, which
// served_model_name and collect_detailed_traces both are.
func jsonStringList(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

// jsonInt64Ptr reads an integer out of a decoded JSON value, tolerating the
// number and string renderings a config block can carry.
func jsonInt64Ptr(value any) *int64 {
	switch v := value.(type) {
	case float64:
		// Tokenizer configs routinely carry sentinel lengths far beyond int64
		// (model_max_length is often 1e30). Converting those wraps to a
		// meaningless number, so report null instead.
		if v > math.MaxInt64 || v < math.MinInt64 {
			return nil
		}
		out := int64(v)
		return &out
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			return nil
		}
		return &parsed
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return nil
		}
		return &parsed
	default:
		return nil
	}
}
