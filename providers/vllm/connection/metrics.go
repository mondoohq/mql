// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

const (
	metricsPath    = "/metrics"
	maxMetricsBody = 16 << 20

	// metricNamePrefix restricts label harvesting to vLLM's own series. A
	// sidecar exporter scraped through the same endpoint uses its own names and
	// its labels say nothing about what this server serves.
	metricNamePrefix = "vllm:"

	loraMetricName = "vllm:lora_requests_info"
	// cacheConfigMetricName is vLLM's engine-configuration info series. It
	// carries the cache configuration as labels and is emitted whenever the
	// Prometheus endpoint is enabled at all.
	cacheConfigMetricName = "vllm:cache_config_info"

	labelModelName          = "model_name"
	labelRunningLoraAdapter = "running_lora_adapters"
	labelWaitingLoraAdapter = "waiting_lora_adapters"
)

// MetricsSnapshot is what an unauthenticated Prometheus scrape of a vLLM server
// discloses about the workload: the served model names carried as labels on
// vLLM's own series, and the LoRA adapter names carried on
// vllm:lora_requests_info.
type MetricsSnapshot struct {
	// Fetched reports whether an anonymous scrape returned a body. When it is
	// false the two name lists are meaningless and callers must render null.
	Fetched bool
	// CacheConfigExposed reports whether the engine-configuration info series
	// was present in the scrape.
	CacheConfigExposed bool
	// CacheConfig is the label set carried on the engine-configuration info
	// series, keyed by label name. A scrape that answered but carried no such
	// series leaves it empty, which is a different answer from a scrape that
	// never happened.
	CacheConfig  map[string]string
	ModelNames   []string
	LoraAdapters []string
}

// MetricsSnapshot scrapes /metrics once per connection. The scrape is
// deliberately anonymous even when an API key is configured: the question this
// answers is what an unauthenticated scraper learns, and vLLM's built-in
// API-key middleware does not guard /metrics at all.
func (c *VllmConnection) MetricsSnapshot(ctx context.Context) (*MetricsSnapshot, error) {
	c.metricsOnce.Do(func() {
		resp, err := c.Request(ctx, http.MethodGet, metricsPath, false, "")
		if err != nil {
			c.metricsErr = err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNotImplemented {
			discardProbeBody(resp.Body)
			c.metrics = &MetricsSnapshot{}
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			discardProbeBody(resp.Body)
			c.metricsErr = fmt.Errorf("vllm: /metrics returned HTTP %d", resp.StatusCode)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMetricsBody))
		if err != nil {
			c.metricsErr = err
			return
		}
		c.metrics = ParseMetrics(raw)
	})
	return c.metrics, c.metricsErr
}

// ParseMetrics harvests the identifying labels out of a Prometheus text
// exposition body. It reads label sets only; no sample value is retained.
func ParseMetrics(raw []byte) *MetricsSnapshot {
	snapshot := &MetricsSnapshot{Fetched: true, CacheConfig: map[string]string{}}

	models := map[string]struct{}{}
	adapters := map[string]struct{}{}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, labels, ok := parseMetricLine(line)
		if !ok || !strings.HasPrefix(name, metricNamePrefix) {
			continue
		}
		if name == cacheConfigMetricName {
			snapshot.CacheConfigExposed = true
			// The engine cache settings travel as the labels of this series.
			// Only its labels are harvested: a label read off any other series
			// would report a value that is not part of the cache configuration.
			for key, value := range labels {
				snapshot.CacheConfig[key] = value
			}
		}
		if model := strings.TrimSpace(labels[labelModelName]); model != "" {
			models[model] = struct{}{}
		}
		if name == loraMetricName {
			for _, label := range []string{labelRunningLoraAdapter, labelWaitingLoraAdapter} {
				for _, adapter := range strings.Split(labels[label], ",") {
					adapter = strings.TrimSpace(adapter)
					if adapter != "" {
						adapters[adapter] = struct{}{}
					}
				}
			}
		}
	}

	snapshot.ModelNames = sortedKeys(models)
	snapshot.LoraAdapters = sortedKeys(adapters)
	return snapshot
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// parseMetricLine splits one Prometheus exposition sample into its metric name
// and its label set. Label values are unescaped per the exposition format, so a
// model path containing a quote or a backslash is read whole rather than
// truncated at the escape.
func parseMetricLine(line string) (string, map[string]string, bool) {
	open := strings.IndexByte(line, '{')
	if open < 0 {
		name, _, _ := strings.Cut(line, " ")
		name = strings.TrimSpace(name)
		if name == "" {
			return "", nil, false
		}
		return name, map[string]string{}, true
	}

	name := strings.TrimSpace(line[:open])
	if name == "" {
		return "", nil, false
	}

	labels := map[string]string{}
	rest := line[open+1:]
	for {
		rest = strings.TrimLeft(rest, " ,")
		if rest == "" {
			return name, labels, true
		}
		if rest[0] == '}' {
			return name, labels, true
		}
		key, remainder, found := strings.Cut(rest, "=")
		if !found {
			return name, labels, true
		}
		key = strings.TrimSpace(key)
		remainder = strings.TrimLeft(remainder, " ")
		if remainder == "" || remainder[0] != '"' {
			return name, labels, true
		}
		value, remainder, ok := scanLabelValue(remainder[1:])
		if !ok {
			return name, labels, true
		}
		labels[key] = value
		rest = remainder
	}
}

// scanLabelValue consumes a quoted, backslash-escaped Prometheus label value
// and returns it alongside the remainder of the line.
func scanLabelValue(in string) (string, string, bool) {
	var out strings.Builder
	for i := 0; i < len(in); i++ {
		switch in[i] {
		case '\\':
			if i+1 >= len(in) {
				return "", "", false
			}
			i++
			switch in[i] {
			case 'n':
				out.WriteByte('\n')
			case '\\':
				out.WriteByte('\\')
			case '"':
				out.WriteByte('"')
			default:
				out.WriteByte(in[i])
			}
		case '"':
			return out.String(), in[i+1:], true
		default:
			out.WriteByte(in[i])
		}
	}
	return "", "", false
}
