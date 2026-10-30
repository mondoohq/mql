#!/bin/bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

# Verify the mql vLLM provider against a live vLLM instance.
#
# Prerequisites:
#   - mql installed with the vllm provider built and installed
#   - A running vLLM server (see README.md for setup)
#
# Usage:
#   VLLM_IP=localhost ./providers/vllm/testdata/verify.sh
#   VLLM_IP=192.168.1.100 VLLM_PORT=8080 ./providers/vllm/testdata/verify.sh

set -eo pipefail

VLLM_IP="${VLLM_IP:-localhost}"
VLLM_PORT="${VLLM_PORT:-8000}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

pass=0
fail=0

run_query() {
  local desc="$1"
  local query="$2"
  local result
  local exit_code=0
  result=$(mql run vllm "http://${VLLM_IP}:${VLLM_PORT}" -c "$query" 2>&1) || exit_code=$?

  local filtered
  filtered=$(echo "$result" | grep -v "loaded configuration from")

  if [ "$exit_code" -ne 0 ] || echo "$filtered" | grep -qi "error occurred\|panic\|unable to"; then
    echo -e "${RED}FAIL${NC}: $desc"
    echo "  Query: $query"
    echo "$filtered" | head -5 | sed 's/^/  /'
    fail=$((fail + 1))
  else
    echo -e "${GREEN}PASS${NC}: $desc"
    pass=$((pass + 1))
  fi
}

if ! command -v mql &>/dev/null; then
  echo "Error: mql is not installed or not in PATH"
  exit 1
fi

if ! curl -sf "http://${VLLM_IP}:${VLLM_PORT}/health" >/dev/null 2>&1; then
  echo "Error: vLLM is not reachable at http://${VLLM_IP}:${VLLM_PORT}/health"
  echo "See README.md for setup instructions."
  exit 1
fi

echo -e "${CYAN}==>${NC} vLLM reachable at http://${VLLM_IP}:${VLLM_PORT}"
echo ""
echo "=== mql vLLM Provider Verification ==="
echo ""

# Server posture
run_query "server summary" "vllm.server { baseUrl reachable version }"
run_query "server TLS" "vllm.server { usesTls }"
run_query "server CORS" "vllm.server { corsConfigured corsAllowsAnyOrigin }"
run_query "server docs exposure" "vllm.server { docsExposed openapiExposed }"
run_query "server metrics exposure" "vllm.server { metricsExposed loadEndpointExposed }"
run_query "server dev endpoints" "vllm.server { devEndpointsExposed profilerEndpointsExposed tokenizerInfoExposed }"
run_query "server anonymous inference" "vllm.server { anonymousInferenceAllowed apiKeyRequired }"
run_query "server runtime lora" "vllm.server { runtimeLoraUpdatingEnabled }"
run_query "server stored responses" "vllm.server { storedResponsesExposed }"

# Endpoints
run_query "endpoint list" "vllm.endpoints { method path category present }"
run_query "endpoint access" "vllm.endpoints { anonymousAccessible requiresAuth }"
run_query "endpoint status codes" "vllm.endpoints { anonymousStatusCode }"

# Metrics
run_query "metrics posture" "vllm.metrics { prometheusExposed loadEndpointExposed loadTrackingVisible }"
run_query "metrics disclosure" "vllm.metrics { exposedModelNames exposedLoraAdapters }"

# Engine configuration
run_query "engine configuration" "vllm.serverInfo { exposed configReadable trustRemoteCode tokenizerMode model tokenizer }"
run_query "engine limits" "vllm.serverInfo { maxModelLen quantization enforceEager enablePrefixCaching servedModelNames }"
run_query "engine lora" "vllm.serverInfo { loraEnabled maxLoras maxLoraRank loraConfig }"
run_query "engine parallelism" "vllm.serverInfo { tensorParallelSize pipelineParallelSize dataParallelSize parallelConfig }"
run_query "engine tracing" "vllm.serverInfo { otlpTracesEndpoint collectDetailedTraces loggingIterationDetailsEnabled }"
run_query "engine mode" "vllm.serverInfo { serverDevMode allowRuntimeLoraUpdating }"

# Tokenizer and chat template
run_query "tokenizer posture" "vllm.tokenizerInfo { exposed tokenizerClass chatTemplateConfigured chatTemplateSha256 }"
run_query "tokenizer tokens" "vllm.tokenizerInfo { maxLength addBosToken addEosToken bosToken eosToken padToken unkToken }"

# Version
run_query "vllm version" "vllm.version"

# Models
run_query "model list" "vllm.models { id root maxModelLen }"
run_query "model details" "vllm.models { id ownedBy created parent }"
run_query "model count" "vllm.models.length"
run_query "model permissions" "vllm.models { id permissions { id allowSampling allowFineTuning allowCreateEngine organization group isBlocking } }"

echo ""
echo "=== Results: ${pass} passed, ${fail} failed ==="

if [ "$fail" -gt 0 ]; then
  exit 1
fi
