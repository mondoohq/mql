# vLLM Provider

The vLLM provider probes the externally observable HTTP posture of a vLLM
inference server. It checks selected documentation, metadata, OpenAI-compatible,
metrics, utility, and operational endpoints from the URL supplied to the
connector.

## Authentication

Authenticated comparison probes use an API key from `--api-key`, inventory
credentials, the `api-key` option, or `VLLM_API_KEY`. Explicit credentials in
the connection configuration take precedence over environment variables.

## Usage

```bash
mql shell vllm http://localhost:8000
mql shell vllm https://vllm.example.com --api-key <token>
```

Use `--insecure` only for lab or test endpoints where TLS certificate
verification is intentionally disabled.

## What the provider reads

| Resource | Answers |
|---|---|
| `vllm.server` | Whether the server is reachable, what it leaks anonymously, whether a stranger can run inference, whether runtime LoRA loading is on, whether stored responses are readable |
| `vllm.endpoints` | Per-route anonymous and authenticated probe results |
| `vllm.serverInfo` | Engine configuration, including `trustRemoteCode`, tokenizer mode, context window, quantization, prefix caching, LoRA support, parallelism, and the tracing configuration |
| `vllm.tokenizerInfo` | Tokenizer class, special tokens, and the chat template with a digest for fleet comparison |
| `vllm.metrics` | Whether the Prometheus endpoint answers anonymously, and the model and LoRA adapter names it discloses |
| `vllm.models` | Served models and the per-model permission entries the server advertises |

`vllm.serverInfo` reads `/server_info`, which vLLM registers only in development
mode, and `vllm.tokenizerInfo` reads `/tokenizer_info`, which vLLM registers
only when the endpoint is explicitly enabled. On a hardened deployment both
report `exposed` as false and leave every configuration field null.

Note that vLLM's built-in API key guards only routes under the `/v1`, `/v2`,
`/inference`, and `/cohere` prefixes. A server can require a key on
`/v1/chat/completions` and still answer `/metrics`, `/server_info`,
`/tokenizer_info`, `/tokenize`, `/classify`, `/score`, and `/invocations` to any
caller, which is why `vllm.endpoints` reports each route separately.

## Probe Safety

Several vLLM routes change server state when they are called: `/sleep` offloads
the engine, `/pause` aborts every in-flight request, `/abort_requests` with an
empty body aborts everything the engine is tracking, the cache-reset routes drop
caches, the LoRA routes swap the served adapters, and the responses cancel route
cancels a caller's response.

The provider never invokes any of them. Each is registered with the method it
documents, but probed with an HTTP `GET` that the route does not accept. The
router answers `405 Method Not Allowed` when the route is registered and `404`
when it is not, so presence is read from routing alone and no handler runs.
Those probes carry no request body.

The stored-response routes are addressed with a synthetic identifier
(`resp_` followed by 32 zeros) that cannot name a real response, because vLLM
mints stored-response identifiers from a random UUID. The retrieval probe reads
only enough of the reply to tell the router's "no such route" apart from the
handler's "no such response", and no response payload is ever stored or
surfaced. The `/render` routes are probed with a body the request validator
rejects before any template is applied, so no assembled prompt is ever returned.

## Security Considerations

Only point this provider at vLLM endpoints you are authorized to assess. The
connector sends HTTP requests to the configured URL. If policies or automation
build that URL from untrusted asset metadata, the scan can become a server-side
request forgery path to internal addresses such as loopback, link-local
metadata services, or private network hosts.

Redirects are not followed. This keeps endpoint posture tied to the probed path
and avoids forwarding bearer tokens to redirect targets.
