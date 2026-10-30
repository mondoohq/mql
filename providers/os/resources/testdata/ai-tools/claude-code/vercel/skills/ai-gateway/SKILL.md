---
name: ai-gateway
description: Vercel AI Gateway guidance for setup, model discovery, authentication, routing, fallbacks, BYOK, budgets, spend reporting, observability, compatible APIs, and coding-agent configuration. Use when adding AI Gateway to an app, migrating provider calls, choosing models or providers, debugging gateway requests, or running `vercel ai-gateway` commands.
summary: Set up and operate Vercel AI Gateway with current models, correct authentication, routing, spend controls, and verification.
metadata:
  priority: 7
  docs:
    - "https://vercel.com/docs/ai-gateway"
    - "https://vercel.com/docs/ai-gateway/getting-started"
    - "https://ai-sdk.dev/providers/ai-sdk-providers/ai-gateway"
  sitemap: "https://vercel.com/docs/sitemap.md"
  pathPatterns: []
  importPatterns:
    - 'ai'
    - '@ai-sdk/gateway'
  bashPatterns:
    - '\bvercel\s+ai-gateway\b'
    - '\bvercel\s+env\s+pull\b'
    - '\bnpm\s+(install|i|add)\s+[^\n]*@ai-sdk/gateway\b'
    - '\bpnpm\s+(install|i|add)\s+[^\n]*@ai-sdk/gateway\b'
    - '\bbun\s+(install|i|add)\s+[^\n]*@ai-sdk/gateway\b'
    - '\byarn\s+add\s+[^\n]*@ai-sdk/gateway\b'
  promptSignals:
    phrases:
      - "ai gateway"
      - "vercel ai gateway"
      - "ai-gateway"
      - "ai-gateway.vercel.sh"
    allOf:
      - [model, routing]
      - [provider, failover]
      - [gateway, budget]
      - [gateway, logs]
      - [gateway, oidc]
      - [coding, gateway]
    anyOf:
      - "provider ordering"
      - "model fallback"
      - "byok"
      - "spend tracking"
      - "gateway key"
      - "credit balance"
      - "safety identifier"
      - "reasoning effort"
      - "tool calling"
      - "structured outputs"
    noneOf:
      - "cloudflare ai gateway"
      - "aws api gateway"
    minScore: 6
validate:
  -
    pattern: '\bclaude-(sonnet|opus|haiku)-\d+-\d+\b'
    message: 'Claude model version uses a hyphen where the AI Gateway slug uses a dot. Fetch /v1/models and use the returned provider/model ID.'
    severity: error
  -
    pattern: gateway\(['"][^'"/]+['"]\)
    message: 'AI Gateway model string is missing its provider prefix. Fetch /v1/models and use a provider/model ID.'
    severity: error
  -
    pattern: (OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY)
    message: 'Provider key detected. AI Gateway request authentication uses AI_GATEWAY_API_KEY or VERCEL_OIDC_TOKEN; provider keys belong only in an intentional BYOK configuration.'
    severity: recommended
    skipIfFileContains: '[Bb][Yy][Oo][Kk]|providerOptions\s*:\s*\{[^}]*gateway'
  -
    pattern: gateway\s*:\s*\{[^}]*cacheControl
    message: "AI Gateway does not cache whole responses through cacheControl. Use caching: 'auto' for provider prompt caching and verify the current caching docs."
    severity: error
  -
    pattern: ANTHROPIC_BASE_URL\s*=\s*["']?https://ai-gateway\.vercel\.sh
    message: 'Claude Code through AI Gateway needs ANTHROPIC_API_KEY set to an empty value and the gateway key in ANTHROPIC_AUTH_TOKEN. A non-empty ANTHROPIC_API_KEY is used instead of the gateway token.'
    severity: recommended
    skipIfFileContains: 'ANTHROPIC_AUTH_TOKEN'
chainTo:
  -
    pattern: 'from\s+[''"]ai[''"]|require\([''"]ai[''"]\)|\b(generateText|streamText|ToolLoopAgent)\b'
    targetSkill: ai-sdk
    message: 'AI SDK code detected. Load the AI SDK skill and read the installed package docs before writing or changing SDK code.'
retrieval:
  aliases:
    - model router
    - ai proxy
    - provider failover
    - llm gateway
    - gateway credits
  intents:
    - add Vercel AI Gateway to an application
    - route AI models across providers
    - configure provider or model fallbacks
    - authenticate AI Gateway requests
    - track AI model costs and set budgets
    - debug AI Gateway requests and routing
    - connect coding agents to AI Gateway
    - find a model by modality, capability, price, or data retention
    - check AI Gateway credit balance or generation cost
    - configure reasoning or extended thinking across providers and API formats
    - add tool calling or function calling across API formats
    - get structured JSON output matching a schema
    - send images or PDFs to a model
  entities:
    - AI Gateway
    - AI Gateway Credits
    - providerOptions.gateway
    - AI_GATEWAY_API_KEY
    - VERCEL_OIDC_TOKEN
    - model routing
    - provider failover
    - BYOK
    - spend reporting
    - safetyIdentifier
    - Usage & Billing API
---
