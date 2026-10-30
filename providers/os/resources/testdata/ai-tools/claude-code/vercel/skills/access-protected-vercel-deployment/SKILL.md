---
name: access-protected-vercel-deployment
description: Access and test Vercel deployments protected by Vercel Authentication, SSO, or Deployment Protection. Use when curl, agent-browser, Playwright, or another automated request reaches a Vercel login or protection page; when a protected preview or production URL returns 401 or 403; when TRUSTED_SOURCES_ENVIRONMENT_MISMATCH appears; or when choosing between `vercel curl` and the `x-vercel-trusted-oidc-idp-token` header.
summary: Access protected Vercel URLs with vercel curl or a short-lived OIDC token
metadata:
  priority: 8
  docs:
    - "https://vercel.com/docs/cli/curl"
    - "https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/trusted-sources"
    - "https://vercel.com/docs/oidc#in-local-development"
  sitemap: "https://vercel.com/sitemap.xml"
  pathPatterns: []
  bashPatterns:
    # Match vc curl for every hostname, including custom aliases.
    - '\b(?:vercel|vc)\s+curl\b'
    # Keep raw clients scoped to hostnames that identify themselves as Vercel.
    - '\b(?:curl|wget)\b[^\n]*\.vercel\.app\b'
    - '\bagent-browser\b[^\n]*(?:open|navigate|goto)[^\n]*\.vercel\.app\b'
    # Match custom aliases when the request includes an explicit Vercel protection header.
    - '\bx-vercel-(?:trusted-oidc-idp-token|protection-bypass)\b'
  importPatterns: []
  promptSignals:
    phrases:
      - "access protected vercel deployment"
      - "protected vercel deployment"
      - "deployment protection"
      - "vercel sso"
      - "vercel authentication page"
      - "behind vercel authentication"
      - "behind vercel sso"
      - "x-vercel-trusted-oidc-idp-token"
      - "trusted_sources_environment_mismatch"
      - "trusted sources environment mismatch"
      - "protection bypass"
    allOf:
      - [vercel, protected]
      - [vercel, sso]
      - [vercel, "403"]
      - [deployment, login]
      - [preview, protected]
      - [production, protected]
    anyOf:
      - "deployment"
      - "preview"
      - "production"
      - "curl"
      - "browser"
      - "authentication"
    noneOf:
      - "aws deployment protection"
      - "github deployment protection"
      - "kubernetes deployment protection"
    minScore: 6
retrieval:
  aliases:
    - protected Vercel deployment
    - Vercel SSO bypass
    - Vercel deployment authentication
    - Vercel Trusted Sources
  intents:
    - access a protected deployment
    - test a protected preview
    - verify a protected production deployment
    - authenticate browser automation to Vercel
  entities:
    - vercel curl
    - VERCEL_OIDC_TOKEN
    - x-vercel-trusted-oidc-idp-token
    - Trusted Sources
    - Deployment Protection
  examples:
    - preview is behind Vercel SSO
    - curl this protected Vercel deployment
    - access a protected Vercel deployment through a custom domain
    - open the protected production URL in agent-browser
---
