# ADR 045: System proxy detection

## Status

Accepted, implemented in mql and cnspec (September 2026).

## Context

Every outbound HTTP client in mql and cnspec was built from one of two proxy
sources: an `api_proxy` set explicitly (config file, `--api-proxy`,
`MONDOO_API_PROXY`) or the `HTTPS_PROXY` environment convention that Go's
`net/http` reads. Nothing else was consulted.

Windows machines rarely have `HTTPS_PROXY` set. The proxy lives in the
operating system: per user in Internet Settings (Settings > Network &
internet > Proxy), as a manual proxy with an exception list, a setup script
(PAC) URL, or "automatically detect settings" (WPAD), and per machine in the
WinHTTP default that administrators set with `netsh winhttp set proxy` so that
services can reach the internet. Browsers, PowerShell, .NET and Windows Update
all read these. A freshly installed cnspec did not, so on a proxied Windows
machine the first `cnspec login` or the `cnspec serve` service failed to reach
the platform until someone found the `api_proxy` key. That is the opposite of
the path of least resistance the product promises.

## Decision

1. **Read the operating system's proxy settings and use them when nothing
   more specific is configured.** A new leaf package, `utils/sysproxy`,
   detects the settings and answers per destination. On Windows it calls
   `winhttp.dll` through the lazy DLL loader (no cgo, as the release build
   requires): `WinHttpGetIEProxyConfigForCurrentUser` for the per-user
   Internet Settings, the HKLM Internet Settings when group policy stores
   them per machine (`ProxySettingsPerUser = 0`, which WinHTTP does not
   read), `WinHttpGetDefaultProxyConfiguration` for the `netsh` default, and
   `WinHttpGetProxyForUrl` to run a setup script or WPAD discovery. Other
   platforms report no settings; a macOS reader would slot into the same
   shape.

2. **Precedence is fixed and documented in one place** (`cli/config/proxy.go`):
   `--api-proxy` or `MONDOO_API_PROXY`, then `api_proxy` in the config file,
   then `HTTPS_PROXY`/`HTTP_PROXY` with `NO_PROXY`, then the operating
   system's settings, then a direct connection. A proxy in the config file
   therefore overrides anything the environment or the operating system says.
   Within the operating system's settings the order is the one Windows uses:
   the script's answer when a script is configured and runs (its DIRECT is
   final), otherwise the per-user manual proxy with its exceptions, otherwise
   the machine-wide WinHTTP proxy with its exceptions. Loopback is never
   proxied unless an exception list says `<-loopback>`, and `NO_PROXY` keeps
   its meaning next to a system proxy.

3. **One opt-out, `system_proxy: false`** (`MONDOO_SYSTEM_PROXY=false`),
   restores the previous behavior exactly: steps one to three stay, only the
   operating system's settings are no longer read. There is no second knob
   for "direct even if the environment says otherwise"; `NO_PROXY=*` already
   does that and always has.

4. **Provider subprocesses see the same decision.** The provider's own
   platform client resolves the system proxy itself, through the same
   package inside `providers-sdk/v1/upstream`, so PAC answers stay
   per-destination. The cloud SDKs inside providers only read the
   environment, so the coordinator exports the system proxy to the provider
   as `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` (a script is evaluated for
   the Mondoo API endpoint, the one destination we know matters; the
   exception list is translated where Go's `NO_PROXY` syntax can express it),
   and the opt-out as `MONDOO_SYSTEM_PROXY=false`. Variables already in the
   environment are never overridden. `api_proxy` is not exported: it is
   scoped to platform traffic and reaches providers through the upstream
   config, as before.

5. **Cost is bounded.** Detection is cached for five minutes so a
   long-running `cnspec serve` follows a changed proxy without a restart and
   a scan pays once. Script evaluation is cached per origin with the same
   TTL, a failed WPAD discovery is remembered so the Windows default of
   "automatically detect settings" with no proxy costs one failed probe and
   not one per host, and a request waits at most fifteen seconds for a
   script before it falls back to the manual settings. `mql status` and
   `cnspec status` print the proxy in effect and where it came from.

## Consequences

- A Windows install with a system proxy works with no proxy configuration,
  for the CLI, the Windows service, and the providers it starts. A machine
  without a proxy behaves as before, with one WPAD probe on the first
  platform call if auto-detection is on, answered from the WinHTTP
  Auto-Discovery Service's cache on most machines.
- `HTTPS_PROXY` is now read with Go's full semantics (`HTTP_PROXY` for http
  targets, `NO_PROXY` honored) at every call site, where a few sites had
  copied only `HTTPS_PROXY` into a fixed proxy URL. `api_proxy` values
  without a scheme (`proxy.corp:3128`) are accepted as http.
- `config.GetAPIProxy` stays for compatibility but is deprecated: it returns
  one fixed URL and cannot express a per-destination answer, so it never
  reports the system proxy. New code takes `config.ProxyFunc` or
  `config.NewHttpClient`.
- The Windows API layer cannot be unit tested off Windows; its smoke tests
  run in the Windows CI job, and the selection logic, list parsing, bypass
  matching and `NO_PROXY` translation are pure Go with tests on every
  platform.
