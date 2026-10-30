// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package mcp_servers holds the shared discovery-target constant for MCP-server
// discovery. It lives in its own leaf package (like docker_engine) so both the
// provider config and the provider's discovery gate reference one source. The
// resolver itself lives in the resources package, where the concrete
// *.mcpServer types are defined. See ADR 030.
package mcp_servers

// DiscoveryMCPServers is the discovery target for MCP servers configured on a
// host. It is opt-in: off by default and under `auto`, on only when explicitly
// requested or under `all`.
//
// No secrets: discovery emits only how to start each server (protocol + target)
// and never the server's declared env. Secrets are supplied explicitly at
// connect time via the AI provider's `--env` flag, so they never enter the
// inventory/asset. See ADR 030.
const DiscoveryMCPServers = "mcp-servers"
