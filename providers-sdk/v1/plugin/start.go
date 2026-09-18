// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"io"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"go.mondoo.com/mql/logger"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
)

type Provider struct {
	Name            string
	ID              string
	Version         string
	ConnectionTypes []string
	Connectors      []Connector
	AssetUrlTrees   []*inventory.AssetUrlBranch
	// Platforms is the static catalog of platforms this provider can emit. It
	// lets users see the supported platforms ahead of running, and lets the
	// runtime construct platforms from a pre-defined descriptor instead of
	// hardcoding name/family/kind/runtime inline.
	Platforms []*PlatformInfo `json:",omitempty"`
	Maturity  string          `json:",omitempty"`
	// DefaultParallelism is how many of this provider's assets may be scanned
	// concurrently when the user did not ask for a specific number. Zero (the
	// default) means the provider has not opted in and its assets are scanned
	// one at a time.
	//
	// Declare the number the provider's backend can sustain -- its API rate
	// limits, its throttling behavior, the blast radius of hitting one account
	// or cluster from several assets at once. The scanner caps whatever is
	// declared here by the CPUs available on the machine, so this is a
	// statement about the target, not about the host running the scan.
	DefaultParallelism int `json:",omitempty"`
	// Requires are the other providers this one calls into, declared by the
	// consumer (ADR 042). The `.lr` import is the build-time half of the same
	// declaration; this is the half the runtime can act on, because by then the
	// question is not "does this resource exist" but "which provider answers for
	// it, is it installed, and is it new enough."
	//
	// Derived at build from the peer's `.lr.versions` and reconciled with what
	// the author declared, so it cannot drift the way the old hardcoded
	// whitelist did.
	Requires []ProviderDep `json:",omitempty"`
	// Root is the resource that roots the tree of an asset this provider
	// connects (ADR 031): the `os` provider's asset is rooted at `os`, the `ai`
	// provider's MCP connection at `mcp`. It is what `_` resolves to at the top
	// level of a query, and what an `asset<root>` chain resolves into.
	//
	// Declared here, and not on Connector, because the runtime resolves it from
	// the connection *type* it holds, and types do not map onto connectors: the
	// `os` provider ships 8 connectors covering 14 connection types
	// (`docker-image`, `tar`, `registry-image` have no connector of their own).
	// Every one of them exposes the same tree, so one declaration per provider
	// is the honest granularity. A provider that grows two roots gets a
	// per-type override, which is additive to this field.
	//
	// Empty means the provider declares no root, and `_` keeps failing for its
	// assets - which is the state every provider starts in. Do not name a
	// resource that only partly covers the asset just to make `_` answer
	// something.
	Root string `json:",omitempty"`
	// Targets are the meta-targets this provider opts into (ADR 045): a
	// declaration that some shape of file tree is this provider's, so a
	// meta-target like `iac` can offer it a candidate without hardcoding the
	// knowledge two more times the way the github and gitlab classifiers do.
	//
	// Demand-driven, and deliberately not Requires: declaring an opt-in
	// installs nothing. Which providers a run needs follows from the
	// meta-target's --discover value alone, resolved through
	// ProviderLookup{Target, Discovery} before the tree is read.
	Targets []TargetOptIn `json:",omitempty"`
}

// ProviderDep is one declared dependency on another provider.
//
// Both ID and Name are carried because both are used: the runtime matches a
// peer by ID, and the installer resolves it by name. MinVersion is the lowest
// peer version that has every resource and field this provider references.
type ProviderDep struct {
	ID   string
	Name string
	// MinVersion is a semver string, e.g. "13.3.1". Empty means no floor is
	// known, which is treated as no constraint rather than as version zero.
	MinVersion string `json:",omitempty"`
	// MaxVersion is optional and usually unset: we have no good rules yet for
	// predicting where a peer's API will break, so it is authored only when
	// someone has a specific reason.
	MaxVersion string `json:",omitempty"`
}

// PlatformInfo is the static, pre-declarable description of one platform a
// provider can emit. It captures the subset of inventory.Platform that is
// known ahead of time. Dynamic fields (Arch, Build, Version, Metadata,
// TechnologyUrlSegments, and often Title) are filled at runtime, not here.
//
// Kind and Runtime list ALL possible values the platform can take: cloud,
// SaaS, and API platforms fix a single value per name, while OS platforms can
// occur as several kinds/runtimes depending on the connection (e.g. the same
// "ubuntu" may be baremetal, virtualmachine, container, or container-image).
// The connection/detection picks the actual value at runtime.
type PlatformInfo struct {
	Name    string   `json:"name"`
	Title   string   `json:"title,omitempty"`   // optional default title
	Family  []string `json:"family,omitempty"`  // fixed family chain for this name
	Kind    []string `json:"kind,omitempty"`    // set of possible kinds
	Runtime []string `json:"runtime,omitempty"` // set of possible runtimes
}

type Connector struct {
	Name      string
	Use       string   `json:",omitempty"`
	Short     string   `json:",omitempty"`
	Long      string   `json:",omitempty"`
	MinArgs   uint     `json:",omitempty"`
	MaxArgs   uint     `json:",omitempty"`
	IsHidden  bool     `json:",omitempty"`
	Flags     []Flag   `json:",omitempty"`
	Aliases   []string `json:",omitempty"`
	Discovery []string `json:",omitempty"`
	Maturity  string   `json:",omitempty"`
}

func Start(args []string, impl ProviderPlugin) {
	logger.CliCompactLogger(logger.LogOutputWriter)

	var logLevel string
	pflag.StringVar(&logLevel, "log-level", "warn", "Log level")
	pflag.Parse()

	ll, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Warn().Msgf("Failed parsing log level: %s", logLevel)
	} else {
		zerolog.SetGlobalLevel(ll)
	}
	log.Debug().Msgf("Log level set to %s", ll)

	// disable the plugin's logs
	pluginLogger := hclog.New(&hclog.LoggerOptions{
		Name: "mql-plugin",
		// Level: hclog.LevelFromString("DEBUG"),
		Level:  hclog.Info,
		Output: io.Discard,
	})

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins: map[string]plugin.Plugin{
			"provider": &ProviderPluginImpl{Impl: impl},
		},
		Logger: pluginLogger,

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
