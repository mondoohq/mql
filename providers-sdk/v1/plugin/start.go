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
	"go.mondoo.com/mql/cli/prof"
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

	// A provider runs as its own process, so its memory is invisible to a heap
	// profile of the parent. MONDOO_PROVIDER_PROF exposes the pprof endpoints of
	// this process, which is the only way to attribute provider memory to
	// allocation sites. Example:
	//
	//   MONDOO_PROVIDER_PROF='enable,listen=localhost:0' mql run docker image <ref> -c "packages.length"
	//
	// The provider logs the address it picked. It stays off when the variable is
	// unset.
	prof.InitProfilerFor("MONDOO_PROVIDER_PROF")

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
