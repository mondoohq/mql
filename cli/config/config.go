// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"sync/atomic"

	"github.com/cockroachdb/errors"
	"github.com/go-viper/mapstructure/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
)

/*
	Configuration is loaded in this order:
	ENV -> ~/.mondoo.conf -> defaults
*/

// Path is the currently loaded config location
// or default if no config exits
var (
	Features mql.Features
	// Strict is the config-file default for ADR 043 strict mode, used by
	// surfaces that carry no content of their own (shell, `mql run`). Content
	// that declares its own mode overrides this.
	Strict bool
)

const (
	configSourceBase64 = "$MONDOO_CONFIG_BASE64"
	defaultAPIendpoint = "https://us.api.mondoo.com"

	AUTH_METHOD_SSH = "ssh"
	AUTH_METHOD_WIF = "wif"
)

// Init initializes and loads the mondoo config
func Init(rootCmd *cobra.Command) {
	cobra.OnInitialize(InitViperConfig, func() {
		var err error
		Features, err = mql.InitFeatures(viper.GetStringSlice("features")...)
		if err != nil {
			log.Error().Msg(err.Error())
		}
		Strict = viper.GetBool("strict")
		// by default we don't print the list of active features, at least not for now...
	})
	// persistent flags are global for the application
	rootCmd.PersistentFlags().StringVar(&UserProvidedPath, "config", "", "Set config file path (default $HOME/.config/mondoo/mondoo.yml)")

	// We need to parse the flags really early in the process, so that
	// the config path is set before we initialize viper. This is because
	// the providers configuration needs to be available before the rootCmd
	// is executed as it does things like tries to download a provider if its missing
	// See AttachCLIs in cli/providers/providers.go
	flags := pflag.NewFlagSet("set", pflag.ContinueOnError)
	flags.ParseErrorsAllowlist.UnknownFlags = true
	flags.StringVar(&UserProvidedPath, "config", "", "")
	flags.BoolP("help", "h", false, "")
	if err := flags.Parse(os.Args); err != nil {
		log.Debug().Err(err).Msg("could not parse flags")
	}
}

func InitViperConfig() {
	viper.SetConfigType("yaml")
	// Effectively, we disable using a key delimiter in viper. So you cannot do something like
	// annotations.foo = "bar"
	// You can only do
	// annotations = {"foo": "bar"}
	viper.SetOptions(viper.KeyDelimiter("\\"))

	Path = strings.TrimSpace(UserProvidedPath)
	// base 64 config env setting has always precedence
	if len(os.Getenv("MONDOO_CONFIG_BASE64")) > 0 {
		Source = configSourceBase64
		decodedData, err := base64.StdEncoding.DecodeString(os.Getenv("MONDOO_CONFIG_BASE64"))
		if err != nil {
			log.Fatal().Err(err).Msg("could not parse base64 ")
		}
		err = viper.ReadConfig(bytes.NewBuffer(decodedData))
		if err != nil {
			log.Fatal().Err(err).Msg("")
		}
	} else if len(Path) == 0 && len(os.Getenv("MONDOO_CONFIG_PATH")) > 0 {
		// fallback to env variable if provided, but only if --config is not used
		Source = "$MONDOO_CONFIG_PATH"
		Path = os.Getenv("MONDOO_CONFIG_PATH")
	} else if len(Path) != 0 {
		Source = "--config"
	} else {
		Source = "default"
	}
	if strings.HasPrefix(Path, AWS_SSM_PARAMETERSTORE_PREFIX) {
		err := loadAwsSSMParameterStore(Path)
		if err != nil {
			LoadedConfig = false
			log.Error().Err(err).Str("path", Path).Msg("could not load aws parameter store config")
		} else {
			LoadedConfig = true
		}
	}

	// check if the default config file is available
	if Path == "" && Source != configSourceBase64 {
		Path = autodetectConfig()
	}

	if Source != configSourceBase64 {
		// we set this here, so that sub commands that rely on writing config, can use the default config
		viper.SetConfigFile(Path)

		// if the file exists, load it
		_, err := AppFs.Stat(Path)
		if err == nil {
			log.Debug().Str("configfile", viper.ConfigFileUsed()).Msg("try to load local config file")
			if err := viper.ReadInConfig(); err == nil {
				LoadedConfig = true
			} else {
				LoadedConfig = false
				log.Error().Err(err).Str("path", Path).Msg("could not read config file")
			}
		}
	}

	// by default it uses console output, for production we may want to set it to json output
	if viper.GetString("log.format") == "json" {
		logger.UseJSONLogging(logger.LogOutputWriter)
	}

	if viper.GetBool("log.color") {
		logger.CliCompactLogger(logger.LogOutputWriter)
	}

	// override values with env variables
	viper.SetEnvPrefix("mondoo")
	// to parse env variables properly we need to replace some chars
	// all hyphens need to be underscores
	// all dots neeto to be underscores
	replacer := strings.NewReplacer("-", "_", ".", "_")
	viper.SetEnvKeyReplacer(replacer)

	// read in environment variables that match
	viper.AutomaticEnv()

	// Check if this is a WIF config file
	if viper.GetString("type") == "external_account" {
		log.Debug().Msg("detected WIF config format")

		// Configure authentication method
		if !viper.IsSet("auth") {
			viper.Set("auth", map[string]string{"method": AUTH_METHOD_WIF})
		} else {
			// If auth exists but method isn't set, set it to wif
			authMap := viper.GetStringMap("auth")
			if _, exists := authMap["method"]; !exists {
				viper.Set("auth.method", AUTH_METHOD_WIF)
			}
		}

		// Set the API endpoint from universeDomain if available
		if universeDomain := viper.GetString("universeDomain"); universeDomain != "" {
			viper.Set("api_endpoint", universeDomain)
		}

		// Log the detected configuration
		log.Debug().
			Str("audience", viper.GetString("audience")).
			Str("issuerUri", viper.GetString("issuerUri")).
			Str("universeDomain", viper.GetString("universeDomain")).
			Msg("configured WIF authentication from config file")
	}
}

func DisplayUsedConfig() {
	// print config file
	if !LoadedConfig && len(UserProvidedPath) > 0 {
		log.Warn().Msg("could not load configuration file " + UserProvidedPath)
	} else if LoadedConfig {
		log.Info().Msg("loaded configuration from " + viper.ConfigFileUsed() + " using source " + Source)
	} else if Source == configSourceBase64 {
		log.Info().Msg("loaded configuration from environment using source " + Source)
	} else {
		// Running without a config file is a normal, common case (e.g. `mql
		// status` with no credentials), so this is debug-only noise rather than
		// something worth printing on every run.
		log.Debug().Msg("no Mondoo configuration file provided, using defaults")
	}
}

// GetAutoUpdate returns the auto_update setting from viper config.
// Returns true (enabled) by default if not explicitly set.
func GetAutoUpdate() bool {
	if viper.IsSet("auto_update") {
		return viper.GetBool("auto_update")
	}
	return true
}

// GetUpdatesURL returns the updates_url setting from viper config.
// Returns empty string if not set (caller should use default).
func GetUpdatesURL() string {
	return viper.GetString("updates_url")
}

// KeyProviderPortRange is the config key for the loopback TCP port range that
// provider subprocesses may listen on, written as "min-max" (for example
// "50000-50100"). It comes from mondoo.yml or, through viper's env binding,
// from MONDOO_PROVIDER_PORT_RANGE. Unset means an OS-assigned port. Only
// Windows uses TCP for the provider transport; other platforms talk to
// providers over Unix sockets and ignore it.
const KeyProviderPortRange = "provider_port_range"

// GetProviderPortRange returns the provider_port_range setting, or an empty
// string when unset. Parsing and the default live with the providers package,
// which is the one that hands the range to the plugin runtime.
func GetProviderPortRange() string {
	return viper.GetString(KeyProviderPortRange)
}

// KeyUpdateChannel is the config key selecting which release track binary
// updates and providers resolve through. It comes from mondoo.yml or, through
// viper's env binding, from MONDOO_UPDATE_CHANNEL.
//
// The key is flat rather than nested under `update` or `providers` because
// InitViperConfig disables viper's key delimiter, so a dotted lookup of a
// nested key silently returns nothing.
const KeyUpdateChannel = "update_channel"

// Release channels. The channel a version belongs to is decided by the release
// service, from the version's semver pre-release segment; the client only picks
// which track to ask for.
const (
	// ChannelStable is the default: the newest release with no pre-release
	// segment.
	ChannelStable = "stable"
	// ChannelPreview is the pre-release track: the newest release overall,
	// release candidates included. It is never older than stable, so a client
	// tracking it moves forward when a candidate becomes a final release.
	ChannelPreview = "preview"
)

// runningVersion is the version of the binary that is executing, set once at
// startup by the app. Empty means unknown, which reads as stable.
//
// It is injected rather than read from a package variable because the binary
// that matters is cnspec or mql, and this package is shared by both.
//
// atomic.Value rather than a plain string: the write happens once at startup
// and the reads come later, so there is no race today, but nothing in the types
// says so. Tests in particular are free to run in parallel.
var runningVersion atomic.Value // string

// SetRunningVersion records the executing binary's version, so an unset
// update_channel can follow the build rather than defaulting to stable. Call it
// before anything resolves a channel.
func SetRunningVersion(version string) {
	runningVersion.Store(version)
}

// getRunningVersion returns the recorded version, or "" if none was set.
func getRunningVersion() string {
	version, _ := runningVersion.Load().(string)
	return version
}

// GetUpdateChannel returns the release channel this binary resolves through.
//
// An explicit update_channel wins. Anything else -- unset, or a value we do not
// recognize -- follows the running build: a pre-release build resolves the
// pre-release track, everything else resolves stable.
//
// Following the build matters because installing a pre-release and then
// resolving *stable* providers is the v13/v14 mismatch in miniature. A
// 14.0.0-rc.2 binary would pull 13.x providers, built against a different
// schema, and report the resulting nulls as passing checks. Someone who
// installed a release candidate has already chosen the pre-release track;
// making them say so twice only creates a way to get it half-applied.
//
// An unrecognized value is treated as unset rather than forced to stable. It
// means "we do not know what you asked for", and the honest answer to that is
// the default behaviour, not a third one. Forcing stable would have produced
// exactly the schema mismatch above for anyone who typed `beta` meaning
// `preview` on a release candidate.
//
// A stable build still never derives preview, which is what keeps this safe: no
// released binary can be moved onto pre-releases by a typo, only by asking for
// it precisely.
func GetUpdateChannel() string {
	configured := strings.ToLower(strings.TrimSpace(viper.GetString(KeyUpdateChannel)))

	switch configured {
	case ChannelPreview:
		return ChannelPreview
	case ChannelStable:
		return ChannelStable
	case "":
	default:
		log.Warn().
			Str("configured", configured).
			Str(KeyUpdateChannel, strings.Join([]string{ChannelStable, ChannelPreview}, ", ")).
			Msg("unknown update channel, falling back to the channel this build belongs to")
	}

	if isPrereleaseVersion(getRunningVersion()) {
		return ChannelPreview
	}
	return ChannelStable
}

// isPrereleaseVersion reports whether a version carries a semver pre-release
// segment. Build metadata is stripped first: it is not a pre-release under
// SemVer 10, and it is where the edge builds put their commit counter.
//
// Deliberately not a full semver parse. This has to answer for "unstable" and
// for the `-rolling` suffix as well as for real versions, and a parse error on
// a development build must not decide a channel.
func isPrereleaseVersion(version string) bool {
	core, _, _ := strings.Cut(version, "+")
	_, prerelease, found := strings.Cut(strings.TrimPrefix(core, "v"), "-")
	return found && prerelease != ""
}

// GetFeatures returns the features from viper config.
// This can be called after InitViperConfig() to get features before cobra initialization.
func GetFeatures() mql.Features {
	features, _ := mql.InitFeatures(viper.GetStringSlice("features")...)
	return features
}

func Read() (*Config, error) {
	// load viper config into a struct
	var opts Config
	err := viper.Unmarshal(&opts)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode into config struct")
	}

	return &opts, nil
}

// configToMap encodes a Config struct into a flat map, respecting mapstructure tags.
func configToMap(cfg *Config) (map[string]any, error) {
	m := make(map[string]any)
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "mapstructure",
		Result:  &m,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create config encoder")
	}
	if err := dec.Decode(cfg); err != nil {
		return nil, errors.Wrap(err, "failed to encode config")
	}
	return m, nil
}

// ApplyConfig sets all values from the given Config into viper,
// allowing programmatic configuration without a config file.
func ApplyConfig(cfg *Config) error {
	m, err := configToMap(cfg)
	if err != nil {
		return err
	}
	return viper.MergeConfigMap(m)
}

type Config struct {
	// inherit common config
	CommonOpts `mapstructure:",squash"`

	// Asset Category
	Category               string `json:"category,omitempty" mapstructure:"category"`
	AutoDetectCICDCategory bool   `json:"detect-cicd,omitempty" mapstructure:"detect-cicd"`
}

type CommonOpts struct {
	// client identifier
	AgentMrn string `json:"agent_mrn,omitempty" mapstructure:"agent_mrn"`

	// service account credentials
	ServiceAccountMrn string `json:"mrn,omitempty" mapstructure:"mrn"`
	// The scope mrn is used to scope the service account to a specific organization or space.
	ScopeMrn string `json:"scope_mrn,omitempty" mapstructure:"scope_mrn"`
	// Deprecated: use scope_mrn instead
	ParentMrn string `json:"parent_mrn,omitempty" mapstructure:"parent_mrn"`
	// Deprecated: use scope_mrn instead
	SpaceMrn    string `json:"space_mrn,omitempty" mapstructure:"space_mrn"`
	PrivateKey  string `json:"private_key,omitempty" mapstructure:"private_key"`
	Certificate string `json:"certificate,omitempty" mapstructure:"certificate"`
	Token       string `json:"token,omitempty" mapstructure:"token"`
	APIEndpoint string `json:"api_endpoint,omitempty" mapstructure:"api_endpoint"`

	// Workload Identity Federation
	WIF `mapstructure:",squash"`

	// authentication
	Authentication *CliConfigAuthentication `json:"auth,omitempty" mapstructure:"auth"`

	// client features
	Features []string `json:"features,omitempty" mapstructure:"features"`

	// Strict turns on ADR 043 strict mode for MQL compiled by this client: every
	// link in an access chain must resolve, and `?` marks one optional.
	//
	// Deliberately a *bool and deliberately not a feature flag. Strictness is a
	// property of the content, so a policy states its own mode and this is only
	// the default for surfaces that carry no content of their own - the shell,
	// `mql run`, embeddings. A tri-state is what lets "unset, fall back to the
	// default" stay distinguishable from "explicitly non-strict", which a
	// two-state feature flag cannot express.
	Strict *bool `json:"strict,omitempty" mapstructure:"strict"`

	// API Proxy for communicating with Mondoo Platform API
	APIProxy string `json:"api_proxy,omitempty" mapstructure:"api_proxy"`

	// labels that will be applied to all assets
	Labels map[string]string `json:"labels,omitempty" mapstructure:"labels"`

	// annotations that will be applied to all assets
	Annotations map[string]string `json:"annotations,omitempty" mapstructure:"annotations"`

	// UpdatesURL is the base URL where updates are fetched from
	// if not set, the default Mondoo releases URL is used (https://releases.mondoo.com)
	// This can be a custom URL for an internal release registry
	// Providers are fetched from UpdatesURL + "/providers"
	UpdatesURL string `json:"updates_url,omitempty" mapstructure:"updates_url"`

	// ProviderPortRange is the loopback TCP port range ("min-max") that provider
	// subprocesses may listen on. Only Windows uses TCP for the provider
	// transport, so the setting has no effect elsewhere. Unset means an
	// OS-assigned port. See KeyProviderPortRange.
	ProviderPortRange string `json:"provider_port_range,omitempty" mapstructure:"provider_port_range"`

	// UpdateChannel selects which release track binary updates and providers
	// resolve through. Unset means "stable". See KeyUpdateChannel.
	UpdateChannel string `json:"update_channel,omitempty" mapstructure:"update_channel"`
}

// Workload Identity Federation
type WIF struct {
	Audience         string   `json:"audience,omitempty" mapstructure:"audience"`
	IssuerURI        string   `json:"issuerUri,omitempty" mapstructure:"issuerUri"`
	JWTToken         string   `json:"jwtToken,omitempty" mapstructure:"jwtToken"`
	UniverseDomain   string   `json:"universeDomain,omitempty" mapstructure:"universeDomain"`
	Scopes           []string `json:"scopes,omitempty" mapstructure:"scopes"`
	Type             string   `json:"type,omitempty" mapstructure:"type"`
	SubjectTokenType string   `json:"subjectTokenType,omitempty" mapstructure:"subjectTokenType"`
}

type CliConfigAuthentication struct {
	Method string `json:"method,omitempty" mapstructure:"method"`
}

// GetStrict reports the configured default for strict mode. Unset means
// non-strict, which is the v14 default; content that wants strictness says so
// itself rather than relying on this.
func (c *CommonOpts) GetStrict() bool {
	return c.Strict != nil && *c.Strict
}

func (c *CommonOpts) GetFeatures() mql.Features {
	bitSet := make([]bool, 256)
	flags := []byte{}

	for _, f := range mql.DefaultFeatures {
		if !bitSet[f] {
			bitSet[f] = true
			flags = append(flags, f)
		}
	}

	for _, name := range c.Features {
		flag, ok := mql.FeaturesValue[name]
		if ok {
			if !bitSet[byte(flag)] {
				bitSet[byte(flag)] = true
				flags = append(flags, byte(flag))
			}
		} else {
			log.Warn().Str("feature", name).Msg("could not get a feature")
		}
	}

	return flags
}

// GetServiceCredential returns the service credential that is defined in the config.
// If no service credential is defined, it will return nil.
func (c *CommonOpts) GetServiceCredential() *upstream.ServiceAccountCredentials {
	// If we have an authentication method defined, use it
	if c.Authentication != nil {
		switch c.Authentication.Method {
		case AUTH_METHOD_SSH:
			log.Info().Msg("using ssh authentication method, generate temporary credentials")
			serviceAccount, err := upstream.ExchangeSSHKey(c.UpstreamApiEndpoint(), c.ServiceAccountMrn, c.GetParentMrn())
			if err != nil {
				log.Error().Err(err).Msg("could not exchange ssh key")
				return nil
			}
			return serviceAccount
		case AUTH_METHOD_WIF:
			log.Info().Msg("using wif authentication method, generate temporary credentials")

			tokenResponse := c.GetFeatures().IsActive(mql.ExchangeTokenForToken)
			serviceAccount, err := upstream.ExchangeExternalToken(c.UpstreamApiEndpoint(), c.Audience, c.IssuerURI, c.JWTToken, tokenResponse)
			if err != nil {
				log.Error().Err(err).Msg("could not exchange external (wif) token")
				return nil
			}

			return serviceAccount
		}
	}

	// return nil when no service account is defined
	if c.ServiceAccountMrn == "" && c.PrivateKey == "" && c.Certificate == "" {
		return nil
	}

	return &upstream.ServiceAccountCredentials{
		Mrn:         c.ServiceAccountMrn,
		ParentMrn:   c.GetScopeMrn(),
		ScopeMrn:    c.GetScopeMrn(),
		PrivateKey:  c.PrivateKey,
		Certificate: c.Certificate,
		Token:       c.Token,
		ApiEndpoint: c.APIEndpoint,
	}
}

// GetScopeMrn returns the scope mrn that is used for the service account.
// This is either the organization mrn or the space mrn.
func (c *CommonOpts) GetScopeMrn() string {
	scopeMrn := c.ScopeMrn

	// fallback to old space_mrn config
	if scopeMrn == "" {
		scopeMrn = c.SpaceMrn
	}

	if scopeMrn == "" {
		scopeMrn = c.ParentMrn
	}

	return scopeMrn
}

// GetParentMrn returns the scope mrn that is used for the service account.
// This is either the organization mrn or the space mrn.
// Deprecated: Use GetScopeMrn instead
func (c *CommonOpts) GetParentMrn() string {
	return c.GetScopeMrn()
}

func (c *CommonOpts) UpstreamApiEndpoint() string {
	apiEndpoint := c.APIEndpoint

	// fallback to default api if nothing was set
	if apiEndpoint == "" {
		apiEndpoint = defaultAPIendpoint
	}

	return apiEndpoint
}
