// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/v13"
	"go.mondoo.com/mql/v13/logger"
	"go.mondoo.com/mql/v13/providers-sdk/v1/upstream"
)

/*
	Configuration is loaded in this order:
	ENV -> ~/.mondoo.conf -> defaults
*/

// Path is the currently loaded config location
// or default if no config exits
var (
	Features mql.Features
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
		log.Info().Msg("no Mondoo configuration file provided, using defaults")
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

// GetProvidersURL returns the providers_url setting from viper config.
// Returns empty string if not set (caller should use default).
func GetProvidersURL() string {
	return viper.GetString("providers_url")
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

	// API Proxy for communicating with Mondoo Platform API
	APIProxy string `json:"api_proxy,omitempty" mapstructure:"api_proxy"`

	// labels that will be applied to all assets
	Labels map[string]string `json:"labels,omitempty" mapstructure:"labels"`

	// annotations that will be applied to all assets
	Annotations map[string]string `json:"annotations,omitempty" mapstructure:"annotations"`

	// UpdatesURL is the base URL where updates are fetched from
	// if not set, the default Mondoo releases URL is used (https://releases.mondoo.com)
	// This can be a custom URL for an internal release registry
	// If ProvidersURL is not set, providers will be fetched from UpdatesURL + "/providers"
	UpdatesURL string `json:"updates_url,omitempty" mapstructure:"updates_url"`

	// ProvidersURL is the URL where providers are downloaded from
	// if not set, the default Mondoo provider URL is used
	// This can be a custom URL for an internal provider registry
	// Deprecated: use UpdatesURL instead
	ProvidersURL string `json:"providers_url,omitempty" mapstructure:"providers_url"`
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

			serviceAccount, err := upstream.ExchangeExternalToken(c.UpstreamApiEndpoint(), c.Audience, c.IssuerURI, c.JWTToken)
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
