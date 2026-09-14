// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package ollama resolves the configuration an Ollama server on a host runs
// with. Ollama has no configuration file: every setting is an environment
// variable read at daemon start, so the configuration has to be reconstructed
// from wherever the daemon's environment is declared. The resolution mirrors
// Ollama's own envconfig package, including its defaults, so a setting left
// unset reports the value the server would actually use rather than an empty
// string.
package ollama

import (
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UnitName is the systemd unit the packaged server runs under.
const UnitName = "ollama.service"

// DefaultPort is the port Ollama binds when OLLAMA_HOST names none.
const DefaultPort = 11434

// Infinite is reported for a duration Ollama treats as unbounded. Ollama models
// this internally as the maximum int64 nanoseconds; -1 says the same thing
// without a number that reads as 292 years.
const Infinite = -1

// Config is the effective configuration of an Ollama server, resolved from the
// environment its process is given plus the files that can override it.
type Config struct {
	// Vars are the OLLAMA_* and proxy variables as declared, before defaults.
	// A variable absent here is one the daemon was never given.
	Vars map[string]string
	// Sources maps a declared variable to the file it was read from.
	Sources map[string]string
	// Files are every file that contributed, in the order they were applied.
	Files []string

	// Host is the address the server binds, as a URL.
	Host string
	// BindAddress and Port are Host split into its parts.
	BindAddress string
	Port        int64
	// ListensOnAllInterfaces is true when the bind address is unspecified
	// (0.0.0.0 or ::), which is how an instance ends up reachable off-box.
	ListensOnAllInterfaces bool
	// TLS is true when the server is addressed over https.
	TLS bool

	// Origins are the browser origins named by OLLAMA_ORIGINS, empty when unset.
	Origins []string
	// AllowsAnyOrigin is true when OLLAMA_ORIGINS contains a bare wildcard.
	AllowsAnyOrigin bool

	// AuthEnabled reports OLLAMA_AUTH.
	AuthEnabled bool

	// CloudEnabled is false when cloud inference and web search are turned off,
	// by OLLAMA_NO_CLOUD or by server.json.
	CloudEnabled bool
	// CloudDisabledSource is "none", "env", "config", or "both", mirroring
	// Ollama's own NoCloudSource().
	CloudDisabledSource string
	// Remotes are the hosts remote models may be served from.
	Remotes []string

	// ModelsPath is the resolved model store.
	ModelsPath string

	// DebugLogRequests reports OLLAMA_DEBUG_LOG_REQUESTS, which writes inference
	// request bodies to a temporary directory.
	DebugLogRequests bool
	// LogLevel is "info", "debug", or "trace".
	LogLevel string
	// HistoryEnabled is false when OLLAMA_NOHISTORY suppresses the prompt history.
	HistoryEnabled bool
	// NoPrune reports OLLAMA_NOPRUNE.
	NoPrune bool

	KeepAliveSeconds   int64
	LoadTimeoutSeconds int64
	ContextLength      int64
	NumParallel        int64
	MaxLoadedModels    int64
	MaxQueue           int64
	GpuOverhead        int64
	FlashAttention     bool
	SchedSpread        bool
	KvCacheType        string
	LlmLibrary         string

	HTTPProxy  string
	HTTPSProxy string
	NoProxy    string
}

// ServerSettings are the fields read from ~/.ollama/server.json, the one file
// that carries a setting the environment cannot express on its own.
type ServerSettings struct {
	DisableOllamaCloud bool `json:"disable_ollama_cloud"`
}

// Resolve turns a declared environment into the configuration the server runs
// with. home is the home directory of the account the daemon runs as, used only
// for the default model store. settings may be nil when no server.json exists.
func Resolve(vars map[string]string, home string, settings *ServerSettings) *Config {
	if vars == nil {
		vars = map[string]string{}
	}

	c := &Config{
		Vars:    vars,
		Sources: map[string]string{},
	}

	c.Host, c.BindAddress, c.Port, c.TLS = resolveHost(get(vars, "OLLAMA_HOST"))
	if ip := net.ParseIP(c.BindAddress); ip != nil {
		c.ListensOnAllInterfaces = ip.IsUnspecified()
	}

	if s := get(vars, "OLLAMA_ORIGINS"); s != "" {
		for _, o := range strings.Split(s, ",") {
			o = strings.TrimSpace(o)
			if o == "" {
				continue
			}
			c.Origins = append(c.Origins, o)
			if o == "*" {
				// Ollama enables gin's wildcard matching, so a bare "*" matches
				// every origin rather than being taken literally.
				c.AllowsAnyOrigin = true
			}
		}
	}

	c.AuthEnabled = boolVar(vars, "OLLAMA_AUTH", false)

	envNoCloud := boolVar(vars, "OLLAMA_NO_CLOUD", false)
	fileNoCloud := settings != nil && settings.DisableOllamaCloud
	c.CloudEnabled = !envNoCloud && !fileNoCloud
	switch {
	case envNoCloud && fileNoCloud:
		c.CloudDisabledSource = "both"
	case envNoCloud:
		c.CloudDisabledSource = "env"
	case fileNoCloud:
		c.CloudDisabledSource = "config"
	default:
		c.CloudDisabledSource = "none"
	}

	if s := get(vars, "OLLAMA_REMOTES"); s != "" {
		for _, r := range strings.Split(s, ",") {
			if r = strings.TrimSpace(r); r != "" {
				c.Remotes = append(c.Remotes, r)
			}
		}
	}
	if len(c.Remotes) == 0 {
		c.Remotes = []string{"ollama.com"}
	}

	c.ModelsPath = ModelsPath(vars, home)

	c.DebugLogRequests = boolVar(vars, "OLLAMA_DEBUG_LOG_REQUESTS", false)
	c.LogLevel = resolveLogLevel(get(vars, "OLLAMA_DEBUG"))
	c.HistoryEnabled = !boolVar(vars, "OLLAMA_NOHISTORY", false)
	c.NoPrune = boolVar(vars, "OLLAMA_NOPRUNE", false)

	// Negative keeps a model resident forever; zero unloads it immediately, so
	// zero is a real value here and only a negative one means unbounded.
	c.KeepAliveSeconds = durationVar(vars, "OLLAMA_KEEP_ALIVE", 5*time.Minute, false)
	// A load timeout of zero is documented as unbounded rather than instant.
	c.LoadTimeoutSeconds = durationVar(vars, "OLLAMA_LOAD_TIMEOUT", 5*time.Minute, true)

	c.ContextLength = uintVar(vars, "OLLAMA_CONTEXT_LENGTH", 0)
	c.NumParallel = uintVar(vars, "OLLAMA_NUM_PARALLEL", 1)
	c.MaxLoadedModels = uintVar(vars, "OLLAMA_MAX_LOADED_MODELS", 0)
	c.MaxQueue = uintVar(vars, "OLLAMA_MAX_QUEUE", 512)
	c.GpuOverhead = uintVar(vars, "OLLAMA_GPU_OVERHEAD", 0)
	c.FlashAttention = boolVar(vars, "OLLAMA_FLASH_ATTENTION", false)
	c.SchedSpread = boolVar(vars, "OLLAMA_SCHED_SPREAD", false)
	c.KvCacheType = get(vars, "OLLAMA_KV_CACHE_TYPE")
	c.LlmLibrary = get(vars, "OLLAMA_LLM_LIBRARY")

	c.HTTPProxy = firstOf(vars, "HTTP_PROXY", "http_proxy")
	c.HTTPSProxy = firstOf(vars, "HTTPS_PROXY", "https_proxy")
	c.NoProxy = firstOf(vars, "NO_PROXY", "no_proxy")

	return c
}

// ModelsPath resolves the model store: OLLAMA_MODELS when set, otherwise
// $HOME/.ollama/models for the account the daemon runs as. It is exported
// separately because the model-cache detector needs it without the rest of the
// configuration.
func ModelsPath(vars map[string]string, home string) string {
	if s := get(vars, "OLLAMA_MODELS"); s != "" {
		return s
	}
	if home == "" {
		return ""
	}
	return strings.TrimRight(home, "/") + "/.ollama/models"
}

// resolveHost mirrors envconfig.Host(). The shape matters: OLLAMA_HOST is
// accepted with or without a scheme, with or without a port, and an address it
// cannot make sense of falls back to the loopback default rather than failing,
// so an unparseable value must not be reported as an exposed one.
func resolveHost(s string) (rawURL string, host string, port int64, tls bool) {
	defaultPort := strconv.Itoa(DefaultPort)

	s = strings.TrimSpace(s)
	scheme, hostport, ok := strings.Cut(s, "://")
	switch {
	case !ok:
		scheme, hostport = "http", s
		if s == "ollama.com" {
			scheme, hostport = "https", "ollama.com:443"
		}
	case scheme == "http":
		defaultPort = "80"
	case scheme == "https":
		defaultPort = "443"
	}

	hostport, path, _ := strings.Cut(hostport, "/")
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		h, p = "127.0.0.1", defaultPort
		if ip := net.ParseIP(strings.Trim(hostport, "[]")); ip != nil {
			h = ip.String()
		} else if hostport != "" {
			h = hostport
		}
	}

	n, err := strconv.ParseInt(p, 10, 32)
	if err != nil || n > 65535 || n < 0 {
		p = defaultPort
		n, _ = strconv.ParseInt(defaultPort, 10, 32)
	}

	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(h, p), Path: path}
	return u.String(), h, n, scheme == "https"
}

// resolveLogLevel mirrors envconfig.LogLevel(): OLLAMA_DEBUG is a boolean or a
// verbosity number, where each step maps to one slog level.
func resolveLogLevel(s string) string {
	if s == "" {
		return "info"
	}
	if b, err := strconv.ParseBool(s); err == nil {
		if b {
			return "debug"
		}
		return "info"
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil || i == 0 {
		return "info"
	}
	if i >= 2 {
		return "trace"
	}
	return "debug"
}

// get reads a variable the way Ollama does, stripping the quotes and surrounding
// whitespace that survive being carried through a unit file.
func get(vars map[string]string, key string) string {
	return strings.Trim(strings.TrimSpace(vars[key]), "\"'")
}

func firstOf(vars map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := get(vars, k); v != "" {
			return v
		}
	}
	return ""
}

// boolVar mirrors envconfig.BoolWithDefault, including its treatment of a value
// it cannot parse as true. That is Ollama's behavior, not a lenient reading:
// OLLAMA_FLASH_ATTENTION=yes turns the feature on.
func boolVar(vars map[string]string, key string, def bool) bool {
	s := get(vars, key)
	if s == "" {
		return def
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return true
	}
	return b
}

// uintVar mirrors envconfig.Uint: a value that is not a non-negative integer
// falls back to the default rather than to zero.
func uintVar(vars map[string]string, key string, def int64) int64 {
	s := get(vars, key)
	if s == "" {
		return def
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return def
	}
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}

// durationVar mirrors envconfig.KeepAlive and LoadTimeout: a Go duration or a
// bare number of seconds, defaulting when neither parses. zeroIsInfinite selects
// between the two settings' differing treatment of zero.
func durationVar(vars map[string]string, key string, def time.Duration, zeroIsInfinite bool) int64 {
	d := def
	if s := get(vars, key); s != "" {
		if parsed, err := time.ParseDuration(s); err == nil {
			d = parsed
		} else if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			d = time.Duration(n) * time.Second
		}
	}

	if d < 0 || (zeroIsInfinite && d == 0) {
		return Infinite
	}
	return int64(d / time.Second)
}

// credentialish are the name fragments that mark a variable as carrying a
// secret. None of Ollama's own settings match any of them, so this only ever
// excludes something a unit carries for another purpose.
var credentialish = []string{"TOKEN", "SECRET", "PASSWORD", "APIKEY", "CREDENTIAL"}

// gpuVisibilityVars are the device-selection variables Ollama reads from the
// wider environment rather than defining itself.
var gpuVisibilityVars = map[string]struct{}{
	"CUDA_VISIBLE_DEVICES":     {},
	"HIP_VISIBLE_DEVICES":      {},
	"ROCR_VISIBLE_DEVICES":     {},
	"GGML_VK_VISIBLE_DEVICES":  {},
	"GPU_DEVICE_ORDINAL":       {},
	"HSA_OVERRIDE_GFX_VERSION": {},
}

// proxyVars are the proxy settings Ollama reports as part of its own
// configuration, in both the spellings it accepts.
var proxyVars = map[string]struct{}{
	"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "NO_PROXY": {},
	"http_proxy": {}, "https_proxy": {}, "no_proxy": {},
}

// IsConfigVar reports whether a variable is part of Ollama's configuration and
// safe to report. A unit's environment is a common place to keep credentials
// for unrelated purposes, and this resource describes how Ollama is configured
// rather than everything the unit happens to carry, so anything outside the
// settings Ollama reads is left out, and so is anything credential-shaped.
//
// TODO: this is a deliberate reduction, not the intended end state. The full
// declared environment is worth reporting: a variable Ollama ignores can still
// explain the daemon's behavior, and a misspelled setting is invisible while
// only the recognized names are shown. It is withheld because MQL has no way to
// mark a field as carrying a secret, so a token parked in the unit would travel
// into every report that reads this resource, with nothing downstream able to
// tell it apart from a bind address. Once fields can be flagged as sensitive
// and handled accordingly, collect the whole environment and let the flagging
// decide what is rendered, rather than deciding it here by name. Until then a
// name-shaped guess is the only filter available, and under-reporting is the
// safe direction to be wrong in.
func IsConfigVar(name string) bool {
	upper := strings.ToUpper(name)
	for _, frag := range credentialish {
		if strings.Contains(upper, frag) {
			return false
		}
	}
	if strings.HasSuffix(upper, "_KEY") {
		return false
	}

	if _, ok := gpuVisibilityVars[name]; ok {
		return true
	}
	if _, ok := proxyVars[name]; ok {
		return true
	}
	// HOME decides where the default model store and server.json sit, so it is
	// part of how the server is configured.
	return name == "HOME" ||
		strings.HasPrefix(name, "OLLAMA_") ||
		strings.HasPrefix(name, "LLAMA_ARG_")
}

// ConfigVars filters a declared environment down to the variables IsConfigVar
// accepts, leaving the map it is given untouched.
func ConfigVars(vars map[string]string) map[string]string {
	out := make(map[string]string, len(vars))
	for k, v := range vars {
		if IsConfigVar(k) {
			out[k] = v
		}
	}
	return out
}
