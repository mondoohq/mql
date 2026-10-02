// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package mongodb contains the parser for MongoDB's on-disk configuration
// file, mongod.conf. The parser operates on already-read file content so it
// doesn't depend on a particular filesystem implementation, which lets it be
// unit-tested against inlined fixtures and re-used over different transports
// (local, SSH, container snapshot, ...).
//
// Unlike the option files of MySQL and PostgreSQL, mongod.conf is a nested
// YAML document (or, on old distribution packages, a flat legacy file that is
// translated into the same tree) and has no include mechanism, so a parse reads exactly one
// file and the result is a tree rather than a flat key/value map. Lookups
// therefore address a value by its key path ("net", "tls", "mode"). Reading
// that tree is shared with the other YAML-shaped server configs and lives in
// the yamlconf package; what stays here is the part specific to mongod,
// namely the pre-4.2 net.ssl aliasing and the version banner.
package mongodb

import (
	"regexp"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/yamlconf"
	"gopkg.in/yaml.v3"
)

// Conf is the result of parsing a mongod.conf.
type Conf struct {
	// Params is the configuration tree, normalized so every value is
	// JSON-native (bool, int64, float64, string, []any, map[string]any, or
	// nil). Normalization is mandatory rather than cosmetic: llx rejects a
	// dict holding any other Go type at query time, and a plain YAML decode
	// yields `int` and `time.Time` values that would trip that check.
	Params map[string]any
}

// ParseConf parses the content of a mongod.conf.
//
// An empty file is not an error: mongod accepts one and runs entirely on its
// built-in defaults, so it parses to an empty tree and every accessor reports
// the default it would have used.
//
// A file in the legacy `name = value` format (see parseLegacy) is translated
// into the same tree.
func ParseConf(content string) (*Conf, error) {
	if isLegacyConf(content) {
		params, err := parseLegacy(content)
		if err != nil {
			return nil, err
		}
		return &Conf{Params: params}, nil
	}
	params, err := yamlconf.Parse(content, "mongod.conf")
	if err != nil {
		return nil, err
	}
	return &Conf{Params: params}, nil
}

// isLegacyConf reports whether mongod would read content in the legacy
// format, which it does when the YAML parser reads the whole file as one
// scalar. A YAML mapping, an empty file, and a file YAML cannot parse at all
// are not legacy files.
func isLegacyConf(content string) bool {
	var root any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return false
	}
	switch root.(type) {
	case nil, map[string]any, []any:
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// lookups
// ---------------------------------------------------------------------------

// Lookup walks the key path and reports the value at it. The second return
// distinguishes an unset key from a key explicitly set to null, which matters
// because the accessors fall back to mongod's own default only for the former.
func Lookup(params map[string]any, path ...string) (any, bool) {
	return yamlconf.Lookup(params, path...)
}

// String reports the value at path as a string, empty when unset.
func String(params map[string]any, path ...string) string {
	return yamlconf.String(params, path...)
}

// Bool reports the value at path, falling back to def when the key is unset.
//
// The caller supplies the default rather than the function assuming false,
// because mongod defaults several security-relevant settings to true
// (security.javascriptEnabled, setParameter.enableLocalhostAuthBypass). A
// hardcoded false fallback would report an unhardened host as hardened.
func Bool(params map[string]any, def bool, path ...string) bool {
	return yamlconf.Bool(params, def, path...)
}

// Int reports the value at path, falling back to def when the key is unset or
// holds something that is not a whole number.
func Int(params map[string]any, def int64, path ...string) int64 {
	return yamlconf.Int(params, def, path...)
}

// List reports the value at path as a list of strings.
//
// It accepts both spellings mongod does. Settings such as net.bindIp and
// net.tls.disabledProtocols are documented as a single comma-delimited
// string, but a YAML sequence is common in the wild and mongod reads it, so
// treating only the documented form would drop every entry on those hosts.
func List(params map[string]any, path ...string) []string {
	return yamlconf.List(params, path...)
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

// tlsLegacyKeys maps a net.tls key to its net.ssl spelling for the two
// settings MongoDB renamed rather than moved when it introduced net.tls in
// 4.2. Every other key kept its name under the new parent.
var tlsLegacyKeys = map[string]string{
	"certificateKeyFile":         "PEMKeyFile",
	"certificateKeyFilePassword": "PEMKeyPassword",
}

// tlsPaths returns the key paths to try for a net.tls setting, newest first.
//
// mongod still accepts the pre-4.2 net.ssl tree as an alias, and plenty of
// deployed configs use it, so reading only net.tls would report TLS as
// unconfigured on a host that has it configured the old way.
func tlsPaths(key string) [][]string {
	paths := [][]string{{"net", "tls", key}}
	legacy := key
	if alias, ok := tlsLegacyKeys[key]; ok {
		legacy = alias
	}
	paths = append(paths, []string{"net", "ssl", legacy})
	return paths
}

// TLSString reads a net.tls setting, falling back to its net.ssl spelling.
func TLSString(params map[string]any, key string) string {
	for _, path := range tlsPaths(key) {
		if v := String(params, path...); v != "" {
			return v
		}
	}
	return ""
}

// TLSBool reads a net.tls setting, falling back to its net.ssl spelling.
func TLSBool(params map[string]any, def bool, key string) bool {
	for _, path := range tlsPaths(key) {
		if _, ok := Lookup(params, path...); ok {
			return Bool(params, def, path...)
		}
	}
	return def
}

// TLSList reads a net.tls list setting, falling back to its net.ssl spelling.
func TLSList(params map[string]any, key string) []string {
	for _, path := range tlsPaths(key) {
		if v := List(params, path...); len(v) > 0 {
			return v
		}
	}
	return nil
}

// legacyTLSModes maps each pre-4.2 net.ssl.mode value to the net.tls.mode
// value it is an exact alias of.
var legacyTLSModes = map[string]string{
	"allowSSL":   "allowTLS",
	"preferSSL":  "preferTLS",
	"requireSSL": "requireTLS",
}

// TLSMode reports net.tls.mode, normalized to the modern spelling.
//
// The pre-4.2 net.ssl.mode values are exact aliases of the net.tls.mode ones,
// so they are reported under the modern name. Without that, an audit asserting
// requireTLS would fail on a correctly configured host that spells it
// requireSSL. The default is disabled, which is what mongod uses when neither
// tree sets a mode.
func TLSMode(params map[string]any) string {
	mode := TLSString(params, "mode")
	if mode == "" {
		return "disabled"
	}
	if modern, ok := legacyTLSModes[mode]; ok {
		return modern
	}
	return mode
}

// ---------------------------------------------------------------------------
// version
// ---------------------------------------------------------------------------

// DefaultBindIp returns the addresses mongod listens on when net.bindIp is
// not set, for the given server version.
//
// MongoDB 3.6 made localhost the default. Before that a server with no
// bindIp listened on every interface (0.0.0.0, plus :: with net.ipv6), so
// reporting 127.0.0.1 for a 2.6 or 3.4 server would describe an exposed
// server as a local-only one. It returns nil when the version is empty or
// unreadable, since the answer depends on it.
func DefaultBindIp(version string, ipv6 bool) []string {
	major, minor, ok := majorMinor(version)
	if !ok {
		return nil
	}
	if major > 3 || (major == 3 && minor >= 6) {
		return []string{"127.0.0.1"}
	}
	if ipv6 {
		return []string{"0.0.0.0", "::"}
	}
	return []string{"0.0.0.0"}
}

// majorMinor reads the first two components of a version such as "3.6.3".
func majorMinor(version string) (int, int, bool) {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// reVersion matches the banner `mongod --version` opens with, for example
// "db version v7.0.14".
var reVersion = regexp.MustCompile(`(?i)db version\s+v?(\d+\.\d+(?:\.\d+)?)`)

// ParseVersion extracts the server version from `mongod --version` output,
// returning the empty string when the output carries no recognizable banner.
func ParseVersion(output string) string {
	m := reVersion.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	return m[1]
}
