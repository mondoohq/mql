// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

// ProvidersURLMigration reports what MigrateProvidersURL did, so a command can
// tell the operator whether anything changed and why not.
type ProvidersURLMigration struct {
	// Migrated is true when updates_url was written to the config file.
	Migrated bool
	// UpdatesURL is the value written, or the value that would be written.
	UpdatesURL string
	// Path is the config file that was, or would be, edited.
	Path string
	// Skipped explains why nothing was written, and is empty when it was.
	Skipped string
}

// MigrateProvidersURL writes the updates_url equivalent of a configured
// providers_url into the config file, and leaves providers_url in place.
//
// providers_url was removed in v14 and is honoured again for compatibility. This
// is the step that ends that: it adds the key the current code prefers, so the
// deprecated one can eventually be dropped from the rollout. The old key stays,
// so an agent that rolls back to an older binary still finds the setting it
// knows, and so a config owned by configuration management is not fighting a
// value this removed.
//
// It is called from a migrate command rather than at startup. These configs are
// rolled out fleet-wide and are often owned by configuration management, where
// an unasked-for write is either reverted on the next converge or a surprise
// edit of a file someone else manages. Migrating is a decision, so it is asked
// for.
//
// Note this widens what the value governs: providers_url names the provider
// registry, while updates_url is also where binary updates are looked for. The
// self-update reads both manifest layouts (see selfupdate.ReleaseURLs), so a
// mirror of the release bucket satisfies it, but a host that carries only
// /providers does not.
func MigrateProvidersURL() (ProvidersURLMigration, error) {
	res := ProvidersURLMigration{Path: viper.ConfigFileUsed()}

	providersURL := strings.TrimSpace(viper.GetString("providers_url"))
	if providersURL == "" {
		res.Skipped = "providers_url is not set"
		return res, nil
	}
	if existing := strings.TrimSpace(viper.GetString("updates_url")); existing != "" {
		res.Skipped = "updates_url is already set to " + existing
		return res, nil
	}

	if res.Path == "" {
		// The setting came from the environment, not a file. There is nothing to
		// migrate, and writing a config file that did not exist would be a
		// surprise rather than a fix.
		res.Skipped = "providers_url did not come from a config file"
		return res, nil
	}
	path := res.Path

	// Only YAML is appended to. The whole point is to add one key and disturb
	// nothing else, which a format-preserving edit of JSON is not.
	if ext := strings.ToLower(filepath.Ext(path)); ext != "" && ext != ".yml" && ext != ".yaml" {
		res.Skipped = "the config file is not YAML"
		return res, nil
	}

	updatesURL := strings.TrimSuffix(providersURL, "/providers")
	if updatesURL == "" || updatesURL == providersURL {
		// Not the "<host>/providers" shape this derives from. Rewriting it would
		// be a guess about a registry laid out some other way.
		res.Skipped = "providers_url does not end in /providers, so updates_url cannot be derived from it"
		return res, nil
	}
	// Parse before writing. The value reaches this from a config file or from
	// MONDOO_PROVIDERS_URL, and a migration that writes whatever it was handed
	// turns a bad setting into a bad config file.
	if u, err := url.Parse(updatesURL); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		res.Skipped = "providers_url is not an http(s) URL"
		return res, nil
	}
	res.UpdatesURL = updatesURL

	if err := appendConfigKey(path, "updates_url", updatesURL); err != nil {
		return res, err
	}

	res.Migrated = true
	return res, nil
}

// appendConfigKey adds one top-level key to a YAML config file, leaving the rest
// of the file -- including its comments and key order -- exactly as it was.
func appendConfigKey(path string, key string, value string) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Re-check against the file rather than viper: viper merges env and flags, so
	// it can report a key the file does not carry, and writing it again would
	// produce a duplicate.
	for _, line := range strings.Split(string(current), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), key+":") {
			return nil
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	// Marshalled rather than concatenated. A value carrying a newline would
	// otherwise continue as further YAML and add keys of its own -- writing
	// "updates_url: https://host" plus whatever came after the newline, as real
	// settings.
	marshalled, err := yaml.Marshal(map[string]string{key: value})
	if err != nil {
		return err
	}

	addition := string(marshalled)
	if len(current) > 0 && !strings.HasSuffix(string(current), "\n") {
		addition = "\n" + addition
	}

	// Write through a temporary file in the same directory and rename, so a
	// concurrent invocation reading the config never sees a half-written one.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mondoo-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(append(current, []byte(addition)...)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
