// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

const (
	// PrivateFileMode is the mode for files that may hold credentials, such as
	// the Mondoo config, which carries the service account's private key.
	PrivateFileMode os.FileMode = 0o600
	// PrivateDirMode is the mode for a directory mql creates to hold such files.
	PrivateDirMode os.FileMode = 0o700
)

// list of field keys to avoid writing to disk
var fieldKeysToOmit = []string{"force"}

// MarshalConfig serializes cfg using the serialization format implied by the
// config file path's extension: a ".json" path produces JSON, everything else
// (".yaml", ".yml", or no extension) produces YAML. This mirrors viper's own
// extension-based format detection (used by WriteConfig) so a config file
// loaded as JSON is written back as JSON rather than silently converted to
// YAML.
//
// Both formats key off the struct's json tags (sigs.k8s.io/yaml marshals via
// JSON under the hood), so the on-disk key names are identical regardless of
// format.
func MarshalConfig(path string, cfg *Config) ([]byte, error) {
	if strings.EqualFold(filepath.Ext(path), ".json") {
		return json.MarshalIndent(cfg, "", "  ")
	}
	return yaml.Marshal(cfg)
}

// privateMode returns the mode a rewritten credentials file should carry: the
// existing mode with every group and other bit cleared. A stricter mode (for
// example 0400) is kept as is; the mode is never widened.
func privateMode(mode os.FileMode) os.FileMode {
	return mode.Perm() & PrivateFileMode
}

// TightenFileMode removes group and other permissions from an existing file at
// path, so a credentials file is no longer readable by other users. Stricter
// modes are preserved. A missing file is not an error.
//
// On Windows, os.Chmod only toggles the read-only attribute and access is
// governed by ACLs, so this is effectively a no-op there.
func TightenFileMode(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if mode := privateMode(info.Mode()); mode != info.Mode().Perm() {
		return os.Chmod(path, mode)
	}
	return nil
}

// WritePrivateFile writes data to path for a file that may hold credentials. A
// new file is created with PrivateFileMode. An existing file is tightened to
// PrivateFileMode (keeping stricter modes) before any data is written, so the
// new content is never readable by other users.
func WritePrivateFile(path string, data []byte) error {
	if err := TightenFileMode(path); err != nil {
		return err
	}
	return os.WriteFile(path, data, PrivateFileMode)
}

// ensureConfigDir creates dir if it does not exist. The directory that holds
// the config itself is created with PrivateDirMode; any missing parents get the
// conventional 0755 so mql does not lock down shared locations such as
// /etc/opt or ~/.config.
func ensureConfigDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, PrivateDirMode); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func StoreConfig() error {
	path := viper.ConfigFileUsed()
	log.Info().Str("path", path).Msg("saving config")

	// create new file if it does not exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info().Str("path", path).Msg("config file does not exist, create a new one")
		// create the directory if it does not exist
		if err := ensureConfigDir(filepath.Dir(path)); err != nil {
			return errors.Wrap(err, "failed to save mondoo config")
		}

		// write file; the config holds the service account's private key, so
		// it must not be readable by other users
		if err := os.WriteFile(path, []byte{}, PrivateFileMode); err != nil {
			return errors.Wrap(err, "failed to save mondoo config")
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to check stats for mondoo config")
	}

	// An existing config may have been written world-readable by an older
	// version. Tighten it before viper writes the credentials into it: viper
	// rewrites the file in place (O_TRUNC) and keeps the existing mode.
	if err := TightenFileMode(path); err != nil {
		return errors.Wrap(err, "failed to restrict permissions of mondoo config")
	}

	// omit fields before storing the configuration
	for _, field := range fieldKeysToOmit {
		viper.Set(field, nil)
	}

	// Should viper create the file itself, it must use the private mode too.
	viper.SetConfigPermissions(PrivateFileMode)
	return viper.WriteConfig()
}
