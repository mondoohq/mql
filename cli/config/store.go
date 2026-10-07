// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

// list of field keys to avoid writing to disk
var fieldKeysToOmit = []string{"force"}

// credentialKeys are the config keys that hold a secret. A config with any of
// them set is written readable by its owner only.
var credentialKeys = []string{"private_key", "token"}

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

// StoreConfig writes the loaded configuration to the config file.
//
// A configuration that holds a credential is written to a temporary file that
// is readable by its owner only (mode 0600; on Windows an access control list
// for the current user, SYSTEM and Administrators) and then renamed over the
// config file. If owner-only access cannot be set, or the config path is a
// symbolic link, nothing is written and an error is returned.
func StoreConfig() error {
	path := viper.ConfigFileUsed()
	log.Info().Str("path", path).Msg("saving config")

	// omit fields before storing the configuration
	for _, field := range fieldKeysToOmit {
		viper.Set(field, nil)
	}

	if hasCredential() {
		return storeOwnerOnly(path)
	}

	// create new file if it does not exist
	osFs := afero.NewOsFs()
	if _, err := osFs.Stat(path); os.IsNotExist(err) {
		log.Info().Str("path", path).Msg("config file does not exist, create a new one")
		// create the directory if it does not exist
		err = osFs.MkdirAll(filepath.Dir(path), 0o755)
		if err != nil {
			return errors.Wrap(err, "failed to save mondoo config")
		}

		// write file
		err = os.WriteFile(path, []byte{}, 0o644)
		if err != nil {
			return errors.Wrap(err, "failed to save mondoo config")
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to check stats for mondoo config")
	}

	return viper.WriteConfig()
}

func hasCredential() bool {
	for _, key := range credentialKeys {
		if viper.GetString(key) != "" {
			return true
		}
	}
	return false
}

// storeOwnerOnly writes the loaded configuration to path through a temporary
// file in the same directory that only its owner can access.
func storeOwnerOnly(path string) error {
	if path == "" {
		return errors.New("failed to save mondoo config: no config file path")
	}
	data, err := encodeSettings(path)
	if err != nil {
		return errors.Wrap(err, "failed to save mondoo config")
	}
	return WriteOwnerOnlyFile(path, data)
}

// encodeSettings serializes the loaded configuration in the format of path's
// extension, as viper.WriteConfig does.
func encodeSettings(path string) ([]byte, error) {
	format := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if format == "" {
		format = "yaml"
	}
	if !slices.Contains(viper.SupportedExts, format) {
		return nil, viper.UnsupportedConfigError(format)
	}
	v := viper.New()
	v.SetConfigType(format)
	if err := v.MergeConfigMap(viper.AllSettings()); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := v.WriteConfigTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteOwnerOnlyFile replaces the file at path with data, readable and
// writable by its owner only. The data is written to a temporary file in the
// same directory, restricted before anything is written to it, and renamed
// over path, so path never holds partial content. An existing file keeps its
// owner where the platform allows it.
//
// It refuses to write when path is a symbolic link or not a regular file, and
// when owner-only access cannot be set.
func WriteOwnerOnlyFile(path string, data []byte) error {
	var existing fs.FileInfo
	fi, err := os.Lstat(path)
	switch {
	case err == nil:
		if fi.Mode()&fs.ModeSymlink != 0 {
			return errors.Newf("refusing to write credentials to %s: it is a symbolic link; replace it with a regular file or use --config to point to the file itself", path)
		}
		if !fi.Mode().IsRegular() {
			return errors.Newf("refusing to write credentials to %s: it is not a regular file", path)
		}
		existing = fi
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return errors.Wrap(err, "failed to create the mondoo config directory")
		}
	default:
		return errors.Wrapf(err, "failed to check %s", path)
	}

	// os.CreateTemp creates the file with mode 0600.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return errors.Wrap(err, "failed to save mondoo config")
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := restrictToOwner(tmp); err != nil {
		tmp.Close()
		return errors.Wrapf(err, "refusing to write credentials to %s: could not make the file readable by its owner only", path)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return errors.Wrap(err, "failed to save mondoo config")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return errors.Wrap(err, "failed to save mondoo config")
	}
	if err := tmp.Close(); err != nil {
		return errors.Wrap(err, "failed to save mondoo config")
	}
	if existing != nil {
		preserveOwner(tmpName, existing)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return errors.Wrap(err, "failed to save mondoo config")
	}
	renamed = true
	return nil
}
