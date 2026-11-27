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
// governed by access lists instead. A file under ProgramData, such as the
// system config C:\ProgramData\Mondoo\mondoo.yml, would inherit ProgramData's
// default access list, which lets every local user read it, so there it gets
// an access list limited to SYSTEM and Administrators. Other files, such as a
// config in the user's profile, keep the access list they inherit.
func TightenFileMode(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if mode := privateMode(info.Mode()); mode != info.Mode().Perm() {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	return restrictAccess(path)
}

// WritePrivateFile writes data to path for a file that may hold credentials. A
// new file is created empty with PrivateFileMode and restricted first. An
// existing file is tightened to PrivateFileMode (keeping stricter modes). Either
// way the restriction is in place before any data is written, so the new
// content is never readable by other users.
func WritePrivateFile(path string, data []byte) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, PrivateFileMode)
		if err != nil && !os.IsExist(err) {
			return err
		}
		if f != nil {
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
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

// StoreConfig writes the loaded configuration to the config file.
//
// A configuration that holds a credential is written to a temporary file that
// is readable by its owner only (mode 0600; on Windows an access control list
// for the current user, SYSTEM and Administrators) and then renamed over the
// config file; a symbolic link at the config path is followed and the file it
// points to is replaced. If owner-only access cannot be set, or the config is
// not a regular file, nothing is written and an error is returned.
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

	// Should viper create the file itself, it must use the private mode too.
	viper.SetConfigPermissions(PrivateFileMode)
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
// A symbolic link at path is resolved first: the file it points to is
// replaced, next to itself, and the link stays a link. Packaged and container
// layouts commonly link the config to a file elsewhere.
//
// It refuses to write when the resolved path is not a regular file (including
// a link that points nowhere), and when owner-only access cannot be set.
func WriteOwnerOnlyFile(path string, data []byte) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}

	var existing fs.FileInfo
	fi, err := os.Lstat(path)
	switch {
	case err == nil:
		if !fi.Mode().IsRegular() {
			return errors.Newf("refusing to write credentials to %s: it is not a regular file", path)
		}
		existing = fi
	case errors.Is(err, fs.ErrNotExist):
		// The config's own directory is private; missing parents keep the
		// conventional mode (ensureConfigDir).
		if err := ensureConfigDir(filepath.Dir(path)); err != nil {
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
