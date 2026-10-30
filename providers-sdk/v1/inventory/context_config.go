// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"sigs.k8s.io/yaml"
)

const (
	// ContextConfigFilename is the config a provider reads at the root it
	// scans. It shares its name and schema with the client config, but only
	// ContextConfigKeys take effect from it.
	ContextConfigFilename = "mondoo.yml"

	// maxContextConfigSize caps how much of an untrusted file is read.
	maxContextConfigSize = 1 << 20
)

// ContextConfigKeys are the top-level keys a context config may carry. Context
// configs are in preview: this set may still change (cnspec ADR-0006).
var ContextConfigKeys = map[string]struct{}{
	"exceptions": {},
}

// sensitiveConfigKeys are client config keys that hold credentials or decide
// where results are sent. They never take effect from a context config, and
// their presence there is worth a warning: the file is in version control.
var sensitiveConfigKeys = map[string]struct{}{
	"agent_mrn":    {},
	"mrn":          {},
	"scope_mrn":    {},
	"parent_mrn":   {},
	"space_mrn":    {},
	"private_key":  {},
	"certificate":  {},
	"token":        {},
	"auth":         {},
	"api_endpoint": {},
	"api_proxy":    {},
}

// FilteredContextConfig is a context config reduced to the keys it may carry.
type FilteredContextConfig struct {
	// Content holds only ContextConfigKeys, re-encoded as YAML; nil when the
	// file holds none of them.
	Content []byte
	// IgnoredKeys are the dropped top-level keys, sorted.
	IgnoredKeys []string
	// SensitiveKeys is the subset of IgnoredKeys that held credentials or
	// endpoints, sorted.
	SensitiveKeys []string
}

// FilterContextConfig drops every top-level key a context config may not
// carry. A provider calls it before the content is put on an asset, because an
// asset is synced upstream and written into reports: a credential committed to
// the scanned repository must not travel with it.
func FilterContextConfig(data []byte) (*FilteredContextConfig, error) {
	res := &FilteredContextConfig{}
	if len(bytes.TrimSpace(data)) == 0 {
		return res, nil
	}

	// The content is filtered through JSON, which is valid YAML, using the YAML
	// library this package already depends on. That keeps every provider module
	// that imports the package free of a further YAML dependency.
	js, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", ContextConfigFilename, err)
	}
	if string(bytes.TrimSpace(js)) == "null" {
		return res, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(js, &top); err != nil {
		return nil, fmt.Errorf("failed to parse %s: expected a mapping at the top level", ContextConfigFilename)
	}

	kept := map[string]json.RawMessage{}
	for key, value := range top {
		if _, ok := ContextConfigKeys[key]; ok {
			kept[key] = value
			continue
		}
		res.IgnoredKeys = append(res.IgnoredKeys, key)
		if _, ok := sensitiveConfigKeys[key]; ok {
			res.SensitiveKeys = append(res.SensitiveKeys, key)
		}
	}
	sort.Strings(res.IgnoredKeys)
	sort.Strings(res.SensitiveKeys)

	if len(kept) == 0 {
		return res, nil
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return nil, fmt.Errorf("failed to encode %s: %w", ContextConfigFilename, err)
	}
	res.Content = out
	return res, nil
}

// ReadContextConfigFile reads the context config in dir. It returns nil, nil
// when there is none. Only a regular file is read: in a cloned repository a
// symlink named mondoo.yml could point at the client's own config. A file
// replaced between the check and the open is refused.
func ReadContextConfigFile(dir string) (data []byte, path string, err error) {
	path = filepath.Join(dir, ContextConfigFilename)
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, path, nil
	}
	if err != nil {
		return nil, path, err
	}
	if !fi.Mode().IsRegular() {
		return nil, path, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxContextConfigSize {
		return nil, path, fmt.Errorf("%s is larger than %d bytes", path, maxContextConfigSize)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, path, err
	}
	defer f.Close()
	// Open follows symlinks, so the file may have been swapped for one since
	// the Lstat. The open file must be the one the Lstat saw.
	ofi, err := f.Stat()
	if err != nil {
		return nil, path, err
	}
	if !os.SameFile(fi, ofi) {
		return nil, path, fmt.Errorf("%s changed while it was being read", path)
	}
	data, err = io.ReadAll(io.LimitReader(f, maxContextConfigSize+1))
	if err != nil {
		return nil, path, err
	}
	if len(data) > maxContextConfigSize {
		return nil, path, fmt.Errorf("%s is larger than %d bytes", path, maxContextConfigSize)
	}
	return data, path, nil
}
