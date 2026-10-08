// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// NewContextConfig prepares a context config a provider found at the root it
// scans, for attaching to an asset. Keys a context config may not carry are
// dropped here, before the content reaches an asset that is synced upstream and
// written into reports; credentials among them are warned about, naming the
// file. It returns nil when nothing is left to attach.
//
// filename is what the warning names; origin and assetPath are recorded as
// they are given.
func NewContextConfig(data []byte, filename string, origin *inventory.ConfigOrigin, assetPath string) *inventory.ContextConfig {
	if data == nil {
		return nil
	}
	filtered, err := inventory.FilterContextConfig(data)
	if err != nil {
		log.Warn().Err(err).Str("file", filename).Msg("ignoring invalid config at scanned root")
		return nil
	}
	if len(filtered.SensitiveKeys) > 0 {
		log.Warn().Str("file", filename).Strs("keys", filtered.SensitiveKeys).
			Msg("config at scanned root holds credentials or endpoints; they are ignored, and should not be in version control")
	}
	if len(filtered.IgnoredKeys) > 0 {
		log.Debug().Str("file", filename).Strs("keys", filtered.IgnoredKeys).
			Msg("config at scanned root may only carry exceptions; ignoring other keys")
	}
	if filtered.Content == nil {
		return nil
	}
	return &inventory.ContextConfig{
		Content:   filtered.Content,
		Origin:    origin,
		AssetPath: assetPath,
	}
}

// ReadContextConfig reads the context config in dir, the root a provider
// scans, for attaching to an asset. It returns nil when there is none or it
// cannot be read; a config that cannot be read never fails a scan.
func ReadContextConfig(dir string, origin *inventory.ConfigOrigin, assetPath string) *inventory.ContextConfig {
	data, path, err := inventory.ReadContextConfigFile(dir)
	if err != nil {
		log.Warn().Err(err).Str("file", path).Msg("ignoring config at scanned root")
		return nil
	}
	if data == nil {
		return nil
	}
	if origin != nil && origin.Path == "" {
		origin.Path = path
	}
	return NewContextConfig(data, path, origin, assetPath)
}
