// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/providers/core/resources/versions/semver"
)

// ResolveUpdateTarget decides which version of a provider should be active,
// given the currently installed version, the latest published version, and the
// pin/floor policy. It returns the target version and whether an update is
// needed.
//
// Precedence:
//
//  1. Pin wins outright: a pinned provider is held at exactly that version. If
//     it is already installed, no update; otherwise install the pinned version
//     (which may be a deliberate downgrade).
//  2. Floor guards the latest: if the published latest is below the configured
//     minimum, it is refused and the installed version is kept. This stops a
//     withdrawn or regressed "latest" from rolling the fleet below a known-good
//     baseline.
//  3. Otherwise update when latest is newer than what is installed.
func ResolveUpdateTarget(name, installed, latest string, cfg UpdateProvidersConfig) (target string, update bool, err error) {
	sv := semver.Parser{}

	if pin, ok := cfg.Pin[name]; ok && pin != "" {
		if pin == installed {
			return installed, false, nil
		}
		log.Info().
			Str("provider", name).
			Str("installed", installed).
			Str("pin", pin).
			Msg("provider is pinned; installing the pinned version")
		return pin, true, nil
	}

	if floor, ok := cfg.Floor[name]; ok && floor != "" {
		cmp, err := sv.Compare(latest, floor)
		if err != nil {
			return "", false, err
		}
		if cmp < 0 {
			log.Warn().
				Str("provider", name).
				Str("latest", latest).
				Str("floor", floor).
				Msg("published latest is below the configured version floor; not updating")
			return installed, false, nil
		}
	}

	diff, err := sv.Compare(installed, latest)
	if err != nil {
		return "", false, err
	}
	if diff >= 0 {
		return installed, false, nil
	}
	return latest, true, nil
}
