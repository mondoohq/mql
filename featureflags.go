// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// In this file we introduce feature flags.
// - Please configure any new feature-flags in features.yaml
// - To generate, use go generate. See the call to go:generate below
// - To learn more about the generator, look at ./utils/featureflags/main.go header
//
// Example usage:
//
// features := []Feature{ MassResolver, LiveQueries }
// features.IsActive( MassResolver )   // true

package mql

//go:generate go run utils/featureflags/main.go features.yaml -type=Feature -out=features.go
//go:generate go run golang.org/x/tools/cmd/stringer -type=Feature

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
)

// Features is a collection of activated features
type Features []byte

// Feature is a simple feature flag
type Feature byte

// IsActive returns true if the given feature has been requested in this list
func (f Features) IsActive(feature Feature) bool {
	return bytes.IndexByte(f, byte(feature)) != -1
}

// Encode a set of features to base64
func (f Features) Encode() string {
	return base64.StdEncoding.EncodeToString(f)
}

// String returns a list of features into human-readable form
func (f Features) String() string {
	all := make([]string, len(f))
	for i, cur := range f {
		all[i] = Feature(cur).String()
	}
	return strings.Join(all, ", ")
}

// DecodeFeatures that were previously encoded
func DecodeFeatures(s string) (Features, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	return Features(data), err
}

type featureContextID struct{}

// SetFeatures to a given context
func SetFeatures(ctx context.Context, fts Features) context.Context {
	return context.WithValue(ctx, featureContextID{}, fts)
}

func WithFeature(ctx context.Context, feature Feature) context.Context {
	existingFeatures := GetFeatures(ctx)
	if existingFeatures.IsActive(feature) {
		return ctx
	}
	// clone existing features
	features := make(Features, len(existingFeatures)+1)
	copy(features, existingFeatures)
	features[len(existingFeatures)] = byte(feature)
	return SetFeatures(ctx, features)
}

func IsFeatureActive(ctx context.Context, f Feature) bool {
	features := GetFeatures(ctx)
	return features.IsActive(f)
}

// GetFeatures from a given context
func GetFeatures(ctx context.Context) Features {
	f, ok := ctx.Value(featureContextID{}).(Features)
	if !ok {
		// nothing stored, assume empty features
		return Features{}
	}
	return f
}

// ScanContentMode returns the single active scan-content mode feature, or 0
// when no mode is active — the explicit form of the modes' mutual
// exclusivity. The scan-content modes (see the ScanContentMode* feature
// docs) let the client and server detect that a scan's content is identical
// to the previous upload and skip redundant transfer and processing. The
// server sends at most one mode, but nothing type-level enforces that on
// arbitrary Features values, so precedence is defined here:
// ScanContentModeNoCompare is the kill switch and wins over everything; the
// remaining modes rank by how much they enable (client_compare >
// server_compare > shadow), so a contradictory feature set degrades
// predictably rather than arbitrarily.
func (f Features) ScanContentMode() Feature {
	switch {
	case f.IsActive(ScanContentModeNoCompare):
		return ScanContentModeNoCompare
	case f.IsActive(ScanContentModeClientCompare):
		return ScanContentModeClientCompare
	case f.IsActive(ScanContentModeServerCompare):
		return ScanContentModeServerCompare
	case f.IsActive(ScanContentModeShadow):
		return ScanContentModeShadow
	default:
		return 0
	}
}

// ScanContentChecksumsActive reports whether the client should compute a
// checksum for every row while writing the scan database — the raw material
// that lets either side detect an unchanged scan and skip redundant work.
// ScanContentModeNoCompare is the kill switch and overrides everything -
// including, once comparison ships enabled-by-default, the client's own
// default - so every mode except it (and off) computes checksums.
func (f Features) ScanContentChecksumsActive() bool {
	switch f.ScanContentMode() {
	case ScanContentModeShadow, ScanContentModeServerCompare, ScanContentModeClientCompare:
		return true
	default:
		return false
	}
}

// InitFeatures initialized everything using the default features
// and can turn individual features on and off based on the
// strings that are provided. To turn a feature on just use its
// name. To turn it off use the "no" prefix in front of its name.
// Feature names are case-sensitive
func InitFeatures(features ...string) (Features, error) {
	bitSet := make([]bool, MAX_FEATURES)

	for _, f := range DefaultFeatures {
		if !bitSet[f] {
			bitSet[f] = true
		}
	}

	var failing []string
	for _, name := range features {
		flag, ok := FeaturesValue[name]
		if ok {
			bitSet[byte(flag)] = true
			continue
		}

		rest, found := strings.CutPrefix(name, "no")
		if found {
			flag, ok = FeaturesValue[rest]
			if ok {
				bitSet[byte(flag)] = false
				continue
			}
		}

		failing = append(failing, name)
	}

	flags := []byte{}
	for i := 1; i < int(MAX_FEATURES); i++ {
		if bitSet[i] {
			flags = append(flags, byte(i))
		}
	}

	var err error
	if len(failing) != 0 {
		err = errors.New("Failed to parse feature-flags: " + strings.Join(failing, ", "))
	}

	return Features(flags), err
}
