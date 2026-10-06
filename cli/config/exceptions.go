// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"bytes"
	"reflect"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"gopkg.in/yaml.v3"
)

// ContextConfigFilename is the name of a context config, read by providers at
// the root they scan. It is the same name and schema as the client config.
const ContextConfigFilename = inventory.ContextConfigFilename

// Exception is one entry under the `exceptions` key of mondoo.yml. Exceptions
// are in preview: the shape may still change (cnspec ADR-0006). Only the shape
// is defined here; what the fields mean, and which values are valid, is up to
// the policy engine that applies them.
type Exception struct {
	// Title is free text, carried through when set. It is not an identifier.
	Title string `json:"title,omitempty" yaml:"title,omitempty" mapstructure:"title"`
	// Checks are check UIDs or MRNs, several per entry.
	Checks []string `json:"checks,omitempty" yaml:"checks,omitempty" mapstructure:"checks"`
	// Paths are path prefixes, relative to the directory holding the config,
	// that scope the entry. Empty means the entry applies to every asset the
	// config governs.
	Paths []string `json:"paths,omitempty" yaml:"paths,omitempty" mapstructure:"paths"`
	// Action names why the exception exists, e.g. "risk-accepted".
	Action string `json:"action,omitempty" yaml:"action,omitempty" mapstructure:"action"`
	// Justification states the reason for the exception.
	Justification string `json:"justification,omitempty" yaml:"justification,omitempty" mapstructure:"justification"`
	// ValidUntil is an RFC3339 date or date-time after which the entry no
	// longer applies.
	ValidUntil string `json:"valid_until,omitempty" yaml:"valid_until,omitempty" mapstructure:"valid_until"`
}

// ContextConfig is what a context config may carry. Context configs are in
// preview: what they may carry may still change (cnspec ADR-0006). A context
// config is a mondoo.yml found at a scanned root, so it is written by anyone
// who can change the scanned repository; it is parsed into this struct and
// never into the client configuration.
type ContextConfig struct {
	Exceptions []Exception
	// IgnoredKeys are top-level keys present in the file that a context config
	// may not set. They have no effect.
	IgnoredKeys []string
	// SensitiveKeys are the subset of IgnoredKeys that hold credentials or
	// redirect where results are sent. Their presence is worth a warning: a
	// credential in a scanned repository is in version control.
	SensitiveKeys []string
}

// ParseContextConfig reads a context config. Only the keys in
// inventory.ContextConfigKeys are read; every other key is reported in
// IgnoredKeys and otherwise has no effect. Entries are decoded strictly, so a
// misspelt field such as `valid-until` is an error rather than an entry that
// silently never expires.
func ParseContextConfig(data []byte) (*ContextConfig, error) {
	filtered, err := inventory.FilterContextConfig(data)
	if err != nil {
		return nil, err
	}
	res := &ContextConfig{
		IgnoredKeys:   filtered.IgnoredKeys,
		SensitiveKeys: filtered.SensitiveKeys,
	}
	if filtered.Content == nil {
		return res, nil
	}

	var top map[string]yaml.Node
	if err := yaml.Unmarshal(filtered.Content, &top); err != nil {
		return nil, errors.Wrap(err, "failed to parse config")
	}
	node, ok := top["exceptions"]
	if !ok {
		return res, nil
	}
	res.Exceptions, err = decodeExceptions(&node)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func decodeExceptions(node *yaml.Node) ([]Exception, error) {
	// yaml.Node.Decode cannot reject unknown fields, so the node is written back
	// out and read through a strict decoder.
	raw, err := yaml.Marshal(node)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read exceptions")
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var res []Exception
	if err := dec.Decode(&res); err != nil {
		return nil, errors.Wrap(err, "failed to parse exceptions")
	}
	return res, nil
}

// DecoderOption is the decoder option to unmarshal the client config with.
// YAML reads an unquoted date such as `valid_until: 2026-11-01` as a timestamp,
// which mapstructure cannot put into a string field, so without it a single
// exception entry would fail the whole config. The remaining hooks are viper's
// defaults, which setting any hook replaces.
func DecoderOption() viper.DecoderConfigOption {
	return viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		stringToWeakSliceHook(","),
		timeToStringHook,
	))
}

var timeType = reflect.TypeOf(time.Time{})

// timeToStringHook writes a timestamp back as the date the author wrote, or as
// RFC3339 when it carries a time of day.
func timeToStringHook(f reflect.Type, t reflect.Type, data any) (any, error) {
	if f != timeType || t.Kind() != reflect.String {
		return data, nil
	}
	ts := data.(time.Time)
	if ts.Equal(ts.Truncate(24*time.Hour)) && ts.Location() == time.UTC {
		return ts.Format(time.DateOnly), nil
	}
	return ts.Format(time.RFC3339), nil
}

// stringToWeakSliceHook matches viper's default string-to-slice hook: an empty
// string becomes an empty slice rather than a slice holding one empty string.
func stringToWeakSliceHook(sep string) mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data any) (any, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Slice {
			return data, nil
		}
		raw := data.(string)
		if raw == "" {
			return []string{}, nil
		}
		return strings.Split(raw, sep), nil
	}
}
