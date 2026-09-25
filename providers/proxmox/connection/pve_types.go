// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// PveBool decodes a Proxmox boolean flag.
//
// Proxmox is written in Perl and has no native JSON boolean, so most flags
// come back as the integers 1 and 0. Its published API schema nonetheless
// declares them as `boolean`, and some endpoints and releases do emit real
// JSON `true`/`false`; a handful of config-derived values arrive quoted.
//
// Neither plain Go type survives that spread. A `bool` field silently stays
// false against the integer form, because encoding/json will not coerce a
// number into a bool, and the zero value is indistinguishable from a real
// false. An `int` field fails outright on the boolean form, and because the
// error propagates out of apiGet it takes the whole list with it.
//
// This accepts every form Proxmox is known to produce, so a flag reports what
// the cluster actually set rather than the Go zero value.
type PveBool bool

// Bool returns the decoded value.
func (b PveBool) Bool() bool { return bool(b) }

func (b *PveBool) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.TrimSpace(string(data)), `"`)
	switch s {
	case "true":
		*b = true
		return nil
	case "false", "null", "":
		*b = false
		return nil
	}
	// Numeric form: Proxmox uses 1 and 0, but treat any non-zero as set
	// rather than rejecting a value the cluster clearly considers true.
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		*b = f != 0
		return nil
	}
	return fmt.Errorf("cannot decode %q as a proxmox boolean", s)
}

// PveNumber decodes a Proxmox numeric value.
//
// Values Proxmox reads out of a guest config keep the Perl scalar they were
// parsed into, so the same key arrives as a JSON number on one endpoint and as
// a quoted string on another: an LXC container's `cpus` is `"1.5"` when it
// comes from a fractional `cpulimit`. Keys the schema declares as `number`
// can also be fractional where the Go side wants a whole count. A plain `int`
// field rejects both forms, and because the error propagates out of apiGet a
// single such guest takes the whole listing down with it.
type PveNumber float64

// Float returns the decoded value.
func (n PveNumber) Float() float64 { return float64(n) }

// Int returns the value rounded to the nearest whole number.
func (n PveNumber) Int() int64 { return int64(math.Round(float64(n))) }

// Ceil returns the value rounded up, for counts where rounding down would
// under-report, such as the CPUs a guest may use.
func (n PveNumber) Ceil() int64 { return int64(math.Ceil(float64(n))) }

func (n *PveNumber) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("cannot decode %q as a proxmox number", s)
	}
	*n = PveNumber(f)
	return nil
}

// PveProps decodes a setting that Proxmox serializes either as a property
// string (`keep-last=3,keep-daily=7`) or as the object that string parses
// into (`{"keep-last":3,"keep-daily":7}`).
//
// Which form arrives depends on the endpoint and release: backup jobs return
// `prune-backups` and `fleecing` as objects, while the same keys are property
// strings when written. Decoding the object form into a Go string fails, and
// the failure takes the whole job listing with it. Both forms are normalized
// to the property-string form, with keys sorted so the value is stable.
type PveProps string

func (p *PveProps) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*p = ""
		return nil
	}
	if strings.HasPrefix(trimmed, "{") {
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		*p = PveProps(FormatPropertyString(obj))
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*p = PveProps(s)
	return nil
}

// FormatPropertyString renders a decoded property-string object back into
// its `key=value,...` form, keys sorted. Numbers print without an exponent or
// a trailing `.0`, so `{"keep-last":3}` becomes `keep-last=3`, and a JSON
// boolean prints as the `1`/`0` Proxmox itself writes.
func FormatPropertyString(obj map[string]any) string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := obj[k]
		if v == nil {
			continue
		}
		parts = append(parts, k+"="+PropertyValueString(v))
	}
	return strings.Join(parts, ",")
}

// PropertyValueString renders one decoded property value the way it would
// appear in a property string.
func PropertyValueString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		if val {
			return "1"
		}
		return "0"
	case []any:
		// list members inside a property string are `;`-separated
		items := make([]string, 0, len(val))
		for _, item := range val {
			items = append(items, PropertyValueString(item))
		}
		return strings.Join(items, ";")
	}
	return fmt.Sprintf("%v", v)
}

// ParsePropertyString splits a Proxmox property string into its key/value
// pairs.
//
// Many of the most security-relevant guest settings are not discrete JSON
// fields. Whether a VM carries pre-enrolled Secure Boot keys, which CPU
// mitigation flags reach the guest, and which SEV features are switched on all
// live inside a single comma-delimited config line such as
// `local-lvm:vm-100-disk-1,efitype=4m,pre-enrolled-keys=1`.
//
// A leading element with no `=` is the format's positional value and is stored
// under defaultKey, which is how PVE serializes the volume of a disk, the CPU
// model of `cpu`, the SEV type of `amd-sev`, and the device of `rng0`. An
// explicit `defaultKey=` later in the string wins over the positional form,
// matching how PVE itself parses the line. Elements that are neither are
// skipped rather than stored under an empty key.
//
// Values may themselves contain semicolons (`flags=+spec-ctrl;-ssbd`), which
// survive because only commas separate elements.
func ParsePropertyString(s, defaultKey string) map[string]string {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out
	}
	for i, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found {
			// Only the first element may be positional; a later bare token is
			// not something PVE emits, so ignore it instead of guessing.
			if i == 0 && defaultKey != "" {
				out[defaultKey] = part
			}
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	return out
}

// PropBool reads a boolean out of a parsed property string, reporting absence
// as nil.
//
// The distinction matters: a setting the config never mentions and a setting
// explicitly turned off are different facts, and collapsing both into false
// would report "SEV debugging is permitted" about a VM whose config was never
// read. Callers that know PVE publishes a default for the key apply it
// themselves rather than having one invented here.
func PropBool(props map[string]string, key string) *bool {
	raw, ok := props[key]
	if !ok {
		return nil
	}
	return decodePveBoolPtr(raw)
}

// ConfigBool reads a boolean out of a raw guest config map, reporting absence
// as nil.
//
// The map comes straight from encoding/json, so the same flag arrives as a
// float64 1, a string "1", or a real JSON true depending on the endpoint and
// the Proxmox release.
func ConfigBool(cfg map[string]any, key string) *bool {
	if cfg == nil {
		return nil
	}
	v, ok := cfg[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case bool:
		return &val
	case float64:
		b := val != 0
		return &b
	case string:
		return decodePveBoolPtr(val)
	}
	return nil
}

func decodePveBoolPtr(raw string) *bool {
	var b PveBool
	if err := b.UnmarshalJSON([]byte(raw)); err != nil {
		return nil
	}
	out := bool(b)
	return &out
}
