// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
)

func (a *mqlAptConfig) id() (string, error) {
	return "apt.config", nil
}

// params returns APT's effective configuration as `apt-config dump` prints
// it: the built-in defaults merged with /etc/apt/apt.conf and
// /etc/apt/apt.conf.d/*. Where apt-config cannot run, it is an error, not
// an empty map: an empty map would make every accessor report APT's
// defaults, which reads as a configured system.
func (a *mqlAptConfig) params() (map[string]any, error) {
	o, err := CreateResource(a.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("apt-config dump"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil {
		return nil, exit.Error
	} else if exit.Data != 0 {
		return nil, fmt.Errorf("apt-config dump failed (exit code %d): %s", exit.Data, strings.TrimSpace(cmd.GetStderr().Data))
	}

	res := map[string]any{}
	for k, v := range parseAptConfigDump(cmd.GetStdout().Data) {
		res[k] = v
	}
	return res, nil
}

// parseAptConfigDump reads the `Key "value";` lines of `apt-config dump`.
// A list option prints as `Key "";` followed by one `Key:: "item";` line
// per item; its items are joined with newlines under Key.
func parseAptConfigDump(out string) map[string]string {
	res := map[string]string{}
	lists := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		i := strings.Index(line, ` "`)
		if i <= 0 {
			continue
		}
		key := line[:i]
		value := strings.TrimSuffix(strings.TrimSuffix(line[i+2:], ";"), `"`)

		if parent, ok := strings.CutSuffix(key, "::"); ok {
			if lists[parent] {
				res[parent] += "\n" + value
			} else {
				res[parent] = value
				lists[parent] = true
			}
			continue
		}
		if !lists[key] {
			res[key] = value
		}
	}
	return res
}

// aptBoolParam interprets an APT boolean option the way APT's FindB does: an
// absent or empty value is the option's default, anything else goes through
// aptStringToBool.
func aptBoolParam(params map[string]any, key string, def bool) bool {
	v, ok := aptParam(params, key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	return aptStringToBool(v, def)
}

// aptStringToBool is APT's StringToBool. A value that is entirely a number,
// read the way C's strtol reads it with base 0 (0x hex, leading-zero octal),
// is false for 0 and true for 1; any other number is not a boolean. Then
// yes/true/with/on/enable are true and no/false/without/off/disable are
// false, ignoring case. Everything else is the default: "2" is not true, and
// "0x0" is false. Like APT, the value is not trimmed: strtol skips leading
// whitespace, but "1 " and " yes" are not booleans.
func aptStringToBool(text string, def bool) bool {
	if n, ok := aptStrtol(text); ok && (n == 0 || n == 1) {
		return n == 1
	}
	switch strings.ToLower(text) {
	case "no", "false", "without", "off", "disable":
		return false
	case "yes", "true", "with", "on", "enable":
		return true
	}
	return def
}

// aptStrtol parses s the way strtol(s, &end, 0) does when end must reach the
// end of s, and truncates to a C int as StringToBool does. glibc 2.38 and
// later also read a 0b binary prefix; that is left out, as older releases
// treat it as no number.
func aptStrtol(s string) (int32, bool) {
	s = strings.TrimLeft(s, " \t\n\v\f\r")
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	base := 10
	switch {
	case len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X"):
		base, s = 16, s[2:]
	case len(s) > 1 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return 0, false
	}
	u, err := strconv.ParseUint(s, base, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, false
	}
	// strtol saturates at LONG_MAX and LONG_MIN
	var v int64
	switch {
	case u > math.MaxInt64 || err != nil:
		v = math.MaxInt64
		if neg {
			v = math.MinInt64
		}
	case neg:
		v = -int64(u)
	default:
		v = int64(u)
	}
	return int32(v), true
}

// aptParam looks an option up the way APT does, ignoring case. apt-config dump
// prints a key in the case it was first set in, so an option no built-in
// default creates (Acquire::Check-Date) shows up as `Acquire::check-date` when
// a configuration file spells it that way.
func aptParam(params map[string]any, key string) (string, bool) {
	if v, ok := params[key].(string); ok {
		return v, true
	}
	for k, raw := range params {
		if strings.EqualFold(k, key) {
			v, ok := raw.(string)
			return v, ok
		}
	}
	return "", false
}

// aptFrontends are the binaries whose Binary::<name>:: scope APT copies over
// the configuration when that binary runs (BinarySpecificConfiguration). apt
// 1.4 (Debian 9) ships `Binary::apt-get::Acquire::AllowInsecureRepositories
// "1"`: apt refuses an unsigned repository there, apt-get still loads it.
var aptFrontends = []string{"apt-get", "apt"}

// aptWeakestBool resolves a repository-trust option the way every APT
// front-end sees it and returns the weaker answer: weak when the base
// configuration or any front-end's Binary:: override sets the option to
// weak. A host whose apt-get accepts unsigned repositories accepts them,
// whatever apt does.
func aptWeakestBool(params map[string]any, key string, def bool, weak bool) bool {
	base := aptBoolParam(params, key, def)
	if base == weak {
		return weak
	}
	for _, bin := range aptFrontends {
		if aptBoolParam(params, "Binary::"+bin+"::"+key, base) == weak {
			return weak
		}
	}
	return base
}

func (a *mqlAptConfig) allowInsecureRepositories(params map[string]any) (bool, error) {
	return aptWeakestBool(params, "Acquire::AllowInsecureRepositories", false, true), nil
}

func (a *mqlAptConfig) allowWeakRepositories(params map[string]any) (bool, error) {
	return aptWeakestBool(params, "Acquire::AllowWeakRepositories", false, true), nil
}

func (a *mqlAptConfig) allowDowngradeToInsecureRepositories(params map[string]any) (bool, error) {
	return aptWeakestBool(params, "Acquire::AllowDowngradeToInsecureRepositories", false, true), nil
}

func (a *mqlAptConfig) checkDate(params map[string]any) (bool, error) {
	return aptWeakestBool(params, "Acquire::Check-Date", true, false), nil
}

// installRecommends is true when apt-config dump has no APT::Install-Recommends:
// APT's built-in configuration sets it. The resolver reads it with
// FindB("APT::Install-Recommends", false), though, so a value that is not a
// boolean ("2", "maybe", "") turns recommends off, as apt-get install shows.
func (a *mqlAptConfig) installRecommends(params map[string]any) (bool, error) {
	if _, ok := aptParam(params, "APT::Install-Recommends"); !ok {
		return true, nil
	}
	return aptBoolParam(params, "APT::Install-Recommends", false), nil
}

func (a *mqlAptConfig) installSuggests(params map[string]any) (bool, error) {
	return aptBoolParam(params, "APT::Install-Suggests", false), nil
}
