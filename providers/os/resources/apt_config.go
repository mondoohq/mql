// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
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

// aptBoolParam interprets an APT boolean option the way APT does
// (StringToBool): yes/true/with/on/enable are true, no/false/without/off/
// disable are false, case-insensitive, and a number is true unless 0. An
// absent or unrecognized value is the option's default.
func aptBoolParam(params map[string]any, key string, def bool) bool {
	v, ok := aptParam(params, key)
	if !ok {
		return def
	}
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "yes", "true", "with", "on", "enable":
		return true
	case "no", "false", "without", "off", "disable":
		return false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n != 0
	}
	return def
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

func (a *mqlAptConfig) installRecommends(params map[string]any) (bool, error) {
	return aptBoolParam(params, "APT::Install-Recommends", true), nil
}

func (a *mqlAptConfig) installSuggests(params map[string]any) (bool, error) {
	return aptBoolParam(params, "APT::Install-Suggests", false), nil
}
