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
	v, ok := params[key].(string)
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

func (a *mqlAptConfig) allowInsecureRepositories(params map[string]any) (bool, error) {
	return aptBoolParam(params, "Acquire::AllowInsecureRepositories", false), nil
}

func (a *mqlAptConfig) allowWeakRepositories(params map[string]any) (bool, error) {
	return aptBoolParam(params, "Acquire::AllowWeakRepositories", false), nil
}

func (a *mqlAptConfig) allowDowngradeToInsecureRepositories(params map[string]any) (bool, error) {
	return aptBoolParam(params, "Acquire::AllowDowngradeToInsecureRepositories", false), nil
}

func (a *mqlAptConfig) checkDate(params map[string]any) (bool, error) {
	return aptBoolParam(params, "Acquire::Check-Date", true), nil
}

func (a *mqlAptConfig) installRecommends(params map[string]any) (bool, error) {
	return aptBoolParam(params, "APT::Install-Recommends", true), nil
}

func (a *mqlAptConfig) installSuggests(params map[string]any) (bool, error) {
	return aptBoolParam(params, "APT::Install-Suggests", false), nil
}
