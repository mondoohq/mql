// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package project

import (
	"os"
	"strings"
)

// Config is a parsed ansible.cfg. Sections holds the full INI contents; the
// typed fields surface high-signal security settings with Ansible's documented
// defaults applied.
type Config struct {
	Path            string
	Sections        map[string]map[string]any
	HostKeyChecking bool
	Become          bool
	BecomeUser      string
}

// loadConfig parses an ansible.cfg file. Returns nil when the file is absent.
func loadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	cfg := &Config{
		Path:     path,
		Sections: parseINI(data),
		// host_key_checking defaults to true when unset.
		HostKeyChecking: true,
	}

	if defaults, ok := cfg.Sections["defaults"]; ok {
		if v, ok := boolValue(defaults["host_key_checking"]); ok {
			cfg.HostKeyChecking = v
		}
	}
	if esc, ok := cfg.Sections["privilege_escalation"]; ok {
		if v, ok := boolValue(esc["become"]); ok {
			cfg.Become = v
		}
		if u, ok := esc["become_user"].(string); ok {
			cfg.BecomeUser = u
		}
	}
	return cfg
}

// parseINI parses a standard INI document ([section] headers with key = value
// lines) into per-section maps. Values are kept as strings.
func parseINI(data []byte) map[string]map[string]any {
	sections := map[string]map[string]any{}
	current := "default"
	sections[current] = map[string]any{}

	for raw := range strings.SplitSeq(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if _, ok := sections[current]; !ok {
				sections[current] = map[string]any{}
			}
			continue
		}
		if k, v, ok := splitKV(line, "="); ok {
			sections[current][k] = v
		}
	}

	// Drop the synthetic default section when nothing preceded the first header.
	if len(sections["default"]) == 0 {
		delete(sections, "default")
	}
	return sections
}

// boolValue interprets the common Ansible boolean spellings.
func boolValue(v any) (bool, bool) {
	s, ok := v.(string)
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, false
}
