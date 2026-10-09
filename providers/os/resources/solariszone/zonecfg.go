// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package solariszone

import (
	"fmt"
	"strconv"
	"strings"
)

// Config is a zone configuration as `zonecfg -z <zone> info -a` prints it.
//
// Oracle Solaris 11.4 prints only the properties with a non-default value
// unless -a is given, in `info` and `export` alike, so a configuration read
// without -a cannot tell an unset property from one at its default. With -a
// every property is printed, an unset one with an empty value.
type Config struct {
	// Props holds the zone-wide properties. A property zonecfg derives
	// from a resource control, printed in brackets ([max-lwps: 2000]), is
	// held under its plain name.
	Props map[string]string
	// Resources holds every resource (anet, fs, dataset, ...) in order.
	Resources []Resource
}

// Resource is one resource of a zone configuration, such as an anet, fs,
// dataset, device, capped-memory or rctl.
type Resource struct {
	Type string
	// Props holds the resource's properties. For a property printed more
	// than once, such as the values of an rctl, the first one is kept.
	Props map[string]string
}

// ParseInfo parses the output of `zonecfg -z <zone> info -a`:
//
//	zonename: web1
//	autoboot: true
//	[max-lwps: 2000]
//	anet:
//		linkname: net0
//		link-protection: mac-nospoof
//
// A line that is not indented is a zone-wide property, or the start of a
// resource whose properties follow indented.
func ParseInfo(out string) (*Config, error) {
	cfg := &Config{Props: map[string]string{}}
	var cur *Resource
	for n, raw := range strings.Split(out, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indented := raw[0] == '\t' || raw[0] == ' '
		key, value, ok := parseInfoLine(raw)
		if !ok {
			return nil, fmt.Errorf("zonecfg info line %d: %q is not a property", n+1, raw)
		}

		if indented {
			if cur == nil {
				return nil, fmt.Errorf("zonecfg info line %d: resource property %q outside a resource", n+1, raw)
			}
			if _, seen := cur.Props[key]; !seen {
				cur.Props[key] = value
			}
			continue
		}

		// zonecfg prints a property without a value as "key: ", with a
		// trailing space, and the start of a resource as "type:".
		if strings.HasSuffix(raw, ":") && !strings.HasPrefix(raw, "[") {
			cfg.Resources = append(cfg.Resources, Resource{Type: key, Props: map[string]string{}})
			cur = &cfg.Resources[len(cfg.Resources)-1]
			continue
		}
		cur = nil
		cfg.Props[key] = value
	}
	return cfg, nil
}

// parseInfoLine splits "key: value" or "[key: value]" into key and value.
func parseInfoLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		line = line[1 : len(line)-1]
	}
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, strings.TrimSpace(value), true
}

// ResourcesOf returns every resource of the given type, in order.
func (c *Config) ResourcesOf(typ string) []Resource {
	var res []Resource
	for _, r := range c.Resources {
		if r.Type == typ {
			res = append(res, r)
		}
	}
	return res
}

// List splits a list value, written as "[a,b]" or "a,b", into its entries.
// Quotes around an entry are removed. An empty value is an empty list.
func List(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	res := []string{}
	for _, e := range strings.Split(v, ",") {
		e = strings.Trim(strings.TrimSpace(e), `"`)
		if e != "" {
			res = append(res, e)
		}
	}
	return res
}

// ParseSize parses a zonecfg memory size such as 512M, 2G or 1.5g into bytes.
// A size without a unit is in bytes.
func ParseSize(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := float64(1)
	switch strings.ToUpper(v[len(v)-1:]) {
	case "K":
		mult = 1 << 10
	case "M":
		mult = 1 << 20
	case "G":
		mult = 1 << 30
	case "T":
		mult = 1 << 40
	}
	num := v
	if mult != 1 {
		num = v[:len(v)-1]
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid size %q", v)
	}
	return int64(f * mult), nil
}
