// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pfctl

import (
	"strings"
)

// Services maps a service name and protocol, as in /etc/services, to the
// port number. pfctl prints a port by the name getservbyport(3) finds for it
// (`port = ssh`), so the name is resolved back to the number it stands for.
type Services map[string]string

// ParseServices parses an /etc/services file. Aliases resolve as well as the
// official name.
func ParseServices(content string) Services {
	res := Services{}
	for _, line := range strings.Split(content, "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		port, proto, ok := strings.Cut(fields[1], "/")
		if !ok {
			continue
		}
		for _, name := range append([]string{fields[0]}, fields[2:]...) {
			key := name + "/" + proto
			if _, exists := res[key]; !exists {
				res[key] = port
			}
		}
	}
	return res
}

// lookup resolves a service name for proto. A name without a protocol-specific
// entry falls back to the tcp entry, then the udp one.
func (s Services) lookup(name, proto string) (string, bool) {
	if s == nil {
		return "", false
	}
	for _, p := range []string{proto, "tcp", "udp"} {
		if p == "" {
			continue
		}
		if port, ok := s[name+"/"+p]; ok {
			return port, true
		}
	}
	return "", false
}

// normalizePort resolves service names in a port expression to numbers and
// drops the `=` of an equality match, so `= ssh` reads "22". Every other
// expression keeps its operator: "!= 22", "> 1024", "6000:6010",
// "1000 >< 2000". A name with no entry in services stays as printed.
func (s Services) normalizePort(expr, proto string) string {
	if expr == "" {
		return ""
	}
	parts := strings.Fields(expr)
	for i, p := range parts {
		if portOps[p] || p == "><" || p == "<>" || isNumericOrRange(p) {
			continue
		}
		if port, ok := s.lookup(p, proto); ok {
			parts[i] = port
		}
	}
	if len(parts) == 2 && parts[0] == "=" && isNumericOrRange(parts[1]) {
		return parts[1]
	}
	return strings.Join(parts, " ")
}

func isNumericOrRange(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && c != ':' {
			return false
		}
	}
	return s != ""
}
