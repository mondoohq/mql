// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshclient

import (
	"strings"
)

// KnownHost is one line of a known_hosts file.
type KnownHost struct {
	// Hosts as written: names, addresses, patterns, or [host]:port. Empty
	// when the names are hashed.
	Hosts []string
	// Hashed is true for an entry written with HashKnownHosts, whose host
	// names can't be read back.
	Hashed bool
	// Marker is "cert-authority", "revoked", or empty.
	Marker  string
	KeyType string
	// Key is the base64 public key.
	Key     string
	Comment string
	Line    int
}

// KnownHostsResult is a parsed known_hosts file. Lines that aren't entries
// are skipped and counted, so a damaged line can't hide the rest.
type KnownHostsResult struct {
	Entries    []KnownHost
	Unreadable int
}

// ParseKnownHosts parses the content of a known_hosts file.
func ParseKnownHosts(content string) KnownHostsResult {
	var res KnownHostsResult
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		e := KnownHost{Line: i + 1}
		if strings.HasPrefix(fields[0], "@") {
			e.Marker = strings.TrimPrefix(fields[0], "@")
			fields = fields[1:]
		}
		if len(fields) < 3 {
			res.Unreadable++
			continue
		}
		if strings.HasPrefix(fields[0], "|1|") {
			e.Hashed = true
			e.Hosts = []string{}
		} else {
			e.Hosts = strings.Split(fields[0], ",")
		}
		e.KeyType = fields[1]
		e.Key = fields[2]
		if len(fields) > 3 {
			e.Comment = strings.Join(fields[3:], " ")
		}
		res.Entries = append(res.Entries, e)
	}
	return res
}
