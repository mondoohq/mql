// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"bufio"
	"strings"
)

// TrustchkCommand prints every Trusted Execution policy attribute, one per
// line, the path policies (TEP, TLP) both as their state and their path.
var TrustchkCommand = "for a in te sig_ver chkexec chkshlib chkscript chkkernext stop_untrustd stop_on_chkfail lock_kern_policies tep tlp; do trustchk -p $a 2>&1; done"

// TrustchkPolicy is the Trusted Execution policy.
type TrustchkPolicy struct {
	// Values holds the state of each attribute, upper case key, lower case
	// value: TE=off, STOP_UNTRUSTD=trojan.
	Values map[string]string
	// Paths holds the directories of TEP and TLP.
	Paths map[string][]string
}

// ParseTrustchk reads `trustchk -p` output. An attribute prints as
// NAME=STATE; TEP and TLP print a second line, NAME=dir:dir:..., with their
// path.
func ParseTrustchk(out string) TrustchkPolicy {
	p := TrustchkPolicy{Values: map[string]string{}, Paths: map[string][]string{}}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			continue
		}
		key = strings.ToUpper(key)
		if strings.HasPrefix(value, "/") {
			p.Paths[key] = SplitPath(value)
			continue
		}
		p.Values[key] = strings.ToLower(strings.TrimSpace(value))
	}
	return p
}

// SplitPath splits a colon separated path list and drops empty items.
func SplitPath(v string) []string {
	res := []string{}
	for _, item := range strings.Split(v, ":") {
		if item = strings.TrimSpace(item); item != "" {
			res = append(res, item)
		}
	}
	return res
}
