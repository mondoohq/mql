// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/sshutil"
)

// parseAuthorizedKeys turns a newline-separated list of OpenSSH public keys
// (the format of the instance metadata `ssh_authorized_keys` value) into one
// dict per key. Blank and unparseable lines are skipped so weak-key audits
// only see keys whose algorithm and size are known.
func parseAuthorizedKeys(raw string) []any {
	out := []any{}
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		algorithm, bits, comment, ok := sshutil.ParseAuthorizedKey(line)
		if !ok {
			continue
		}
		out = append(out, map[string]any{
			"algorithm": algorithm,
			"bits":      bits,
			"publicKey": line,
			"comment":   comment,
		})
	}
	return out
}
