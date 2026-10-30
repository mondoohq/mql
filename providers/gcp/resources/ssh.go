// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/sshutil"
)

// parseInstanceSSHKeys turns the GCE instance metadata `ssh-keys` value into
// one dict per configured key. Each metadata line has the form
// `<username>:<openssh-public-key>`; unparseable lines are skipped.
func parseInstanceSSHKeys(raw string) []any {
	out := []any{}
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// A metadata line is `<username>:<key>`. The key itself never
		// contains a colon before its first space, so split on the first
		// colon to peel off the username, then parse the remainder as an
		// authorized key.
		username, keyPart, found := strings.Cut(line, ":")
		if !found {
			username, keyPart = "", line
		}
		algorithm, bits, comment, ok := sshutil.ParseAuthorizedKey(keyPart)
		if !ok {
			continue
		}
		out = append(out, map[string]any{
			"username":  username,
			"algorithm": algorithm,
			"bits":      bits,
			"publicKey": strings.TrimSpace(keyPart),
			"comment":   comment,
		})
	}
	return out
}
