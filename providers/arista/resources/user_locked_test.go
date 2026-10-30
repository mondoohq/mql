// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func tstr(v string) plugin.TValue[string] {
	return plugin.TValue[string]{Data: v, State: plugin.StateIsSet}
}

// TestUserLocked pins the predicate against the values `nopassword` actually
// carries. It is the string "true" or "false"; comparing it against the
// keyword "nopassword" is a comparison that can never hold, so locked() read
// false for every account on every device and an audit hunting credential-less
// accounts reported "none found" as a fact.
func TestUserLocked(t *testing.T) {
	for _, tc := range []struct {
		name       string
		nopassword string
		secret     string
		sshkey     string
		want       bool
	}{
		{"nopassword and no key is locked", "true", "", "", true},
		{"nopassword but an ssh key still authenticates", "true", "", "ssh-rsa AAAA", false},
		{"a secret means the account can log in", "false", "$6$salt$hash", "", false},
		{"a password-protected account is not locked", "false", "$6$salt$hash", "ssh-rsa AAAA", false},
		{"no password and no key, keyword absent", "false", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &mqlAristaEosUser{
				Nopassword: tstr(tc.nopassword),
				Secret:     tstr(tc.secret),
				Sshkey:     tstr(tc.sshkey),
			}
			got, err := u.locked()
			if err != nil {
				t.Fatalf("locked: %v", err)
			}
			if got != tc.want {
				t.Fatalf("locked = %v, want %v", got, tc.want)
			}
		})
	}
}
