// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
)

func TestBindsAll(t *testing.T) {
	cases := []struct {
		bind []string
		want bool
	}{
		{nil, true},                            // no bind configured => all interfaces
		{[]string{}, true},                     // empty => all interfaces
		{[]string{"127.0.0.1", "-::1"}, false}, // loopback only
		{[]string{"0.0.0.0"}, true},            // wildcard
		{[]string{"127.0.0.1", "0.0.0.0"}, true},
		{[]string{"*"}, true},
		{[]string{"10.0.0.5"}, false},
		// the optional "-" prefix still binds the address when it exists;
		// both were seen listening on all interfaces in ss
		{[]string{"127.0.0.1", "-::*"}, true},
		{[]string{"-0.0.0.0"}, true},
		{[]string{"-::1"}, false},
	}
	for _, c := range cases {
		if got := bindsAll(c.bind); got != c.want {
			t.Errorf("bindsAll(%v) = %v, want %v", c.bind, got, c.want)
		}
	}
}

func TestIsNoPerm(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("NOPERM this user has no permissions to run the 'config|get' command"), true},
		{errors.New("WRONGPASS invalid username-password pair"), true},
		{errors.New("connection refused"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := isNoPerm(c.err); got != c.want {
			t.Errorf("isNoPerm(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestAtoiOr(t *testing.T) {
	if got := atoiOr("6379", 0); got != 6379 {
		t.Errorf("atoiOr(6379) = %d", got)
	}
	if got := atoiOr("", 42); got != 42 {
		t.Errorf("atoiOr(empty) = %d, want 42", got)
	}
	if got := atoiOr("notanumber", 7); got != 7 {
		t.Errorf("atoiOr(bad) = %d, want 7", got)
	}
}

// ACL GETUSER default replies captured from live servers (RESP2 arrays).
func TestDefaultUserRequiresAuth(t *testing.T) {
	cases := []struct {
		name     string
		reply    any
		ok       bool
		required bool
	}{
		{
			// Redis 6.2 after "ACL SETUSER default nopass": requirepass still
			// reads Db4-legacy-pw, yet an unauthenticated PING gets PONG
			name:     "6.2 default nopass with requirepass left set",
			reply:    resp2("flags", []any{"on", "allkeys", "allchannels", "allcommands", "nopass"}, "passwords", []any{}, "commands", "+@all", "keys", []any{"*"}, "channels", []any{"*"}),
			ok:       true,
			required: false,
		},
		{
			name:     "6.2 default with the requirepass password",
			reply:    resp2("flags", []any{"on", "allkeys", "allchannels", "allcommands"}, "passwords", []any{hashDecafbad}, "commands", "+@all", "keys", []any{"*"}, "channels", []any{"*"}),
			ok:       true,
			required: true,
		},
		{
			// Redis 7.2 with the default user's password in the ACL file and
			// requirepass empty: unauthenticated PING gets NOAUTH
			name:     "7.2 aclfile default password",
			reply:    resp2("flags", []any{"on", "sanitize-payload"}, "passwords", []any{hashDecafbad}, "commands", "+@all", "keys", "~*", "channels", "&*", "selectors", []any{}),
			ok:       true,
			required: true,
		},
		{
			// Valkey 8.1 with "user default off": NOAUTH for everyone
			name:     "valkey 8.1 default off",
			reply:    resp2("flags", []any{"off"}, "passwords", []any{}, "commands", "-@all", "keys", "", "channels", "&*", "selectors", []any{}),
			ok:       true,
			required: true,
		},
		{
			// Redis 8.2 out of the box: PONG without credentials
			name:     "8.2 default on nopass",
			reply:    resp2("flags", []any{"on", "nopass", "sanitize-payload"}, "passwords", []any{}, "commands", "+@all", "keys", "~*", "channels", "&*", "selectors", []any{}),
			ok:       true,
			required: false,
		},
		{
			// a disabled nopass default user still serves nobody
			name:     "default off nopass",
			reply:    resp3("flags", []any{"off", "nopass"}, "passwords", []any{}),
			ok:       true,
			required: true,
		},
		{name: "nil reply", reply: nil, ok: false},
		{name: "not a user", reply: "OK", ok: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			required, ok := defaultUserRequiresAuth(c.reply)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && required != c.required {
				t.Errorf("required = %v, want %v", required, c.required)
			}
		})
	}
}
