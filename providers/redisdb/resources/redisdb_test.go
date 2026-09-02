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
