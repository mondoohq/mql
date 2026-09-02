// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestRequiresCredential(t *testing.T) {
	cases := []struct {
		name      string
		authTypes []string
		want      bool
	}{
		{"password only", []string{"sha256_password"}, true},
		{"no_password only", []string{"no_password"}, false},
		// ClickHouse admits a login if any method matches, so a no_password entry
		// alongside a real credential still means the account is reachable without one.
		{"mixed with no_password", []string{"sha256_password", "no_password"}, false},
		{"multiple real methods", []string{"sha256_password", "ldap"}, true},
		// An empty method list is anomalous; treated defensively as requiring a credential.
		{"empty", nil, true},
	}
	for _, c := range cases {
		if got := requiresCredential(c.authTypes); got != c.want {
			t.Errorf("%s: requiresCredential(%v) = %v, want %v", c.name, c.authTypes, got, c.want)
		}
	}
}

// TestAllowsAnyHost covers the three columns ClickHouse gates connection origin
// on. Each is checked on its own, because the regression this guards against is
// an account that is genuinely narrow in one column and open in another: reading
// only host_ip reported such an account as restricted.
func TestAllowsAnyHost(t *testing.T) {
	// A narrow IP list, used to prove that an open name pattern is enough on its
	// own and that a narrow one leaves the verdict alone.
	narrowIP := []string{"10.0.0.1"}

	cases := []struct {
		name            string
		hostIps         []string
		hostNamesRegexp []string
		hostNamesLike   []string
		want            bool
	}{
		// host_ip
		{"ipv6 any", []string{"::/0"}, nil, nil, true},
		{"ipv4 any", []string{"0.0.0.0/0"}, nil, nil, true},
		{"narrow range", []string{"10.0.0.0/8"}, nil, nil, false},
		{"narrow range beside any", []string{"10.0.0.0/8", "::/0"}, nil, nil, true},

		// host_names_regexp, the case the fix is about: ClickHouse admits the
		// connection if any list matches, so an open expression beats a narrow IP.
		{"regexp any", narrowIP, []string{".*"}, nil, true},
		{"regexp any anchored", narrowIP, []string{"^.*$"}, nil, true},
		{"regexp one or more", narrowIP, []string{".+"}, nil, true},
		{"regexp non-greedy any", narrowIP, []string{".*?"}, nil, true},
		{"regexp grouped any", narrowIP, []string{"(.*)"}, nil, true},
		{"regexp any beside a domain", narrowIP, []string{`.*\.corp\.example\.com`, ".*"}, nil, true},
		// A domain-scoped expression is a real restriction and must not be read
		// as open, or every host-restricted account reports as internet-facing.
		{"regexp scoped to a domain", narrowIP, []string{`.*\.corp\.example\.com`}, nil, false},
		{"regexp anchored to a domain", narrowIP, []string{`^web[0-9]+\.example\.com$`}, nil, false},
		{"regexp empty pattern matches only the empty name", narrowIP, []string{""}, nil, false},

		// host_names_like
		{"like single percent", narrowIP, nil, []string{"%"}, true},
		{"like repeated percent", narrowIP, nil, []string{"%%"}, true},
		{"like scoped to a domain", narrowIP, nil, []string{"%.corp.example.com"}, false},
		// "_" stands for exactly one character, so it is a restriction even when
		// the rest of the pattern is "%".
		{"like with a single-character wildcard", narrowIP, nil, []string{"%_%"}, false},
		{"like empty pattern", narrowIP, nil, []string{""}, false},
		{"like any beside a domain", narrowIP, nil, []string{"%.corp.example.com", "%"}, true},

		// Every column empty. A user with no host entries at all is not open;
		// reporting true here would flag the whole server.
		{"all columns empty", nil, nil, nil, false},
		{"all columns present and narrow", narrowIP, []string{`.*\.corp\.example\.com`}, []string{"%.corp.example.com"}, false},
	}
	for _, c := range cases {
		got := allowsAnyHost(c.hostIps, c.hostNamesRegexp, c.hostNamesLike)
		if got != c.want {
			t.Errorf("%s: allowsAnyHost(%v, %v, %v) = %v, want %v",
				c.name, c.hostIps, c.hostNamesRegexp, c.hostNamesLike, got, c.want)
		}
	}
}

func TestMatchesAnyHostName(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{".*", true},
		{"^.*$", true},
		{"^.*", true},
		{".*$", true},
		{".+", true},
		{"^.+$", true},
		{".*?", true},
		{".+?", true},
		{"(.*)", true},
		{"(.+)", true},
		{`[\s\S]*`, true},
		{`[\s\S]+`, true},
		{`^[\s\S]+$`, true},
		{"", false},
		{"^$", false},
		{"a.*", false},
		{".*a", false},
		{`.*\.example\.com`, false},
		{"[a-z]+", false},
	}
	for _, c := range cases {
		if got := matchesAnyHostName(c.expr); got != c.want {
			t.Errorf("matchesAnyHostName(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestLikeMatchesAnyHostName(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"%", true},
		{"%%", true},
		{"%%%", true},
		{"", false},
		{"_", false},
		{"%_%", false},
		{"%.example.com", false},
		{"host1.example.com", false},
	}
	for _, c := range cases {
		if got := likeMatchesAnyHostName(c.pattern); got != c.want {
			t.Errorf("likeMatchesAnyHostName(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

// TestStringList covers the two shapes system.users.auth_type actually takes:
// a scalar Enum8 up to the 24.8 LTS line, and an Array(Enum8) from 25.x. The
// error cases matter as much as the happy ones -- an unrecognised shape read as
// an empty list would make requiresCredential report a password-less account as
// requiring a credential.
func TestStringList(t *testing.T) {
	cases := []struct {
		name    string
		in      any
		want    []string
		wantErr bool
	}{
		{"array, as 25.x returns it", []string{"sha256_password"}, []string{"sha256_password"}, false},
		{"array with several methods", []string{"sha256_password", "kerberos"}, []string{"sha256_password", "kerberos"}, false},
		{"scalar, as 24.8 returns it", "plaintext_password", []string{"plaintext_password"}, false},
		{"empty scalar is no entry", "", nil, false},
		{"nil column", nil, nil, false},
		{"driver any-slice", []any{"no_password"}, []string{"no_password"}, false},
		{"empty array stays empty", []string{}, []string{}, false},
		{"unknown type errors rather than reading as empty", 42, nil, true},
		{"mixed any-slice errors", []any{"ldap", 7}, nil, true},
	}
	for _, c := range cases {
		got, err := stringList("auth_type", c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: stringList(%v) error = %v, wantErr %v", c.name, c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: stringList(%v) = %v, want %v", c.name, c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: stringList(%v) = %v, want %v", c.name, c.in, got, c.want)
				break
			}
		}
	}
}
