// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func newTestConn(t *testing.T, opts map[string]string) *ClickhousedbConnection {
	t.Helper()
	if opts == nil {
		opts = map[string]string{}
	}
	if opts[OptionHost] == "" {
		opts[OptionHost] = "ch.example.com"
	}
	conf := &inventory.Config{
		Type:        "clickhousedb",
		Options:     opts,
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "")},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := NewClickhousedbConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("NewClickhousedbConnection: %v", err)
	}
	return conn
}

func TestServerIDAndDefaults(t *testing.T) {
	c := newTestConn(t, nil)
	if got := c.ServerID(); got != "ch.example.com:9000" {
		t.Errorf("ServerID = %q", got)
	}
	if c.database != "default" {
		t.Errorf("default database = %q, want default", c.database)
	}
	if c.user != "default" {
		t.Errorf("default user = %q, want default", c.user)
	}
	p := newTestConn(t, map[string]string{OptionPort: "9440"})
	if got := p.ServerID(); got != "ch.example.com:9440" {
		t.Errorf("ServerID (port) = %q", got)
	}
}

func TestMissingHostErrors(t *testing.T) {
	conf := &inventory.Config{Type: "clickhousedb", Options: map[string]string{}}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	if _, err := NewClickhousedbConnection(1, asset, conf); err == nil {
		t.Error("expected an error when host is not set")
	}
}

func TestIsPermissionError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("code: 497, message: ... ACCESS_DENIED: ..."), true},
		{errors.New("Not enough privileges to read system.users"), true},
		{errors.New("code: 210, message: Connection refused"), false},
		{errors.New("network down"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := IsPermissionError(c.err); got != c.want {
			t.Errorf("IsPermissionError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestIsUnknownPortError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			"tls disabled, the case this exists for",
			errors.New("code: 701, message: There is no port named tcp_port_secure: In scope SELECT getServerPort('tcp_port_secure')"),
			true,
		},
		// Code 701 is shared with cluster lookups, so the code alone must not
		// be enough to read a real failure as "not configured".
		{"a genuine cluster failure", errors.New("code: 701, message: Requested cluster 'x' not found"), false},
		{"unrelated failure", errors.New("code: 497, message: ACCESS_DENIED"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := IsUnknownPortError(c.err); got != c.want {
			t.Errorf("%s: IsUnknownPortError(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

func TestIsAccessDenied(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		// captured live from ClickHouse 26.9 as a user without the grant
		{errors.New("code: 497, message: nopriv: Not enough privileges. To execute this query, it's necessary to have the grant SELECT ON system.users"), true},
		{errors.New("code: 492, message: There is no role `x` in user directories"), false},
		{errors.New("code: 516, message: nopriv: Authentication failed: password is incorrect, or there is no user with such name"), false},
		{errors.New("dial tcp 192.0.2.10:9000: connect: connection refused"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := IsAccessDenied(c.err); got != c.want {
			t.Errorf("IsAccessDenied(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
