// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func newTestConn(t *testing.T, opts map[string]string) *CassandraConnection {
	t.Helper()
	if opts == nil {
		opts = map[string]string{}
	}
	if opts[OptionHost] == "" {
		opts[OptionHost] = "cass.example.com"
	}
	conf := &inventory.Config{Type: "cassandra", Options: opts}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := NewCassandraConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("NewCassandraConnection: %v", err)
	}
	return conn
}

func TestServerID(t *testing.T) {
	if got := newTestConn(t, nil).ServerID(); got != "cass.example.com:9042" {
		t.Errorf("ServerID = %q, want cass.example.com:9042", got)
	}
	if got := newTestConn(t, map[string]string{OptionPort: "9142"}).ServerID(); got != "cass.example.com:9142" {
		t.Errorf("ServerID = %q, want cass.example.com:9142", got)
	}
}

func TestMissingHostErrors(t *testing.T) {
	conf := &inventory.Config{Type: "cassandra", Options: map[string]string{}}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	if _, err := NewCassandraConnection(1, asset, conf); err == nil {
		t.Error("expected an error for a missing host")
	}
}

// fakeRequestError implements gocql.RequestError with a given code.
type fakeRequestError struct{ code int }

func (e fakeRequestError) Code() int       { return e.code }
func (e fakeRequestError) Message() string { return "boom" }
func (e fakeRequestError) Error() string   { return "boom" }

func TestIsUnauthorized(t *testing.T) {
	if !IsUnauthorized(fakeRequestError{code: cqlErrCodeUnauthorized}) {
		t.Error("a 0x2100 request error should be unauthorized")
	}
	if IsUnauthorized(fakeRequestError{code: 0x2200}) {
		t.Error("a non-0x2100 request error should not be unauthorized")
	}
	if IsUnauthorized(errors.New("network down")) {
		t.Error("a plain error should not be unauthorized")
	}
	if IsUnauthorized(nil) {
		t.Error("nil should not be unauthorized")
	}
}
