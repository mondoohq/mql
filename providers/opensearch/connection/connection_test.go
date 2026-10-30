// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func newTestConn(t *testing.T, opts map[string]string) *OpensearchConnection {
	t.Helper()
	if opts == nil {
		opts = map[string]string{}
	}
	if opts[OptionHost] == "" {
		opts[OptionHost] = "os.example.com"
	}
	conf := &inventory.Config{Type: "opensearch", Options: opts}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := NewOpensearchConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("NewOpensearchConnection: %v", err)
	}
	return conn
}

func TestAddressDefaults(t *testing.T) {
	// Default scheme https and port 9200.
	if got := newTestConn(t, nil).address(); got != "https://os.example.com:9200" {
		t.Errorf("address = %q", got)
	}
	c := newTestConn(t, map[string]string{OptionScheme: "http", OptionPort: "9201"})
	if got := c.address(); got != "http://os.example.com:9201" {
		t.Errorf("address = %q", got)
	}
}

func TestServerID(t *testing.T) {
	if got := newTestConn(t, map[string]string{OptionPort: "9250"}).ServerID(); got != "os.example.com:9250" {
		t.Errorf("ServerID = %q", got)
	}
}

func TestPermissionError(t *testing.T) {
	err := &PermissionError{Path: "/_plugins/_security/api/roles", StatusCode: 403}
	if !IsPermissionError(err) {
		t.Error("PermissionError should be classified as a permission error")
	}
	if IsPermissionError(errors.New("boom")) {
		t.Error("a plain error is not a permission error")
	}
	if IsPermissionError(nil) {
		t.Error("nil is not a permission error")
	}
}
