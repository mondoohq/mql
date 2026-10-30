// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/redfish/connection"
)

func TestParseCLI(t *testing.T) {
	s := Init()

	t.Run("user, host and explicit port", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Connector: "redfish",
			Args:      []string{"admin@10.0.0.5:8443"},
			Flags:     map[string]*llx.Primitive{"password": llx.StringPrimitive("secret")},
		})
		if err != nil {
			t.Fatal(err)
		}
		conf := res.Asset.Connections[0]
		if conf.Host != "10.0.0.5" {
			t.Errorf("host = %q, want 10.0.0.5", conf.Host)
		}
		if conf.Port != 8443 {
			t.Errorf("port = %d, want 8443", conf.Port)
		}
		if len(conf.Credentials) != 1 || conf.Credentials[0].User != "admin" {
			t.Errorf("expected credential for user admin, got %+v", conf.Credentials)
		}
	})

	t.Run("defaults to port 443", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Connector: "redfish",
			Args:      []string{"admin@bmc.example.com"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Asset.Connections[0].Port; got != connection.DefaultPort {
			t.Errorf("port = %d, want %d", got, connection.DefaultPort)
		}
	})

	t.Run("insecure flag", func(t *testing.T) {
		res, err := s.ParseCLI(&plugin.ParseCLIReq{
			Connector: "redfish",
			Args:      []string{"admin@host"},
			Flags:     map[string]*llx.Primitive{"insecure": llx.BoolPrimitive(true)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.Asset.Connections[0].Options["insecure"] != "true" {
			t.Errorf("expected insecure=true option, got %v", res.Asset.Connections[0].Options)
		}
	})

	t.Run("rejects invalid port", func(t *testing.T) {
		if _, err := s.ParseCLI(&plugin.ParseCLIReq{
			Connector: "redfish",
			Args:      []string{"admin@host:0"},
		}); err == nil {
			t.Error("expected error for port 0, got nil")
		}
		if _, err := s.ParseCLI(&plugin.ParseCLIReq{
			Connector: "redfish",
			Args:      []string{"admin@host:99999"},
		}); err == nil {
			t.Error("expected error for out-of-range port, got nil")
		}
	})
}
