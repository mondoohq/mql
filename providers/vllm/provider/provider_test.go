// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/vllm/connection"
)

func TestParseCLINormalizesEndpointAndCredentials(t *testing.T) {
	svc := Init()

	res, err := svc.ParseCLI(&plugin.ParseCLIReq{
		Connector: "vllm",
		Args:      []string{"vllm.example.com:8000/"},
		Flags: map[string]*llx.Primitive{
			connection.OptionAPIKey: llx.StringPrimitive("test-token"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Asset == nil {
		t.Fatal("expected asset")
	}
	if len(res.Asset.Connections) != 1 {
		t.Fatalf("connections length = %d, want 1", len(res.Asset.Connections))
	}

	conf := res.Asset.Connections[0]
	if got, want := conf.Options[connection.OptionBaseURL], "http://vllm.example.com:8000"; got != want {
		t.Fatalf("base URL = %q, want %q", got, want)
	}
	if got, want := conf.Host, "vllm.example.com"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got, want := conf.Port, int32(8000); got != want {
		t.Fatalf("port = %d, want %d", got, want)
	}
	if len(conf.Credentials) != 1 {
		t.Fatalf("credentials length = %d, want 1", len(conf.Credentials))
	}
	if conf.Credentials[0].Type != vault.CredentialType_password {
		t.Fatalf("credential type = %s, want password", conf.Credentials[0].Type)
	}
	if got := string(conf.Credentials[0].Secret); got != "test-token" {
		t.Fatalf("credential secret = %q, want test-token", got)
	}
}

func TestParseCLIRejectsUnsupportedScheme(t *testing.T) {
	svc := Init()

	_, err := svc.ParseCLI(&plugin.ParseCLIReq{
		Connector: "vllm",
		Args:      []string{"ssh://vllm.example.com"},
	})
	if err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}
