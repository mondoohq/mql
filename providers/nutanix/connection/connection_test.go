// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestNewNutanixConnection_MissingEndpoint(t *testing.T) {
	conf := &inventory.Config{Options: map[string]string{}}
	conf.Credentials = []*vault.Credential{vault.NewPasswordCredential("admin", "pw")}
	if _, err := NewNutanixConnection(1, &inventory.Asset{}, conf); err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func TestNewNutanixConnection_MissingCredentials(t *testing.T) {
	conf := &inventory.Config{Host: "pc.example.com", Options: map[string]string{}}
	if _, err := NewNutanixConnection(1, &inventory.Asset{}, conf); err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestNewNutanixConnection_InvalidPort(t *testing.T) {
	conf := &inventory.Config{
		Host:        "pc.example.com",
		Options:     map[string]string{"port": "not-a-number"},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("admin", "pw")},
	}
	if _, err := NewNutanixConnection(1, &inventory.Asset{}, conf); err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestNewNutanixConnection_BasicAuth(t *testing.T) {
	conf := &inventory.Config{
		Host:        "pc.example.com",
		Options:     map[string]string{},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("admin", "pw")},
	}
	conn, err := NewNutanixConnection(1, &inventory.Asset{}, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.Endpoint() != "pc.example.com" {
		t.Errorf("Endpoint() = %q, want pc.example.com", conn.Endpoint())
	}
	if conn.port != defaultPort {
		t.Errorf("port = %d, want %d", conn.port, defaultPort)
	}
	if conn.iamClient == nil || conn.netClient == nil || conn.cmgClient == nil || conn.vmmClient == nil {
		t.Error("expected all four SDK clients to be initialized")
	}
	if conn.cmgClient.Username != "admin" || conn.cmgClient.Password != "pw" {
		t.Error("basic auth not applied to client")
	}
}

func TestNewNutanixConnection_ApiKey(t *testing.T) {
	conf := &inventory.Config{
		Host:    "pc.example.com",
		Options: map[string]string{"api-key": "secret-key", "port": "9999"},
	}
	conn, err := NewNutanixConnection(1, &inventory.Asset{}, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.port != 9999 {
		t.Errorf("port = %d, want 9999", conn.port)
	}
	// API key auth should not set basic-auth username/password.
	if conn.cmgClient.Username != "" || conn.cmgClient.Password != "" {
		t.Error("api-key auth should not set username/password")
	}
}

func TestNewNutanixConnection_CredentialUserOverride(t *testing.T) {
	conf := &inventory.Config{
		Host:        "pc.example.com",
		Options:     map[string]string{"user": "fromflag"},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("fromcred", "pw")},
	}
	conn, err := NewNutanixConnection(1, &inventory.Asset{}, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.cmgClient.Username != "fromcred" {
		t.Errorf("username = %q, want fromcred (credential should override flag)", conn.cmgClient.Username)
	}
}
