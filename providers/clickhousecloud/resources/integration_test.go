// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/clickhousecloud/connection"
)

// newIntegrationRuntime connects to a live ClickHouse Cloud organization
// described by the CLICKHOUSE_CLOUD_TEST_* environment, or skips when it is not
// configured.
//
//	CLICKHOUSE_CLOUD_TEST_ORG      organization ID (required)
//	CLICKHOUSE_CLOUD_TEST_KEY      API key id (required)
//	CLICKHOUSE_CLOUD_TEST_SECRET   API key secret (required)
//	CLICKHOUSE_CLOUD_TEST_API_URL  optional API base URL override
//	CLICKHOUSE_CLOUD_TEST_SERVICE  optional service id the seeded test asserts
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	org := os.Getenv("CLICKHOUSE_CLOUD_TEST_ORG")
	key := os.Getenv("CLICKHOUSE_CLOUD_TEST_KEY")
	secret := os.Getenv("CLICKHOUSE_CLOUD_TEST_SECRET")
	if org == "" || key == "" || secret == "" {
		t.Skip("set CLICKHOUSE_CLOUD_TEST_ORG, _KEY and _SECRET to run clickhousecloud integration tests")
	}

	options := map[string]string{"organization-id": org}
	if u := os.Getenv("CLICKHOUSE_CLOUD_TEST_API_URL"); u != "" {
		options["api-url"] = u
	}
	conf := &inventory.Config{
		Type:        "clickhousecloud",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(key, secret)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewClickhousecloudConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustOrg(t *testing.T, runtime *plugin.Runtime) *mqlClickhousecloudOrganization {
	res, err := NewResource(runtime, "clickhousecloud.organization", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve clickhousecloud.organization: %v", err)
	}
	return res.(*mqlClickhousecloudOrganization)
}

func resolveList(t *testing.T, label string, tv *plugin.TValue[[]any]) []any {
	t.Helper()
	if tv.Error != nil {
		t.Errorf("%s errored: %v", label, tv.Error)
		return nil
	}
	return tv.Data
}

func TestIntegrationOrganization(t *testing.T) {
	org := mustOrg(t, newIntegrationRuntime(t))
	if v := org.GetId(); v.Error != nil || v.Data == "" {
		t.Errorf("org id = %q (err=%v)", v.Data, v.Error)
	}
}

// TestIntegrationResolveAll walks every resource and field getter.
func TestIntegrationResolveAll(t *testing.T) {
	org := mustOrg(t, newIntegrationRuntime(t))

	resolveList(t, "members", org.GetMembers())
	resolveList(t, "apiKeys", org.GetApiKeys())

	wantService := os.Getenv("CLICKHOUSE_CLOUD_TEST_SERVICE")
	foundService := false
	for _, x := range resolveList(t, "services", org.GetServices()) {
		s := x.(*mqlClickhousecloudService)
		if v := s.GetName(); v.Error != nil || v.Data == "" {
			t.Errorf("service.name = %q (err=%v)", v.Data, v.Error)
		}
		if s.GetId().Data == wantService {
			foundService = true
		}
		resolveList(t, "service.ipAccessList", s.GetIpAccessList())
		resolveList(t, "service.endpoints", s.GetEndpoints())
		if v := s.GetOpenToAllIps(); v.Error != nil {
			t.Errorf("service.openToAllIps errored: %v", v.Error)
		}
	}
	if wantService != "" && !foundService {
		t.Errorf("expected service %q was not found", wantService)
	}
}
