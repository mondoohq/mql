// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/elasticsearch/connection"
)

// newIntegrationRuntime connects to a live Elasticsearch cluster described by
// the ES_TEST_* environment, or skips when it is not configured.
//
//	ES_TEST_HOST      host or host:port (default port 9200)
//	ES_TEST_SCHEME    http or https (default http for the test container)
//	ES_TEST_USER      user (default "elastic")
//	ES_TEST_PASSWORD  password (required)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("ES_TEST_HOST")
	password := os.Getenv("ES_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set ES_TEST_HOST and ES_TEST_PASSWORD to run elasticsearch integration tests")
	}
	user := os.Getenv("ES_TEST_USER")
	if user == "" {
		user = "elastic"
	}

	options := map[string]string{"scheme": "http"}
	if s := os.Getenv("ES_TEST_SCHEME"); s != "" {
		options["scheme"] = s
	}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid ES_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:        "elasticsearch",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(user, password)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewElasticsearchConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustCluster(t *testing.T, runtime *plugin.Runtime) *mqlElasticsearchCluster {
	res, err := NewResource(runtime, "elasticsearch.cluster", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve elasticsearch.cluster: %v", err)
	}
	return res.(*mqlElasticsearchCluster)
}

func resolveList(t *testing.T, label string, tv *plugin.TValue[[]any]) []any {
	t.Helper()
	if tv.Error != nil {
		t.Errorf("%s errored: %v", label, tv.Error)
		return nil
	}
	return tv.Data
}

func TestIntegrationCluster(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))
	if v := c.GetVersion(); v.Error != nil || v.Data == "" {
		t.Errorf("version = %q (err=%v)", v.Data, v.Error)
	}
	if v := c.GetDistribution(); v.Error != nil || v.Data != "elasticsearch" {
		t.Errorf("distribution = %q (err=%v), want elasticsearch", v.Data, v.Error)
	}
	sec := c.GetSecurity()
	if sec.Error != nil {
		t.Fatalf("security errored: %v", sec.Error)
	}
	if v := sec.Data.GetEnabled(); v.Error != nil {
		t.Errorf("security.enabled errored: %v", v.Error)
	}
}

// TestIntegrationResolveAll walks every resource and field getter.
func TestIntegrationResolveAll(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))

	for _, x := range resolveList(t, "users", c.GetUsers()) {
		u := x.(*mqlElasticsearchUser)
		if v := u.GetName(); v.Error != nil || v.Data == "" {
			t.Errorf("user.name = %q (err=%v)", v.Data, v.Error)
		}
	}
	for _, x := range resolveList(t, "roles", c.GetRoles()) {
		role := x.(*mqlElasticsearchRole)
		resolveList(t, "role.indexPrivileges", role.GetIndexPrivileges())
	}
	resolveList(t, "roleMappings", c.GetRoleMappings())
	resolveList(t, "apiKeys", c.GetApiKeys())
}

// TestIntegrationSeededFixtures verifies values seeded by testdata/seed.sh.
// Enable it with ES_TEST_SEEDED=1 after running the seed.
func TestIntegrationSeededFixtures(t *testing.T) {
	if os.Getenv("ES_TEST_SEEDED") == "" {
		t.Skip("set ES_TEST_SEEDED=1 after running testdata/seed.sh")
	}
	c := mustCluster(t, newIntegrationRuntime(t))

	// The built-in elastic user is reserved; the seeded appuser is not.
	users := map[string]*mqlElasticsearchUser{}
	for _, x := range c.GetUsers().Data {
		u := x.(*mqlElasticsearchUser)
		users[u.GetName().Data] = u
	}
	if u := users["elastic"]; u == nil || !u.GetIsReserved().Data {
		t.Error("elastic should be a reserved user")
	}
	appuser := users["appuser"]
	if appuser == nil {
		t.Fatal("seeded appuser not found")
	}
	if appuser.GetIsReserved().Data {
		t.Error("appuser should not be reserved")
	}

	// The seeded reader role is custom and scoped to logs-* read.
	var reader *mqlElasticsearchRole
	for _, x := range c.GetRoles().Data {
		if r := x.(*mqlElasticsearchRole); r.GetName().Data == "reader" {
			reader = r
		}
	}
	if reader == nil {
		t.Fatal("seeded reader role not found")
	}
	if reader.GetIsReserved().Data {
		t.Error("reader should be a custom (non-reserved) role")
	}
	idx := reader.GetIndexPrivileges().Data
	if len(idx) != 1 {
		t.Fatalf("reader should have 1 index privilege, got %d", len(idx))
	}
	ip := idx[0].(*mqlElasticsearchRoleIndexPrivilege)
	names := ip.GetNames().Data
	if len(names) != 1 || names[0] != "logs-*" {
		t.Errorf("reader index names = %v, want [logs-*]", names)
	}

	// The seeded ci-key has an expiration; posture query for never-expiring keys
	// must not include it.
	for _, x := range c.GetApiKeys().Data {
		k := x.(*mqlElasticsearchApiKey)
		if k.GetName().Data == "ci-key" && k.GetNeverExpires().Data {
			t.Error("ci-key was created with an expiration, should not be neverExpires")
		}
	}
}
