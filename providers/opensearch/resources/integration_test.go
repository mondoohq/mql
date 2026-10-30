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
	"go.mondoo.com/mql/providers/opensearch/connection"
)

// newIntegrationRuntime connects to a live OpenSearch cluster described by the
// OS_TEST_* environment, or skips when it is not configured.
//
//	OS_TEST_HOST      host or host:port (default port 9200)
//	OS_TEST_SCHEME    http or https (default https)
//	OS_TEST_USER      user (default "admin")
//	OS_TEST_PASSWORD  password (required)
//	OS_TEST_INSECURE  "1" to skip TLS verification (self-signed demo cert)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("OS_TEST_HOST")
	password := os.Getenv("OS_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set OS_TEST_HOST and OS_TEST_PASSWORD to run opensearch integration tests")
	}
	user := os.Getenv("OS_TEST_USER")
	if user == "" {
		user = "admin"
	}

	options := map[string]string{"scheme": "https"}
	if s := os.Getenv("OS_TEST_SCHEME"); s != "" {
		options["scheme"] = s
	}
	if os.Getenv("OS_TEST_INSECURE") != "" {
		options["tls-insecure"] = "true"
	}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid OS_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:        "opensearch",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(user, password)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewOpensearchConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustCluster(t *testing.T, runtime *plugin.Runtime) *mqlOpensearchCluster {
	res, err := NewResource(runtime, "opensearch.cluster", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve opensearch.cluster: %v", err)
	}
	return res.(*mqlOpensearchCluster)
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
	if v := c.GetDistribution(); v.Error != nil || v.Data != "opensearch" {
		t.Errorf("distribution = %q (err=%v), want opensearch", v.Data, v.Error)
	}
	sec := c.GetSecurity()
	if sec.Error != nil {
		t.Fatalf("security errored: %v", sec.Error)
	}
	if v := sec.Data.GetAnonymousAccessEnabled(); v.Error != nil {
		t.Errorf("security.anonymousAccessEnabled errored: %v", v.Error)
	}
}

// TestIntegrationResolveAll walks every resource and field getter.
func TestIntegrationResolveAll(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))

	for _, x := range resolveList(t, "users", c.GetUsers()) {
		u := x.(*mqlOpensearchUser)
		if v := u.GetName(); v.Error != nil || v.Data == "" {
			t.Errorf("user.name = %q (err=%v)", v.Data, v.Error)
		}
	}
	for _, x := range resolveList(t, "roles", c.GetRoles()) {
		role := x.(*mqlOpensearchRole)
		resolveList(t, "role.indexPermissions", role.GetIndexPermissions())
	}
	resolveList(t, "roleMappings", c.GetRoleMappings())
}

// TestIntegrationSeededFixtures verifies values seeded by testdata/seed.sh.
// Enable it with OS_TEST_SEEDED=1 after running the seed.
func TestIntegrationSeededFixtures(t *testing.T) {
	if os.Getenv("OS_TEST_SEEDED") == "" {
		t.Skip("set OS_TEST_SEEDED=1 after running testdata/seed.sh")
	}
	c := mustCluster(t, newIntegrationRuntime(t))

	// The built-in admin user is reserved; the seeded appuser is not.
	users := map[string]*mqlOpensearchUser{}
	for _, x := range c.GetUsers().Data {
		u := x.(*mqlOpensearchUser)
		users[u.GetName().Data] = u
	}
	if u := users["admin"]; u == nil || !u.GetIsReserved().Data {
		t.Error("admin should be a reserved user")
	}
	appuser := users["appuser"]
	if appuser == nil {
		t.Fatal("seeded appuser not found")
	}
	if appuser.GetIsReserved().Data {
		t.Error("appuser should not be reserved")
	}

	// The seeded readers role is custom and scoped to logs-* read.
	var readers *mqlOpensearchRole
	for _, x := range c.GetRoles().Data {
		if r := x.(*mqlOpensearchRole); r.GetName().Data == "readers" {
			readers = r
		}
	}
	if readers == nil {
		t.Fatal("seeded readers role not found")
	}
	if readers.GetIsReserved().Data {
		t.Error("readers should be a custom (non-reserved) role")
	}
	idx := readers.GetIndexPermissions().Data
	if len(idx) != 1 {
		t.Fatalf("readers should have 1 index permission, got %d", len(idx))
	}
	ip := idx[0].(*mqlOpensearchRoleIndexPermission)
	patterns := ip.GetIndexPatterns().Data
	if len(patterns) != 1 || patterns[0] != "logs-*" {
		t.Errorf("readers index patterns = %v, want [logs-*]", patterns)
	}

	// The built-in all_access role grants cluster "*"; verify it is detected.
	var allAccess *mqlOpensearchRole
	for _, x := range c.GetRoles().Data {
		if r := x.(*mqlOpensearchRole); r.GetName().Data == "all_access" {
			allAccess = r
		}
	}
	if allAccess == nil {
		t.Fatal("built-in all_access role not found")
	}
	if !allAccess.GetIsReserved().Data {
		t.Error("all_access should be reserved")
	}
}
