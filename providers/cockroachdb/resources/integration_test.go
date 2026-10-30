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
	"go.mondoo.com/mql/providers/cockroachdb/connection"
)

// newIntegrationRuntime connects to a live, seeded CockroachDB cluster
// (testdata/seed.sh) described by the COCKROACHDB_TEST_* environment, or
// skips when it is not configured.
//
//	COCKROACHDB_TEST_HOST       host (port 26257 unless COCKROACHDB_TEST_PORT)
//	COCKROACHDB_TEST_CERTS_DIR  certificate directory with client.root.crt/.key
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("COCKROACHDB_TEST_HOST")
	certsDir := os.Getenv("COCKROACHDB_TEST_CERTS_DIR")
	if host == "" || certsDir == "" {
		t.Skip("set COCKROACHDB_TEST_HOST and COCKROACHDB_TEST_CERTS_DIR to run cockroachdb integration tests")
	}
	options := map[string]string{
		connection.OptionHost:     host,
		connection.OptionCertsDir: certsDir,
	}
	if port := os.Getenv("COCKROACHDB_TEST_PORT"); port != "" {
		options[connection.OptionPort] = port
	}
	conf := &inventory.Config{
		Type:        "cockroachdb",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential("root", "")},
	}
	conn, err := connection.NewCockroachdbConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustCluster(t *testing.T, runtime *plugin.Runtime) *mqlCockroachdbCluster {
	t.Helper()
	res, err := NewResource(runtime, "cockroachdb.cluster", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve cockroachdb.cluster: %v", err)
	}
	return res.(*mqlCockroachdbCluster)
}

func mustList(t *testing.T, label string, tv *plugin.TValue[[]any]) []any {
	t.Helper()
	if tv.Error != nil {
		t.Fatalf("%s errored: %v", label, tv.Error)
	}
	return tv.Data
}

func TestIntegrationCluster(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))
	if c.GetId().Data == "" || c.GetVersion().Data == "" || c.GetClusterVersion().Data == "" {
		t.Errorf("cluster id=%q version=%q clusterVersion=%q", c.GetId().Data, c.GetVersion().Data, c.GetClusterVersion().Data)
	}
	if v := c.GetInsecure(); v.Error != nil || v.Data {
		t.Errorf("insecure = %v (err=%v), want false on a secure cluster", v.Data, v.Error)
	}
	if n := len(mustList(t, "settings", c.GetSettings())); n < 100 {
		t.Errorf("settings: %d, want the full list", n)
	}
	rules := mustList(t, "hbaRules", c.GetHbaRules())
	if len(rules) != 4 || rules[3].(*mqlCockroachdbHbaRule).GetConnectionType().Data != "local" {
		t.Errorf("hbaRules: %d rules, want the 4 seeded", len(rules))
	}
}

func TestIntegrationRoles(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))
	byName := map[string]*mqlCockroachdbRole{}
	for _, r := range mustList(t, "roles", c.GetRoles()) {
		role := r.(*mqlCockroachdbRole)
		byName[role.GetName().Data] = role
	}
	for name, want := range map[string]struct {
		admin, login bool
		method       string
	}{
		"root":   {admin: true, login: true},
		"ops":    {admin: true},
		"nested": {admin: true},
		"app":    {login: true, method: "scram-sha-256"},
		"legacy": {login: true, method: "crdb-bcrypt"},
	} {
		r, ok := byName[name]
		if !ok {
			t.Errorf("role %q missing", name)
			continue
		}
		if r.GetIsAdmin().Data != want.admin || r.GetCanLogin().Data != want.login {
			t.Errorf("%s: isAdmin=%v canLogin=%v, want %v %v", name, r.GetIsAdmin().Data, r.GetCanLogin().Data, want.admin, want.login)
		}
		if got := r.GetPasswordHashMethod(); got.Error != nil || got.Data != want.method {
			t.Errorf("%s: passwordHashMethod=%q (err=%v), want %q", name, got.Data, got.Error, want.method)
		}
	}
	if app := byName["app"]; app != nil {
		defaults := app.GetDefaultSessionVariables().Data
		if defaults["idle_in_session_timeout"] != "15m" || defaults["statement_timeout"] != "1h" {
			t.Errorf("app defaults = %v", defaults)
		}
		if app.GetValidUntil().Data == nil {
			t.Error("app validUntil is null")
		}
	}
}

func TestIntegrationBackupSchedules(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))
	encrypted := map[string]bool{}
	for _, s := range mustList(t, "backupSchedules", c.GetBackupSchedules()) {
		sched := s.(*mqlCockroachdbBackupSchedule)
		encrypted[sched.GetLabel().Data] = sched.GetEncrypted().Data
	}
	if !encrypted["enc"] || encrypted["plain"] {
		t.Errorf("backup schedules encrypted = %v, want enc true and plain false", encrypted)
	}
}

func TestIntegrationNodes(t *testing.T) {
	c := mustCluster(t, newIntegrationRuntime(t))
	nodes := mustList(t, "nodes", c.GetNodes())
	if len(nodes) == 0 {
		t.Fatal("no nodes")
	}
	n := nodes[0].(*mqlCockroachdbNode)
	if len(mustList(t, "certificates", n.GetCertificates())) == 0 {
		t.Error("a secure node reports no certificates")
	}
	if len(mustList(t, "stores", n.GetStores())) == 0 {
		t.Error("node reports no stores")
	}
}
