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
	"go.mondoo.com/mql/providers/yugabyte/connection"
)

// newIntegrationRuntime connects to a live YugabyteDB node described by the
// YUGABYTE_TEST_* environment, or skips when it is not configured. A
// single-node cluster in a container works:
//
//	docker run -d --name yb -p 17000:7000 -p 19000:9000 -p 15433:5433 -p 19042:9042 \
//	  yugabytedb/yugabyte:2025.2.8.1-b8 bin/yugabyted start --background=false
//	YUGABYTE_TEST_HOST=127.0.0.1 YUGABYTE_TEST_MASTER_HTTP_PORT=17000 \
//	  YUGABYTE_TEST_TSERVER_HTTP_PORT=19000 YUGABYTE_TEST_YSQL_PORT=15433 \
//	  YUGABYTE_TEST_YCQL_PORT=19042 go test ./resources/ -run Integration
//
// YUGABYTE_PASSWORD supplies the password of a cluster with authentication,
// YUGABYTE_YCQL_PASSWORD the YCQL password when it differs.
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("YUGABYTE_TEST_HOST")
	if host == "" {
		t.Skip("set YUGABYTE_TEST_HOST to run yugabyte integration tests")
	}
	options := map[string]string{connection.OptionHost: host}
	for env, option := range map[string]string{
		"YUGABYTE_TEST_MASTER_HTTP_PORT":  connection.OptionMasterHTTPPort,
		"YUGABYTE_TEST_TSERVER_HTTP_PORT": connection.OptionTserverHTTPPort,
		"YUGABYTE_TEST_YSQL_PORT":         connection.OptionYSQLPort,
		"YUGABYTE_TEST_YCQL_PORT":         connection.OptionYCQLPort,
	} {
		if v := os.Getenv(env); v != "" {
			options[option] = v
		}
	}
	conf := &inventory.Config{
		Type:        "yugabyte",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "")},
	}
	conn, err := connection.NewYugabyteConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	t.Cleanup(conn.Close)
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustList(t *testing.T, label string, tv *plugin.TValue[[]any]) []any {
	t.Helper()
	if tv.Error != nil {
		t.Fatalf("%s errored: %v", label, tv.Error)
	}
	return tv.Data
}

func TestIntegrationCluster(t *testing.T) {
	runtime := newIntegrationRuntime(t)
	res, err := NewResource(runtime, "yugabyte.cluster", map[string]*llx.RawData{})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(*mqlYugabyteCluster)
	if c.GetUuid().Data == "" || c.GetVersion().Data == "" || c.GetReplicationFactor().Data < 1 {
		t.Errorf("cluster uuid=%q version=%q rf=%d", c.GetUuid().Data, c.GetVersion().Data, c.GetReplicationFactor().Data)
	}

	// The node behind the host must be matched to its reported entry, so
	// its flags are readable even when its reported address is not.
	tservers := mustList(t, "tservers", c.GetTservers())
	readable := 0
	for _, ts := range tservers {
		if flags := ts.(*mqlYugabyteTserver).GetFlags(); flags.Error == nil {
			for _, f := range flags.Data {
				if f.(*mqlYugabyteFlag).Name.Data == "ysql_enable_auth" {
					readable++
				}
			}
		}
	}
	if readable == 0 {
		t.Error("no tablet server's flags were readable")
	}

	ysql := c.GetYsql()
	if ysql.Error != nil {
		t.Fatal(ysql.Error)
	}
	foundYugabyte := false
	for _, r := range mustList(t, "roles", ysql.Data.GetRoles()) {
		role := r.(*mqlYugabyteYsqlRole)
		if role.Name.Data == "yugabyte" && role.IsSuperuser.Data {
			foundYugabyte = true
		}
	}
	if !foundYugabyte {
		t.Error("superuser role yugabyte not listed")
	}
	rules := mustList(t, "hbaRules", ysql.Data.GetHbaRules())
	if len(rules) == 0 || rules[0].(*mqlYugabyteYsqlHbaRule).Method.Data == "" {
		t.Errorf("hbaRules: %d rules", len(rules))
	}

	ycql := c.GetYcql()
	if ycql.Error != nil {
		t.Fatal(ycql.Error)
	}
	foundAuth := false
	for _, k := range mustList(t, "keyspaces", ycql.Data.GetKeyspaces()) {
		if k.(*mqlYugabyteYcqlKeyspace).Name.Data == "system_auth" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Error("keyspace system_auth not listed")
	}
}
