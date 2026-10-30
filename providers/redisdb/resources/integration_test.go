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
	"go.mondoo.com/mql/providers/redisdb/connection"
)

// newIntegrationRuntime connects to a live Redis/Valkey server described by the
// REDIS_TEST_* environment, or skips when it is not configured.
//
//	REDIS_TEST_HOST      host or host:port (default port 6379)
//	REDIS_TEST_USER      ACL user (optional)
//	REDIS_TEST_PASSWORD  password (required)
func newIntegrationRuntime(t *testing.T) *plugin.Runtime {
	host := os.Getenv("REDIS_TEST_HOST")
	password := os.Getenv("REDIS_TEST_PASSWORD")
	if host == "" || password == "" {
		t.Skip("set REDIS_TEST_HOST and REDIS_TEST_PASSWORD to run redisdb integration tests")
	}

	options := map[string]string{}
	if h, p, ok := strings.Cut(host, ":"); ok {
		options["host"] = h
		options["port"] = p
		if _, err := strconv.Atoi(p); err != nil {
			t.Fatalf("invalid REDIS_TEST_HOST port: %q", p)
		}
	} else {
		options["host"] = host
	}

	conf := &inventory.Config{
		Type:        "redisdb",
		Options:     options,
		Credentials: []*vault.Credential{vault.NewPasswordCredential(os.Getenv("REDIS_TEST_USER"), password)},
	}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := connection.NewRedisdbConnection(1, asset, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustInstance(t *testing.T, runtime *plugin.Runtime) *mqlRedisdbInstance {
	res, err := NewResource(runtime, "redisdb.instance", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to resolve redisdb.instance: %v", err)
	}
	return res.(*mqlRedisdbInstance)
}

func TestIntegrationInstance(t *testing.T) {
	inst := mustInstance(t, newIntegrationRuntime(t))
	if v := inst.GetVersion(); v.Error != nil || v.Data == "" {
		t.Errorf("version = %q (err=%v)", v.Data, v.Error)
	}
	for _, tv := range []*plugin.TValue[bool]{
		inst.GetProtectedMode(), inst.GetRequirepassSet(), inst.GetBindsAllInterfaces(), inst.GetTlsEnabled(),
	} {
		if tv.Error != nil {
			t.Errorf("instance bool field errored: %v", tv.Error)
		}
	}
}

// TestIntegrationResolveAll walks every resource and field getter and asserts
// each resolves without error against a live server.
func TestIntegrationResolveAll(t *testing.T) {
	inst := mustInstance(t, newIntegrationRuntime(t))

	cfg := inst.GetConfig()
	if cfg.Error != nil {
		t.Errorf("config errored: %v", cfg.Error)
	} else if v := cfg.Data.GetMaxmemoryPolicy(); v.Error != nil {
		t.Errorf("config.maxmemoryPolicy errored: %v", v.Error)
	}

	users := inst.GetUsers()
	if users.Error != nil {
		t.Errorf("users errored: %v", users.Error)
	}
	for _, x := range users.Data {
		u := x.(*mqlRedisdbAclUser)
		if v := u.GetName(); v.Error != nil || v.Data == "" {
			t.Errorf("user.name = %q (err=%v)", v.Data, v.Error)
		}
		u.GetCommandRules()
		u.GetKeyPatterns()
	}
}

// TestIntegrationSeededFixtures verifies the default user and the seeded
// auditor ACL user. Enable it with REDIS_TEST_SEEDED=1 against a server started
// with: redis-server --requirepass ... --user auditor on '>...' '~app:*'
// '&notifications:*' +@read +@connection
func TestIntegrationSeededFixtures(t *testing.T) {
	if os.Getenv("REDIS_TEST_SEEDED") == "" {
		t.Skip("set REDIS_TEST_SEEDED=1 against a server seeded with the auditor ACL user")
	}
	inst := mustInstance(t, newIntegrationRuntime(t))

	users := map[string]*mqlRedisdbAclUser{}
	for _, x := range inst.GetUsers().Data {
		u := x.(*mqlRedisdbAclUser)
		users[u.GetName().Data] = u
	}

	def := users["default"]
	if def == nil {
		t.Fatal("default user not found")
	}
	if !def.GetIsDefault().Data || !def.GetEnabled().Data {
		t.Error("default user should be flagged default and enabled")
	}

	aud := users["auditor"]
	if aud == nil {
		t.Fatal("seeded auditor user not found")
	}
	if aud.GetIsDefault().Data {
		t.Error("auditor should not be flagged default")
	}
	// auditor is scoped to app:* keys and read-only commands.
	keys := aud.GetKeyPatterns().Data
	if len(keys) != 1 || keys[0] != "app:*" {
		t.Errorf("auditor keyPatterns = %v, want [app:*]", keys)
	}
	hasReadOnly := false
	for _, r := range aud.GetCommandRules().Data {
		if r == "+@read" {
			hasReadOnly = true
		}
	}
	if !hasReadOnly {
		t.Error("auditor should carry the +@read command rule")
	}
}
