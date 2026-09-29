// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// statusRuntime points a real connection at a server answering each path in
// routes with the given status and body, and 404 for anything else.
func statusRuntime(t *testing.T, routes map[string]struct {
	status int
	body   string
}) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rt, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"id":"not_found","message":"not found"}`))
			return
		}
		w.WriteHeader(rt.status)
		_, _ = w.Write([]byte(rt.body))
	}))
	t.Cleanup(srv.Close)

	t.Setenv("DIGITALOCEAN_TOKEN", "test-token")
	conn, err := connection.NewDigitaloceanConnection(0, &inventory.Asset{},
		&inventory.Config{Options: map[string]string{}})
	require.NoError(t, err)
	base, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)
	conn.Client().BaseURL = base
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

type route = struct {
	status int
	body   string
}

// ----- Credential redaction -----

func TestRedactURLPassword(t *testing.T) {
	cases := map[string]string{
		"https://admin:s3cr3t@search.example.com:25060/logs": "https://admin@search.example.com:25060/logs",
		"https://search.example.com:9200":                    "https://search.example.com:9200",
		"https://token@git.example.com/org/repo.git":         "https://token@git.example.com/org/repo.git",
		"": "",
		"syslog+tls://logs.papertrailapp.com:12345": "syslog+tls://logs.papertrailapp.com:12345",
	}
	for in, want := range cases {
		assert.Equal(t, want, redactURLPassword(in), in)
	}
	// Input url.Parse rejects (a control character) still loses the password.
	got := redactURLPassword("https://u:p4ss@host\x7f/x")
	assert.NotContains(t, got, "p4ss")
}

func TestAlertSlackTargetsWithholdWebhook(t *testing.T) {
	const hook = "https://hooks.slack.com/services/T000/B000/XXXXSECRET"
	out := alertSlackTargets([]godo.SlackDetails{{Channel: "#ops", URL: hook}})
	require.Len(t, out, 1)
	assert.Equal(t, "#ops", out[0].(map[string]any)["channel"])
	raw, err := json.Marshal(out)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "XXXXSECRET")
}

func TestLogsinkURLPasswordRemoved(t *testing.T) {
	args, err := logsinkArgs("db1", &godo.DatabaseLogsink{
		ID: "s1", Name: "search", Type: "opensearch",
		Config: &godo.DatabaseLogsinkConfig{URL: "https://user:hunter2@os.example.com:25060"},
	})
	require.NoError(t, err)
	assert.Equal(t, "https://user@os.example.com:25060", args["url"].Value)
}

func TestLogDestinationEndpointPasswordRemoved(t *testing.T) {
	_, ep, os := logDestinationTarget(&godo.AppLogDestinationSpec{
		OpenSearch: &godo.AppLogDestinationSpecOpenSearch{Endpoint: "https://u:hunter2@os.example.com"},
	})
	assert.Equal(t, "https://u@os.example.com", ep)
	assert.Equal(t, "https://u@os.example.com", os.endpoint)

	_, ep, _ = logDestinationTarget(&godo.AppLogDestinationSpec{Endpoint: "https://u:hunter2@logs.example.com"})
	assert.Equal(t, "https://u@logs.example.com", ep)
}

// ----- Engine configuration -----

func TestEngineConfigDictDropsSecretShapedKeys(t *testing.T) {
	type fake struct {
		SSL      *bool  `json:"redis_ssl,omitempty"`
		Password string `json:"admin_password,omitempty"`
		APIKey   string `json:"backup_api_key,omitempty"`
		Unset    *int   `json:"redis_timeout,omitempty"`
	}
	tr := true
	out, err := engineConfigDict(&fake{SSL: &tr, Password: "p", APIKey: "k"})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"redis_ssl": true}, out,
		"secret-shaped settings are dropped and unreported settings stay absent")
}

func TestIsSecretShapedConfigKey(t *testing.T) {
	for _, k := range []string{"admin_password", "auth_token", "api_key", "backup.secret_key", "credentials"} {
		assert.True(t, isSecretShapedConfigKey(k), k)
	}
	// Real settings that contain a credential word without holding one.
	for _, k := range []string{"innodb_ft_min_token_size", "sql_require_primary_key", "redis_notify_keyspace_events", "redis_ssl"} {
		assert.False(t, isSecretShapedConfigKey(k), k)
	}
}

func TestEngineConfigDictNestedAndRealKeys(t *testing.T) {
	type nested struct {
		Pass string `json:"auth_password,omitempty"`
		Mode string `json:"pool_mode,omitempty"`
	}
	type fake struct {
		Tok *int    `json:"innodb_ft_min_token_size,omitempty"`
		PK  *bool   `json:"sql_require_primary_key,omitempty"`
		Pgb *nested `json:"pgbouncer,omitempty"`
	}
	n, tr := 3, true
	out, err := engineConfigDict(&fake{Tok: &n, PK: &tr, Pgb: &nested{Pass: "p", Mode: "session"}})
	require.NoError(t, err)
	assert.Equal(t, float64(3), out["innodb_ft_min_token_size"])
	assert.Equal(t, true, out["sql_require_primary_key"])
	assert.Equal(t, map[string]any{"pool_mode": "session"}, out["pgbouncer"])
}

func TestEngineConfigDictKafkaBigInt(t *testing.T) {
	cfg := &godo.KafkaConfig{}
	require.NoError(t, json.Unmarshal([]byte(`{"log_retention_ms": 604800000, "auto_create_topics_enable": false}`), cfg))
	out, err := engineConfigDict(cfg)
	require.NoError(t, err)
	assert.Equal(t, float64(604800000), out["log_retention_ms"])
	assert.Equal(t, false, out["auto_create_topics_enable"])
}

func dbWithEngine(rt *plugin.Runtime, engine string) *mqlDigitaloceanDatabase {
	return &mqlDigitaloceanDatabase{
		MqlRuntime: rt,
		Id:         plugin.TValue[string]{Data: "db1", State: plugin.StateIsSet},
		Engine:     plugin.TValue[string]{Data: engine, State: plugin.StateIsSet},
	}
}

func TestRedisSettings(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{"redis_ssl":false,"redis_acl_channels_default":"allchannels"}}`},
	})
	r := dbWithEngine(rt, "redis")

	ssl, err := r.sslRequired()
	require.NoError(t, err)
	assert.False(t, ssl)
	assert.Equal(t, plugin.State(0), r.SslRequired.State, "a read false must not be null")

	acl, err := r.aclChannelsDefault()
	require.NoError(t, err)
	assert.Equal(t, "allchannels", acl)

	// A Redis cluster has no OpenSearch settings.
	_, err = r.securityAuditEnabled()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.SecurityAuditEnabled.State)
}

func TestValkeySettings(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{"valkey_ssl":true,"valkey_acl_channels_default":"resetchannels"}}`},
	})
	r := dbWithEngine(rt, "valkey")
	ssl, err := r.sslRequired()
	require.NoError(t, err)
	assert.True(t, ssl)
	acl, err := r.aclChannelsDefault()
	require.NoError(t, err)
	assert.Equal(t, "resetchannels", acl)
}

func TestOpensearchSettings(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{"enable_security_audit":true,"action_destructive_requires_name":false,"reindex_remote_whitelist":["10.0.0.5:9200"]}}`},
	})
	r := dbWithEngine(rt, "opensearch")
	audit, err := r.securityAuditEnabled()
	require.NoError(t, err)
	assert.True(t, audit)
	destr, err := r.destructiveActionsRequireName()
	require.NoError(t, err)
	assert.False(t, destr)
	assert.Equal(t, plugin.State(0), r.DestructiveActionsRequireName.State)
	allow, err := r.reindexRemoteAllowlist()
	require.NoError(t, err)
	assert.Equal(t, []any{"10.0.0.5:9200"}, allow)
	_, err = r.sslRequired()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.SslRequired.State)
}

func TestKafkaAndMySQLSettings(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{"auto_create_topics_enable":true}}`},
	})
	k := dbWithEngine(rt, "kafka")
	v, err := k.autoCreateTopicsEnabled()
	require.NoError(t, err)
	assert.True(t, v)

	rt2 := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{"slow_query_log":false,"sql_require_primary_key":true}}`},
	})
	m := dbWithEngine(rt2, "mysql")
	slow, err := m.slowQueryLogEnabled()
	require.NoError(t, err)
	assert.False(t, slow)
	pk, err := m.requirePrimaryKey()
	require.NoError(t, err)
	assert.True(t, pk)
}

// An unreported setting is null, not the false its Go zero value would read as.
func TestEngineSettingUnreportedIsNull(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {200, `{"config":{}}`},
	})
	r := dbWithEngine(rt, "redis")
	_, err := r.sslRequired()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.SslRequired.State)
}

func TestEngineConfigNotFoundIsNull(t *testing.T) {
	rt := statusRuntime(t, map[string]route{})
	r := dbWithEngine(rt, "pg")
	out, err := r.engineConfig()
	require.NoError(t, err)
	assert.Nil(t, out)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.EngineConfig.State)
}

// A refused read is an error of the Forbidden kind, never an unset setting.
func TestEngineConfigForbiddenIsError(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/config": {403, `{"id":"forbidden","message":"You are not authorized"}`},
	})
	r := dbWithEngine(rt, "redis")
	_, err := r.sslRequired()
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden))
}

// ----- Kafka topics -----

func TestUnderReplicated(t *testing.T) {
	rf := uint32(3)
	topic := &godo.DatabaseTopic{
		ReplicationFactor: &rf,
		Partitions: []*godo.TopicPartition{
			{Id: 0, InSyncReplicas: 3},
			{Id: 1, InSyncReplicas: 2},
			nil,
			{Id: 2, InSyncReplicas: 1},
		},
	}
	n := underReplicated(topic)
	require.NotNil(t, n)
	assert.Equal(t, int64(2), *n)

	assert.Nil(t, underReplicated(&godo.DatabaseTopic{}), "no replication factor means unknown, not zero")
	assert.Nil(t, underReplicated(nil))
}

func TestTopicsNonKafkaMakesNoCall(t *testing.T) {
	rt := statusRuntime(t, map[string]route{})
	r := dbWithEngine(rt, "pg")
	out, err := r.topics()
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestTopicsAndDetail(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/topics": {200, `{"topics":[{"name":"events","state":"active","replication_factor":3},{"name":"audit","state":"active","replication_factor":2}]}`},
		"/v2/databases/db1/topics/events": {200, `{"topic":{"name":"events","state":"active","replication_factor":3,
			"partitions":[{"id":0,"in_sync_replicas":3},{"id":1,"in_sync_replicas":1}],
			"config":{"cleanup_policy":"compact","min_insync_replicas":2,"retention_ms":-1}}}`},
	})
	r := dbWithEngine(rt, "kafka")
	out, err := r.topics()
	require.NoError(t, err)
	require.Len(t, out, 2)

	ev := out[0].(*mqlDigitaloceanDatabaseTopic)
	au := out[1].(*mqlDigitaloceanDatabaseTopic)
	assert.Equal(t, "events", ev.Name.Data)
	assert.Equal(t, int64(3), ev.ReplicationFactor.Data)
	assert.NotEqual(t, ev.__id, au.__id)

	pc, err := ev.partitionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(2), pc)
	ur, err := ev.underReplicatedPartitions()
	require.NoError(t, err)
	assert.Equal(t, int64(1), ur)
	mi, err := ev.minInsyncReplicas()
	require.NoError(t, err)
	assert.Equal(t, int64(2), mi)
	ret, err := ev.retentionMs()
	require.NoError(t, err)
	assert.Equal(t, int64(-1), ret)
	_, err = ev.retentionBytes()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, ev.RetentionBytes.State)
	cp, err := ev.cleanupPolicy()
	require.NoError(t, err)
	assert.Equal(t, "compact", cp)
}

func TestTopicCleanupPolicyUnreportedIsNull(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/databases/db1/topics/t": {200, `{"topic":{"name":"t","state":"active","replication_factor":3,"config":{}}}`},
	})
	tp := &mqlDigitaloceanDatabaseTopic{
		MqlRuntime: rt,
		DatabaseId: plugin.TValue[string]{Data: "db1", State: plugin.StateIsSet},
		Name:       plugin.TValue[string]{Data: "t", State: plugin.StateIsSet},
	}
	_, err := tp.cleanupPolicy()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, tp.CleanupPolicy.State)
}

// ----- Clusterlint -----

func k8sCluster(rt *plugin.Runtime) *mqlDigitaloceanKubernetesCluster {
	return &mqlDigitaloceanKubernetesCluster{
		MqlRuntime: rt,
		Id:         plugin.TValue[string]{Data: "c1", State: plugin.StateIsSet},
	}
}

func TestClusterlintNeverRunIsNull(t *testing.T) {
	rt := statusRuntime(t, map[string]route{})
	c := k8sCluster(rt)
	out, err := c.lintDiagnostics()
	require.NoError(t, err)
	assert.Nil(t, out)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, c.LintDiagnostics.State,
		"a cluster nobody linted must not read as a clean one")
	_, err = c.lintCompletedAt()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, c.LintCompletedAt.State)
}

func TestClusterlintDiagnostics(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/kubernetes/clusters/c1/clusterlint": {200, `{"run_id":"run1","requested_at":"2026-09-01T10:00:00Z","completed_at":"2026-09-01T10:00:05Z",
			"diagnostics":[
			 {"check_name":"privileged-containers","severity":"warning","message":"Privileged container 'x' found",
			  "object":{"kind":"Pod","name":"web-1","namespace":"default","owners":[{"kind":"ReplicaSet","name":"web-abc"}]}},
			 {"check_name":"privileged-containers","severity":"warning","message":"Privileged container 'y' found",
			  "object":{"kind":"Pod","name":"web-1","namespace":"default"}},
			 {"check_name":"node-name-pod-selector","severity":"suggestion","message":"m","object":null}
			]}`},
	})
	c := k8sCluster(rt)
	at, err := c.lintCompletedAt()
	require.NoError(t, err)
	require.NotNil(t, at)
	assert.Equal(t, "2026-09-01T10:00:05Z", at.UTC().Format("2006-01-02T15:04:05Z"))

	out, err := c.lintDiagnostics()
	require.NoError(t, err)
	require.Len(t, out, 3)
	d0 := out[0].(*mqlDigitaloceanKubernetesLintDiagnostic)
	d1 := out[1].(*mqlDigitaloceanKubernetesLintDiagnostic)
	d2 := out[2].(*mqlDigitaloceanKubernetesLintDiagnostic)
	assert.Equal(t, "privileged-containers", d0.CheckName.Data)
	assert.Equal(t, "Pod", d0.ObjectKind.Data)
	assert.Equal(t, "default", d0.ObjectNamespace.Data)
	assert.Equal(t, []any{"ReplicaSet/web-abc"}, d0.Owners.Data)
	assert.NotEqual(t, d0.__id, d1.__id, "the same check on the same object twice must not collide")
	assert.Equal(t, "Privileged container 'y' found", d1.Message.Data)
	assert.Equal(t, "", d2.ObjectKind.Data)
	assert.Equal(t, []any{}, d2.Owners.Data)
}

// A run still in progress answers without a completion time; the diagnostics
// must still decode.
func TestClusterlintInProgress(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/kubernetes/clusters/c1/clusterlint": {200, `{"run_id":"run2","requested_at":"2026-09-01T10:00:00Z","completed_at":"","diagnostics":[]}`},
	})
	c := k8sCluster(rt)
	_, err := c.lintCompletedAt()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, c.LintCompletedAt.State)
	out, err := c.lintDiagnostics()
	require.NoError(t, err)
	assert.NotNil(t, out)
	assert.Empty(t, out)
}

// ----- App components -----

func TestComponentSourceImage(t *testing.T) {
	s := componentSource(&godo.AppServiceSpec{
		Name: "api",
		Image: &godo.ImageSourceSpec{
			RegistryType:        godo.ImageSourceSpecRegistryType_DockerHub,
			Registry:            "acme",
			Repository:          "api",
			Tag:                 "latest",
			RegistryCredentials: "acme:dckr_pat_SECRET",
			DeployOnPush:        &godo.ImageSourceSpecDeployOnPush{Enabled: true},
		},
	})
	assert.Equal(t, "image", s.sourceType)
	assert.Equal(t, "DOCKER_HUB", s.imageRegistryType)
	assert.Equal(t, "acme", s.imageRegistry)
	assert.Equal(t, "api", s.repository)
	assert.Equal(t, "latest", s.imageTag)
	assert.True(t, s.hasRegistryCreds)
	assert.True(t, s.deployOnPush)
}

func TestComponentSourceGit(t *testing.T) {
	gh := componentSource(&godo.AppWorkerSpec{GitHub: &godo.GitHubSourceSpec{Repo: "acme/w", Branch: "main", DeployOnPush: true}})
	assert.Equal(t, "github", gh.sourceType)
	assert.Equal(t, "acme/w", gh.repository)
	assert.Equal(t, "main", gh.branch)
	assert.True(t, gh.deployOnPush)

	gl := componentSource(&godo.AppStaticSiteSpec{GitLab: &godo.GitLabSourceSpec{Repo: "acme/site", Branch: "prod"}})
	assert.Equal(t, "gitlab", gl.sourceType)
	assert.False(t, gl.deployOnPush)

	bb := componentSource(&godo.AppFunctionsSpec{Bitbucket: &godo.BitbucketSourceSpec{Repo: "acme/fn"}})
	assert.Equal(t, "bitbucket", bb.sourceType)

	git := componentSource(&godo.AppJobSpec{Git: &godo.GitSourceSpec{RepoCloneURL: "https://ci:ghp_SECRET@github.com/acme/j.git", Branch: "main"}})
	assert.Equal(t, "git", git.sourceType)
	assert.NotContains(t, git.repository, "ghp_SECRET")
	assert.Equal(t, "https://ci@github.com/acme/j.git", git.repository)

	none := componentSource(&godo.AppServiceSpec{Name: "x"})
	assert.Equal(t, "", none.sourceType)
}

func TestComponentRuntime(t *testing.T) {
	svc := componentRuntime(&godo.AppServiceSpec{
		InstanceSizeSlug: "apps-s-1vcpu-1gb",
		Autoscaling:      &godo.AppAutoscalingSpec{MinInstanceCount: 2, MaxInstanceCount: 5},
		HTTPPort:         8080,
		InternalPorts:    []int64{9090},
		Routes:           []*godo.AppRouteSpec{{Path: "/api"}, nil},
	})
	require.NotNil(t, svc.autoscaleMin)
	assert.Equal(t, int64(2), *svc.autoscaleMin)
	assert.Equal(t, int64(5), *svc.autoscaleMax)
	require.NotNil(t, svc.httpPort)
	assert.Equal(t, int64(8080), *svc.httpPort)
	assert.Equal(t, []any{int64(9090)}, svc.internalPorts)
	assert.Equal(t, []any{"/api"}, svc.routes)

	unset := componentRuntime(&godo.AppServiceSpec{InstanceCount: 1})
	assert.Nil(t, unset.httpPort, "an unset port is the platform default, not port 0")
	assert.Nil(t, unset.autoscaleMin)

	wk := componentRuntime(&godo.AppWorkerSpec{InstanceCount: 3})
	assert.Equal(t, int64(3), wk.instanceCount)
	assert.Nil(t, wk.httpPort)
	assert.Empty(t, wk.routes)
}

func TestAppComponentSpecsSkipsDatabases(t *testing.T) {
	spec := &godo.AppSpec{
		Services:    []*godo.AppServiceSpec{{Name: "api"}},
		Workers:     []*godo.AppWorkerSpec{{Name: "w"}},
		Jobs:        []*godo.AppJobSpec{{Name: "j"}},
		Databases:   []*godo.AppDatabaseSpec{{Name: "db"}},
		Functions:   []*godo.AppFunctionsSpec{{Name: "f"}},
		StaticSites: []*godo.AppStaticSiteSpec{{Name: "s"}},
	}
	names := []string{}
	for _, c := range appComponentSpecs(spec) {
		names = append(names, c.GetName())
	}
	assert.ElementsMatch(t, []string{"api", "w", "j", "f", "s"}, names)
	assert.Empty(t, appComponentSpecs(nil))
}

func TestAppComponentsDistinctIds(t *testing.T) {
	rt := statusRuntime(t, map[string]route{})
	app := &mqlDigitaloceanApp{
		MqlRuntime: rt,
		Id:         plugin.TValue[string]{Data: "app1", State: plugin.StateIsSet},
	}
	app.cacheSpec = &godo.AppSpec{
		Services: []*godo.AppServiceSpec{{Name: "web", Image: &godo.ImageSourceSpec{Repository: "web", RegistryCredentials: "u:SECRET"}}},
		Workers:  []*godo.AppWorkerSpec{{Name: "queue"}},
	}
	out, err := app.components()
	require.NoError(t, err)
	require.Len(t, out, 2)
	a := out[0].(*mqlDigitaloceanAppComponent)
	b := out[1].(*mqlDigitaloceanAppComponent)
	assert.NotEqual(t, a.__id, b.__id)
	assert.Equal(t, "service", a.Type.Data)
	assert.True(t, a.RegistryCredentialsConfigured.Data)
	for _, c := range []*mqlDigitaloceanAppComponent{a, b} {
		for _, v := range []string{c.Repository.Data, c.ImageRegistry.Data, c.ImageTag.Data} {
			assert.False(t, strings.Contains(v, "SECRET"))
		}
	}
}
