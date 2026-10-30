// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"
	"testing"

	"github.com/stackitcloud/stackit-sdk-go/core/config"
	resourcemanager "github.com/stackitcloud/stackit-sdk-go/services/resourcemanager/v0api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// applyOpts replays a slice of ConfigurationOptions against an empty
// Configuration so tests can inspect the final field values directly. Mirrors
// what the SDK does internally when constructing a client.
func applyOpts(t *testing.T, opts []config.ConfigurationOption) *config.Configuration {
	t.Helper()
	cfg := &config.Configuration{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			t.Fatalf("applying option: %v", err)
		}
	}
	return cfg
}

func TestGetOptionValueFrom(t *testing.T) {
	t.Setenv("STACKIT_TEST_VAR", "from-env")

	cases := []struct {
		name    string
		options map[string]string
		wantVal string
		wantOk  bool
	}{
		{"nothing set", map[string]string{}, "from-env", true},
		{"option overrides env", map[string]string{"opt": "from-opt"}, "from-opt", true},
		{"empty option falls back to env", map[string]string{"opt": ""}, "from-env", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := getOptionValueFrom(tc.options, "STACKIT_TEST_VAR", "opt")
			if got != tc.wantVal || ok != tc.wantOk {
				t.Fatalf("got (%q, %v), want (%q, %v)", got, ok, tc.wantVal, tc.wantOk)
			}
		})
	}

	t.Run("nothing anywhere", func(t *testing.T) {
		t.Setenv("STACKIT_TEST_VAR", "")
		got, ok := getOptionValueFrom(map[string]string{}, "STACKIT_TEST_VAR", "opt")
		if got != "" || ok {
			t.Fatalf("expected ('', false), got (%q, %v)", got, ok)
		}
	})
}

func TestCredentialFor_PrefersCredentialOverOptionOverEnv(t *testing.T) {
	t.Setenv("STACKIT_TEST_SECRET", "from-env")
	conf := &inventory.Config{
		Options: map[string]string{OptionToken: "from-option"},
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, User: OptionToken, Secret: []byte("from-cred")},
		},
	}
	got, ok := credentialFor(conf, OptionToken, "STACKIT_TEST_SECRET")
	if !ok || got != "from-cred" {
		t.Fatalf("expected credentials-list to win, got (%q, %v)", got, ok)
	}
}

func TestCredentialFor_CredentialMatchedByUserTag(t *testing.T) {
	// A credential tagged with a *different* option must NOT match; this
	// keeps `--token` and `--service-account-key` from clobbering each other.
	conf := &inventory.Config{
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, User: OptionServiceAccountKey, Secret: []byte("sa-key")},
		},
	}
	if got, ok := credentialFor(conf, OptionToken, "STACKIT_NO_SUCH_VAR"); ok {
		t.Fatalf("expected miss for OptionToken, got %q", got)
	}
	if got, ok := credentialFor(conf, OptionServiceAccountKey, "STACKIT_NO_SUCH_VAR"); !ok || got != "sa-key" {
		t.Fatalf("expected hit for OptionServiceAccountKey, got (%q, %v)", got, ok)
	}
}

func TestCredentialFor_OptionsBeatsEnv(t *testing.T) {
	t.Setenv("STACKIT_TEST_SECRET", "from-env")
	conf := &inventory.Config{Options: map[string]string{OptionToken: "from-option"}}
	got, ok := credentialFor(conf, OptionToken, "STACKIT_TEST_SECRET")
	if !ok || got != "from-option" {
		t.Fatalf("expected option to beat env, got (%q, %v)", got, ok)
	}
}

func TestCredentialFor_EnvOnly(t *testing.T) {
	t.Setenv("STACKIT_TEST_SECRET", "from-env")
	conf := &inventory.Config{}
	got, ok := credentialFor(conf, OptionToken, "STACKIT_TEST_SECRET")
	if !ok || got != "from-env" {
		t.Fatalf("expected env fallback, got (%q, %v)", got, ok)
	}
}

func TestBuildAuthOptions_TokenFlag(t *testing.T) {
	conf := &inventory.Config{
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, User: OptionToken, Secret: []byte("tok-123")},
		},
	}
	cfg := applyOpts(t, buildAuthOptions(conf))
	if cfg.Token != "tok-123" {
		t.Fatalf("expected Token=tok-123, got %q", cfg.Token)
	}
	if cfg.ServiceAccountKey != "" || cfg.PrivateKey != "" {
		t.Fatalf("expected only Token set, got %+v", cfg)
	}
}

func TestBuildAuthOptions_ServiceAccountKeyPath(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{OptionServiceAccountKeyPath: "/path/to/sa.json"},
	}
	cfg := applyOpts(t, buildAuthOptions(conf))
	if cfg.ServiceAccountKeyPath != "/path/to/sa.json" {
		t.Fatalf("got %q", cfg.ServiceAccountKeyPath)
	}
}

func TestBuildAuthOptions_PrefersServiceAccountKeyOverPath(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{OptionServiceAccountKeyPath: "/path/ignored.json"},
		Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, User: OptionServiceAccountKey, Secret: []byte("{...}")},
		},
	}
	cfg := applyOpts(t, buildAuthOptions(conf))
	if cfg.ServiceAccountKey != "{...}" || cfg.ServiceAccountKeyPath != "" {
		t.Fatalf("inline key should win over path; got Key=%q Path=%q",
			cfg.ServiceAccountKey, cfg.ServiceAccountKeyPath)
	}
}

func TestBuildAuthOptions_Endpoint(t *testing.T) {
	conf := &inventory.Config{
		Options: map[string]string{OptionEndpoint: "https://api.eu02.stackit.cloud"},
	}
	// Endpoint isn't a top-level Configuration field — it goes into
	// per-service URLs via ConfigureRegion. So we can't read it back from a
	// bare Configuration. Smoke-test that the option list at least has one
	// extra entry vs. no-endpoint.
	got := len(buildAuthOptions(conf))
	want := len(buildAuthOptions(&inventory.Config{})) + 1
	if got != want {
		t.Fatalf("expected one extra option for endpoint, got %d vs %d", got, want)
	}
}

func TestNewStackitConnection_RequiresProjectID(t *testing.T) {
	t.Setenv(ProjectIDEnvVar, "")
	_, err := NewStackitConnection(1, &inventory.Asset{}, &inventory.Config{Options: map[string]string{}})
	if err == nil {
		t.Fatalf("expected error when project-id missing")
	}
	if !strings.Contains(err.Error(), OptionProjectID) {
		t.Fatalf("error should reference --%s, got: %v", OptionProjectID, err)
	}
}

func TestNewStackitConnection_DefaultRegion(t *testing.T) {
	t.Setenv(ProjectIDEnvVar, "")
	t.Setenv(RegionEnvVar, "")
	conn, err := NewStackitConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{OptionProjectID: "00000000-0000-0000-0000-000000000000"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.Region() != DefaultRegion {
		t.Fatalf("expected default region %q, got %q", DefaultRegion, conn.Region())
	}
}

func TestPlatformInfo_TechnologyUrlSegments(t *testing.T) {
	conn := &StackitConnection{projectID: "11111111-2222-3333-4444-555555555555"}

	p := conn.PlatformInfo()
	if p.Name != "stackit-project" {
		t.Fatalf("expected platform name stackit-project, got %q", p.Name)
	}
	// Must match the provider's AssetUrlTrees (technology=stackit -> project).
	want := []string{"stackit", conn.projectID}
	if len(p.TechnologyUrlSegments) != len(want) {
		t.Fatalf("expected segments %v, got %v", want, p.TechnologyUrlSegments)
	}
	for i := range want {
		if p.TechnologyUrlSegments[i] != want[i] {
			t.Fatalf("expected segments %v, got %v", want, p.TechnologyUrlSegments)
		}
	}
}

func TestPlatformInfo_TitleUsesProjectName(t *testing.T) {
	conn := &StackitConnection{projectID: "p-1", projectName: "production"}
	if got := conn.PlatformInfo().Title; got != "STACKIT Project production" {
		t.Fatalf("expected title to include project name, got %q", got)
	}

	// With no resolved name, the static catalog title is used.
	bare := &StackitConnection{projectID: "p-1"}
	if got := bare.PlatformInfo().Title; got != "STACKIT Project" {
		t.Fatalf("expected catalog title, got %q", got)
	}
}

func TestCaptureProjectMetadata(t *testing.T) {
	resp := resourcemanager.NewGetProjectResponseWithDefaults()
	resp.SetName("my-project")
	resp.SetLabels(map[string]string{"team": "platform", "env": "prod"})
	parent := resourcemanager.NewParentWithDefaults()
	parent.SetContainerId("org-abc")
	resp.SetParent(*parent)

	conn := &StackitConnection{}
	conn.captureProjectMetadata(resp)

	if conn.ProjectName() != "my-project" {
		t.Fatalf("expected project name my-project, got %q", conn.ProjectName())
	}
	if conn.ProjectParent() != "org-abc" {
		t.Fatalf("expected parent org-abc, got %q", conn.ProjectParent())
	}
	labels := conn.ProjectLabels()
	if labels["team"] != "platform" || labels["env"] != "prod" {
		t.Fatalf("unexpected labels: %v", labels)
	}
}

func TestCaptureProjectMetadata_NilSafe(t *testing.T) {
	conn := &StackitConnection{}
	conn.captureProjectMetadata(nil)
	if conn.ProjectName() != "" || conn.ProjectParent() != "" || conn.ProjectLabels() != nil {
		t.Fatalf("nil response should leave metadata empty")
	}
}

func TestNewStackitConnection_ExplicitRegion(t *testing.T) {
	t.Setenv(ProjectIDEnvVar, "")
	t.Setenv(RegionEnvVar, "")
	conn, err := NewStackitConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			OptionProjectID: "00000000-0000-0000-0000-000000000000",
			OptionRegion:    "eu02",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.Region() != "eu02" {
		t.Fatalf("expected eu02, got %q", conn.Region())
	}
}

func TestWithRequestTimeoutAllocatesPerClient(t *testing.T) {
	var a, b config.Configuration
	opt := withRequestTimeout()
	require.NoError(t, opt(&a))
	require.NoError(t, opt(&b))

	require.NotNil(t, a.HTTPClient)
	assert.Equal(t, requestTimeout, a.HTTPClient.Timeout)
	// The SDK overwrites each client's Transport with its own auth round
	// tripper, so two service clients must never share one *http.Client.
	assert.NotSame(t, a.HTTPClient, b.HTTPClient)
}

func TestBuildAuthOptionsSetsRequestTimeout(t *testing.T) {
	var cfg config.Configuration
	for _, opt := range buildAuthOptions(&inventory.Config{Options: map[string]string{}}) {
		require.NoError(t, opt(&cfg))
	}
	require.NotNil(t, cfg.HTTPClient)
	assert.Equal(t, requestTimeout, cfg.HTTPClient.Timeout)
}
