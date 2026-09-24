// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// emptyBodyRuntime points a real connection at a server that answers every
// request 200 with an empty JSON object.
//
// That is the shape these tests exist for. godo's Get methods end in
// `return root.X, resp, err`, so a 200 whose body carries no "firewall" /
// "load_balancer" / "database" / "account" / "deployment" (or similar) key
// decodes to a nil object and a nil error. The caller sees success and a nil pointer.
func emptyBodyRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	t.Setenv("DIGITALOCEAN_TOKEN", "test-token")
	conn, err := connection.NewDigitaloceanConnection(0, &inventory.Asset{},
		&inventory.Config{Options: map[string]string{}})
	require.NoError(t, err)

	base, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)
	conn.Client().BaseURL = base

	return &plugin.Runtime{Connection: conn}
}

// Each init used to hand the fetched object straight to its constructor.
//
// For the firewall, load balancer and cluster that dereferences nil in the arg
// builder. For the GradientAI agent the constructor returns a nil
// *mqlDigitaloceanGradientaiAgent, which is not == nil once widened to
// plugin.Resource, so the runtime accepts it and panics reading its id.
//
// Either way the provider panics, and a provider panic takes down the whole
// scan rather than the one resource that triggered it. A not-found error is
// what the caller should get instead.
func TestInitReportsNotFoundInsteadOfPanicking(t *testing.T) {
	for _, tc := range []struct {
		name string
		init func(*plugin.Runtime, map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error)
		args map[string]*llx.RawData
		want string
	}{
		{
			name: "firewall",
			init: initDigitaloceanFirewall,
			args: map[string]*llx.RawData{"id": llx.StringData("fw-1")},
			want: `digitalocean.firewall with id "fw-1" not found`,
		},
		{
			name: "load balancer",
			init: initDigitaloceanLoadBalancer,
			args: map[string]*llx.RawData{"id": llx.StringData("lb-1")},
			want: `digitalocean.loadBalancer with id "lb-1" not found`,
		},
		{
			name: "kubernetes cluster",
			init: initDigitaloceanKubernetesCluster,
			args: map[string]*llx.RawData{"id": llx.StringData("k8s-1")},
			want: `digitalocean.kubernetes.cluster with id "k8s-1" not found`,
		},
		{
			name: "database",
			init: initDigitaloceanDatabase,
			args: map[string]*llx.RawData{"id": llx.StringData("db-1")},
			want: `digitalocean.database with id "db-1" not found`,
		},
		{
			name: "byoip prefix",
			init: initDigitaloceanByoipPrefix,
			args: map[string]*llx.RawData{"uuid": llx.StringData("prefix-1")},
			want: `digitalocean.byoipPrefix with uuid "prefix-1" not found`,
		},
		{
			name: "partner attachment",
			init: initDigitaloceanPartnerAttachment,
			args: map[string]*llx.RawData{"id": llx.StringData("pa-1")},
			want: `digitalocean.partnerAttachment with id "pa-1" not found`,
		},
		{
			name: "account",
			init: initDigitaloceanAccount,
			args: map[string]*llx.RawData{},
			want: "the DigitalOcean API returned no account",
		},
		{
			name: "gradientai agent",
			init: initDigitaloceanGradientaiAgent,
			args: map[string]*llx.RawData{"uuid": llx.StringData("agent-1")},
			want: `digitalocean.gradientai.agent with uuid "agent-1" not found`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := emptyBodyRuntime(t)

			require.NotPanics(t, func() {
				_, res, err := tc.init(runtime, tc.args)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.want)

				// The resource must be absent as an interface, not merely a nil
				// pointer inside one: a typed nil satisfies `res != nil` and is
				// exactly what the runtime would go on to panic reading.
				assert.True(t, res == nil, "init returned a non-nil plugin.Resource alongside an error")
			})
		})
	}
}

// The app deployment accessors hand the fetched deployment to
// newAppDeployment, which reads d.Progress straight away. A 200 with no
// "deployment" key is a nil deployment with a nil error, so without a guard
// the provider panics. Nothing was returned to describe, so the field is null.
func TestAppDeploymentEmptyBodyIsNull(t *testing.T) {
	t.Run("active deployment", func(t *testing.T) {
		r := &mqlDigitaloceanApp{
			MqlRuntime:         emptyBodyRuntime(t),
			Id:                 plugin.TValue[string]{Data: "app-1", State: plugin.StateIsSet},
			ActiveDeploymentId: plugin.TValue[string]{Data: "dep-1", State: plugin.StateIsSet},
		}
		require.NotPanics(t, func() {
			res, err := r.activeDeployment()
			require.NoError(t, err)
			assert.Nil(t, res)
		})
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.ActiveDeployment.State)
	})

	t.Run("previous deployment", func(t *testing.T) {
		r := &mqlDigitaloceanAppDeployment{
			MqlRuntime:           emptyBodyRuntime(t),
			AppId:                plugin.TValue[string]{Data: "app-1", State: plugin.StateIsSet},
			PreviousDeploymentId: plugin.TValue[string]{Data: "dep-0", State: plugin.StateIsSet},
		}
		require.NotPanics(t, func() {
			res, err := r.previousDeployment()
			require.NoError(t, err)
			assert.Nil(t, res)
		})
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, r.PreviousDeployment.State)
	})
}
