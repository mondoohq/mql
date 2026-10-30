// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppSecureHeader(t *testing.T) {
	t.Run("reads a header the ingress sets", func(t *testing.T) {
		spec := &godo.AppSpec{Ingress: &godo.AppIngressSpec{
			SecureHeader: &godo.AppSecureHeaderSpec{Key: "X-Frame-Options", Value: "DENY"},
		}}
		key, value, removed := appSecureHeader(spec)
		assert.Equal(t, "X-Frame-Options", key)
		assert.Equal(t, "DENY", value)
		assert.False(t, removed)
	})

	t.Run("reads a header the ingress strips", func(t *testing.T) {
		spec := &godo.AppSpec{Ingress: &godo.AppIngressSpec{
			SecureHeader: &godo.AppSecureHeaderSpec{Key: "X-Powered-By", RemoveHeader: true},
		}}
		key, value, removed := appSecureHeader(spec)
		assert.Equal(t, "X-Powered-By", key)
		assert.Empty(t, value)
		assert.True(t, removed)
	})

	t.Run("is empty with no ingress or no header", func(t *testing.T) {
		for _, spec := range []*godo.AppSpec{nil, {}, {Ingress: &godo.AppIngressSpec{}}} {
			key, value, removed := appSecureHeader(spec)
			assert.Empty(t, key)
			assert.Empty(t, value)
			assert.False(t, removed)
		}
	})
}

func TestAppCorsPolicies(t *testing.T) {
	t.Run("flattens a policy and tags each origin with its match kind", func(t *testing.T) {
		prefix := "/api"
		spec := &godo.AppSpec{Ingress: &godo.AppIngressSpec{Rules: []*godo.AppIngressSpecRule{{
			Match: &godo.AppIngressSpecRuleMatch{Path: &godo.AppIngressSpecRuleStringMatch{Prefix: &prefix}},
			CORS: &godo.AppCORSPolicy{
				AllowOrigins: []*godo.AppStringMatch{
					{Exact: "https://example.com"},
					{Prefix: "https://"},
					{Regex: ".*"},
				},
				AllowMethods:     []string{"GET", "POST"},
				AllowHeaders:     []string{"Authorization"},
				ExposeHeaders:    []string{"X-Request-Id"},
				MaxAge:           "5h30m",
				AllowCredentials: true,
			},
		}}}}

		policies := appCorsPolicies(spec)
		require.Len(t, policies, 1)

		p, ok := policies[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "/api", p["path"])
		assert.Equal(t, []any{"exact:https://example.com", "prefix:https://", "regex:.*"}, p["allowOrigins"])
		assert.Equal(t, []any{"GET", "POST"}, p["allowMethods"])
		assert.Equal(t, []any{"Authorization"}, p["allowHeaders"])
		assert.Equal(t, []any{"X-Request-Id"}, p["exposeHeaders"])
		assert.Equal(t, "5h30m", p["maxAge"])
		assert.Equal(t, true, p["allowCredentials"])
	})

	t.Run("skips rules without a CORS policy", func(t *testing.T) {
		spec := &godo.AppSpec{Ingress: &godo.AppIngressSpec{Rules: []*godo.AppIngressSpecRule{
			nil,
			{Match: &godo.AppIngressSpecRuleMatch{}},
		}}}
		assert.Empty(t, appCorsPolicies(spec))
	})

	t.Run("is empty with no ingress", func(t *testing.T) {
		assert.Empty(t, appCorsPolicies(nil))
		assert.Empty(t, appCorsPolicies(&godo.AppSpec{}))
	})
}

func TestAppEnvVars(t *testing.T) {
	t.Run("collects app-level and component variables without values", func(t *testing.T) {
		spec := &godo.AppSpec{
			Envs: []*godo.AppVariableDefinition{
				{Key: "SHARED", Value: "plaintext", Scope: "RUN_TIME", Type: "GENERAL"},
			},
			Services: []*godo.AppServiceSpec{{
				Name: "api",
				Envs: []*godo.AppVariableDefinition{
					{Key: "DB_PASSWORD", Value: "encrypted", Scope: "RUN_TIME", Type: "SECRET"},
				},
			}},
		}

		vars := appEnvVars(spec)
		require.Len(t, vars, 2)

		// An empty component name marks a variable shared by the whole app.
		assert.Equal(t, map[string]any{
			"component": "", "key": "SHARED", "scope": "RUN_TIME", "type": "GENERAL",
		}, vars[0])
		assert.Equal(t, map[string]any{
			"component": "api", "key": "DB_PASSWORD", "scope": "RUN_TIME", "type": "SECRET",
		}, vars[1])

		// Values must never be reported.
		for _, v := range vars {
			entry, ok := v.(map[string]any)
			require.True(t, ok)
			assert.NotContains(t, entry, "value")
		}
	})

	t.Run("skips nil definitions", func(t *testing.T) {
		spec := &godo.AppSpec{Envs: []*godo.AppVariableDefinition{nil, {Key: "K"}}}
		assert.Len(t, appEnvVars(spec), 1)
	})

	t.Run("is empty with no spec", func(t *testing.T) {
		assert.Empty(t, appEnvVars(nil))
	})
}

// TestAppComponentEnvsCoverage guards componentEnvs against SDK drift. It walks
// every component type ForEachAppComponentSpec visits and asserts that any type
// declaring an Envs field is one componentEnvs actually handles, so a new
// component type in a future godo release fails here rather than silently
// dropping that component's environment variables.
func TestAppComponentEnvsCoverage(t *testing.T) {
	spec := &godo.AppSpec{
		Services:    []*godo.AppServiceSpec{{Name: "svc"}},
		Workers:     []*godo.AppWorkerSpec{{Name: "worker"}},
		Jobs:        []*godo.AppJobSpec{{Name: "job"}},
		StaticSites: []*godo.AppStaticSiteSpec{{Name: "site"}},
		Functions:   []*godo.AppFunctionsSpec{{Name: "fn"}},
		Databases:   []*godo.AppDatabaseSpec{{Name: "db"}},
	}

	visited := 0
	err := spec.ForEachAppComponentSpec(func(c godo.AppComponentSpec) error {
		visited++
		field := reflect.ValueOf(c).Elem().FieldByName("Envs")
		if !field.IsValid() {
			// This component type declares no environment variables.
			assert.Nil(t, componentEnvs(c), "componentEnvs returned vars for %T, which has no Envs field", c)
			return nil
		}

		field.Set(reflect.ValueOf([]*godo.AppVariableDefinition{{Key: "PROBE"}}))
		assert.Len(t, componentEnvs(c), 1, "componentEnvs does not handle %T, so its env vars are dropped", c)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 6, visited, "godo changed the set of app component types; revisit componentEnvs")
}
