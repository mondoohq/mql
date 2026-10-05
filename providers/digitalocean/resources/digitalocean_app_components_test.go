// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
)

func TestComponentRoutes(t *testing.T) {
	prefix := func(s string) *godo.AppIngressSpecRuleStringMatch {
		return &godo.AppIngressSpecRuleStringMatch{Prefix: &s}
	}
	exact := "/healthz"
	rule := func(component string, path *godo.AppIngressSpecRuleStringMatch) *godo.AppIngressSpecRule {
		return &godo.AppIngressSpecRule{
			Match:     &godo.AppIngressSpecRuleMatch{Path: path},
			Component: &godo.AppIngressSpecRuleRoutingComponent{Name: component},
		}
	}
	// The shape App Platform returns for a deployed app: component routes are
	// moved into the ingress rules and the per-component routes are gone.
	spec := &godo.AppSpec{
		Ingress: &godo.AppIngressSpec{Rules: []*godo.AppIngressSpecRule{
			rule("web", prefix("/api")),
			rule("scaled", prefix("/scaled")),
			rule("web", &godo.AppIngressSpecRuleStringMatch{Exact: &exact}),
			rule("site", prefix("/")),
			nil,
			{Match: &godo.AppIngressSpecRuleMatch{Path: prefix("/redirect")}},
			rule("web", nil),
		}},
	}

	assert.Equal(t, []any{"/api", "/healthz"}, componentRoutes(spec, "web", nil))
	assert.Equal(t, []any{"/"}, componentRoutes(spec, "site", nil))
	assert.Equal(t, []any{}, componentRoutes(spec, "worker", nil))
	assert.Equal(t, []any{}, componentRoutes(spec, "web2", []any{"/legacy"}),
		"ingress rules are authoritative once a spec has them")

	legacy := []any{"/legacy"}
	assert.Equal(t, legacy, componentRoutes(&godo.AppSpec{}, "web", legacy))
	assert.Equal(t, legacy, componentRoutes(nil, "web", legacy))
}
