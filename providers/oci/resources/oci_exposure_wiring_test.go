// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"testing"
)

// exposureSourceFile holds the exposure verdicts this guard reads.
const exposureSourceFile = "oci_exposure.go"

// loadBalancerExposureReceivers names the two receivers whose exposure() has to
// read the address resources.
var loadBalancerExposureReceivers = map[string]string{
	"mqlOciLoadBalancerLoadBalancer":        "load balancer",
	"mqlOciNetworkLoadBalancerLoadBalancer": "network load balancer",
}

// TestLoadBalancerExposureReadsTypedAddresses guards the wiring behind
// hasPublicIp on both load balancers.
//
// The bug: exposure() read GetIpAddresses(), the deprecated dict field. Its
// entries are map[string]any, which implements no isPublic accessor, so the
// type assertion inside ociLoadBalancerHasPublicIp rejected every element, the
// loop ran to completion without reading anything, and hasPublicIp was false on
// every load balancer in every tenancy. internetReachable is a conjunction over
// hasPublicIp, so it could never be true either: an internet-facing load
// balancer passed a "nothing may be exposed" policy with nothing to fail on.
//
// The verdict cannot be reached from a unit test - building the exposure
// resource needs a live connection - so the wiring is pinned at the source
// level instead. Reintroducing the deprecated field here fails this test.
func TestLoadBalancerExposureReadsTypedAddresses(t *testing.T) {
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, exposureSourceFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", exposureSourceFile, err)
	}

	seen := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "exposure" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		ident, ok := star.X.(*ast.Ident)
		if !ok {
			continue
		}
		what, wanted := loadBalancerExposureReceivers[ident.Name]
		if !wanted {
			continue
		}
		seen[ident.Name] = true

		calls := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				calls[sel.Sel.Name] = true
			}
			return true
		})

		if !calls["GetAddresses"] {
			t.Errorf("the %s exposure() must read GetAddresses(); only the address resources carry isPublic", what)
		}
		if calls["GetIpAddresses"] {
			t.Errorf("the %s exposure() reads the deprecated GetIpAddresses(); its dicts answer no isPublic, so hasPublicIp reads false for every balancer", what)
		}
	}

	for receiver, what := range loadBalancerExposureReceivers {
		if !seen[receiver] {
			t.Errorf("no exposure() found on the %s (%s); this guard has gone stale", what, receiver)
		}
	}
}
