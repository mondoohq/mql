// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// internetGateway builds a gateway resource whose enabled flag was read.
func internetGateway(enabled bool) *mqlOciNetworkInternetGateway {
	return &mqlOciNetworkInternetGateway{
		IsEnabled: plugin.TValue[bool]{Data: enabled, State: plugin.StateIsSet},
	}
}

// routeToGateway builds a route rule forwarding dest at a target of the given
// type. An internet gateway target also carries the gateway resource, which is
// what the verdict reads to tell an enabled gateway from a disabled one.
func routeToGateway(dest string, targetType string, igw *mqlOciNetworkInternetGateway) any {
	route := &mqlOciNetworkRouteTableRoute{
		Destination: plugin.TValue[string]{Data: dest, State: plugin.StateIsSet},
		TargetType:  plugin.TValue[string]{Data: targetType, State: plugin.StateIsSet},
	}
	route.InternetGateway = plugin.TValue[*mqlOciNetworkInternetGateway]{
		Data:  igw,
		State: plugin.StateIsSet,
	}
	return route
}

// routeTableWith builds a route table whose rules were read.
func routeTableWith(routes ...any) *mqlOciNetworkRouteTable {
	return &mqlOciNetworkRouteTable{
		Routes: plugin.TValue[[]any]{Data: routes, State: plugin.StateIsSet},
	}
}

// subnetRoutedBy builds a subnet whose route table reference was resolved.
func subnetRoutedBy(rt *mqlOciNetworkRouteTable) *mqlOciNetworkSubnet {
	return &mqlOciNetworkSubnet{
		RouteTable: plugin.TValue[*mqlOciNetworkRouteTable]{Data: rt, State: plugin.StateIsSet},
	}
}

// vnicRoutedBy builds a VNIC that overrides its subnet's routing with rt.
func vnicRoutedBy(rt *mqlOciNetworkRouteTable) *mqlOciComputeVnic {
	return &mqlOciComputeVnic{
		RouteTable: plugin.TValue[*mqlOciNetworkRouteTable]{Data: rt, State: plugin.StateIsSet},
	}
}

// TestOciVnicReachesInternet pins which route table decides an instance's
// internet reachability.
//
// The bug: the verdict read the subnet's route table and nothing else, while
// OCI per-resource routing lets a VNIC carry a route table of its own that
// governs the interface instead. That is wrong in both directions. A VNIC
// routed to an internet gateway from a subnet with no such route reported
// internetReachable false, so an exposed instance passed a "nothing may be
// reachable" policy; a VNIC routed away from an internet gateway on a public
// subnet reported true, so a hardened instance failed one.
func TestOciVnicReachesInternet(t *testing.T) {
	openTable := routeTableWith(routeToGateway("0.0.0.0/0", "INTERNET_GATEWAY", internetGateway(true)))
	closedTable := routeTableWith(routeToGateway("0.0.0.0/0", "NAT_GATEWAY", nil))
	ipv6Table := routeTableWith(routeToGateway("::/0", "INTERNET_GATEWAY", internetGateway(true)))
	disabledGatewayTable := routeTableWith(routeToGateway("0.0.0.0/0", "INTERNET_GATEWAY", internetGateway(false)))

	// A VNIC that states no route table of its own. Reading it yields null,
	// which is what sends the verdict to the subnet.
	noOverride := &mqlOciComputeVnic{
		RouteTable: plugin.TValue[*mqlOciNetworkRouteTable]{State: plugin.StateIsSet | plugin.StateIsNull},
	}
	// A VNIC that names a route table the scan could not read: it lives in a
	// compartment the scanner cannot list, or the call was refused.
	unreadable := &mqlOciComputeVnic{
		RouteTable: plugin.TValue[*mqlOciNetworkRouteTable]{
			State: plugin.StateIsSet | plugin.StateIsNull,
			Error: errors.New("oci.network.routeTable not found"),
		},
	}

	tests := []struct {
		name   string
		vnic   *mqlOciComputeVnic
		subnet *mqlOciNetworkSubnet
		want   bool
	}{
		// The VNIC's own table decides, whichever way it points.
		{
			name:   "vnic routes to an internet gateway from a subnet that does not",
			vnic:   vnicRoutedBy(openTable),
			subnet: subnetRoutedBy(closedTable),
			want:   true,
		},
		{
			// The case that proves the fix: the subnet's table is the wide-open
			// one, and reading it instead of the VNIC's reports an instance as
			// internet-reachable that per-resource routing has taken off the
			// internet.
			name:   "vnic routes away from the internet on a subnet that routes to it",
			vnic:   vnicRoutedBy(closedTable),
			subnet: subnetRoutedBy(openTable),
			want:   false,
		},
		{
			name:   "vnic routes ::/0 to an internet gateway",
			vnic:   vnicRoutedBy(ipv6Table),
			subnet: subnetRoutedBy(closedTable),
			want:   true,
		},
		{
			name:   "vnic routes to a disabled internet gateway",
			vnic:   vnicRoutedBy(disabledGatewayTable),
			subnet: subnetRoutedBy(openTable),
			want:   false,
		},

		// No override: the subnet's table is the one in force.
		{
			name:   "vnic sets no route table on a subnet that routes to the internet",
			vnic:   noOverride,
			subnet: subnetRoutedBy(openTable),
			want:   true,
		},
		{
			name:   "vnic sets no route table on a subnet that does not",
			vnic:   noOverride,
			subnet: subnetRoutedBy(closedTable),
			want:   false,
		},

		// Unread evidence must not read as "not exposed".
		{
			name:   "vnic names a route table that could not be read",
			vnic:   unreadable,
			subnet: subnetRoutedBy(closedTable),
			want:   true,
		},

		// Degenerate inputs.
		{
			name:   "no vnic and no subnet",
			vnic:   nil,
			subnet: nil,
			want:   false,
		},
		{
			name:   "no vnic falls back to the subnet",
			vnic:   nil,
			subnet: subnetRoutedBy(openTable),
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ociVnicReachesInternet(tt.vnic, tt.subnet)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestInstanceExposureRoutesOnTheVnic guards the wiring behind
// hasRouteToInternet on a compute instance.
//
// The verdict resource cannot be built from a unit test, so the call is pinned
// at the source level the way the load balancer address wiring is. Routing the
// instance verdict back through ociSubnetReachesInternet fails this test.
func TestInstanceExposureRoutesOnTheVnic(t *testing.T) {
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, exposureSourceFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", exposureSourceFile, err)
	}

	found := false
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
		if !ok || ident.Name != "mqlOciComputeInstance" {
			continue
		}
		found = true

		called := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); ok {
				called[name.Name] = true
			}
			return true
		})

		if !called["ociVnicReachesInternet"] {
			t.Error("the compute instance exposure() must route on ociVnicReachesInternet; a VNIC can carry a route table that overrides its subnet's")
		}
		if called["ociSubnetReachesInternet"] {
			t.Error("the compute instance exposure() reads the subnet's route table directly, which ignores per-resource routing on the VNIC")
		}
	}

	if !found {
		t.Error("no exposure() found on mqlOciComputeInstance; this guard has gone stale")
	}
}

// TestVnicMappingCachesRouteTableId guards the other half of the wiring: the
// accessor can only answer if the creator cached the OCID the VNIC reported.
//
// Dropping the assignment leaves routeTable reading null on every VNIC, which
// silently sends every instance verdict back to the subnet's route table. The
// mapping needs a live connection to exercise, so the field read is pinned at
// the source level.
func TestVnicMappingCachesRouteTableId(t *testing.T) {
	const mappingSourceFile = "network.go"

	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, mappingSourceFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", mappingSourceFile, err)
	}

	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ociVnicToMql" || fn.Recv != nil {
			continue
		}
		found = true

		reads := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				reads[sel.Sel.Name] = true
			}
			return true
		})

		if !reads["RouteTableId"] {
			t.Error("ociVnicToMql must read vnic.RouteTableId; without it the routeTable reference is null on every VNIC")
		}
		if !reads["cacheRouteTableID"] {
			t.Error("ociVnicToMql must set cacheRouteTableID; the routeTable accessor resolves from it")
		}
	}

	if !found {
		t.Error("no ociVnicToMql found; this guard has gone stale")
	}
}
