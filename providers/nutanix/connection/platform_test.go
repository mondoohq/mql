// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestIdentifiers(t *testing.T) {
	if got := NewPrismCentralIdentifier("pc.example.com"); got != platformIdPrismCentral+"pc.example.com" {
		t.Errorf("prism central identifier = %q", got)
	}
	if got := NewClusterIdentifier("uuid-1"); got != platformIdCluster+"uuid-1" {
		t.Errorf("cluster identifier = %q", got)
	}
	if got := NewNodeIdentifier("uuid-2"); got != platformIdNode+"uuid-2" {
		t.Errorf("node identifier = %q", got)
	}
}

func TestNewClusterPlatform(t *testing.T) {
	pf := NewClusterPlatform("uuid-1")
	if pf.Name != "nutanix-cluster" {
		t.Errorf("Name = %q, want nutanix-cluster", pf.Name)
	}
	if pf.Kind != "api" {
		t.Errorf("Kind = %q, want api", pf.Kind)
	}
	if len(pf.Family) != 1 || pf.Family[0] != Family {
		t.Errorf("Family = %v, want [%s]", pf.Family, Family)
	}
	last := pf.TechnologyUrlSegments[len(pf.TechnologyUrlSegments)-1]
	if last != "uuid-1" {
		t.Errorf("last url segment = %q, want uuid-1", last)
	}
}

func TestNodePlatformKind(t *testing.T) {
	pf := NewNodePlatform("n1")
	if pf.Kind != inventory.AssetKindBaremetal {
		t.Errorf("node Kind = %q, want %q", pf.Kind, inventory.AssetKindBaremetal)
	}
}

func connWithOptions(opts map[string]string) *NutanixConnection {
	return &NutanixConnection{
		Conf:     &inventory.Config{Options: opts},
		endpoint: "pc.example.com",
	}
}

func TestPlatformInfoScoping(t *testing.T) {
	tests := []struct {
		name     string
		opts     map[string]string
		wantName string
	}{
		{"root", map[string]string{}, "nutanix-prism-central"},
		{"cluster", map[string]string{"cluster-id": "c1"}, "nutanix-cluster"},
		{"node", map[string]string{"node-id": "n1"}, "nutanix-node"},
		{"node-precedence", map[string]string{"cluster-id": "c1", "node-id": "n1"}, "nutanix-node"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pf := connWithOptions(tc.opts).PlatformInfo()
			if pf.Name != tc.wantName {
				t.Errorf("PlatformInfo().Name = %q, want %q", pf.Name, tc.wantName)
			}
		})
	}
}

func TestPlatformIDs(t *testing.T) {
	if got := connWithOptions(map[string]string{}).PlatformIDs(); got[0] != NewPrismCentralIdentifier("pc.example.com") {
		t.Errorf("root PlatformIDs = %v", got)
	}
	if got := connWithOptions(map[string]string{"cluster-id": "c1"}).PlatformIDs(); got[0] != NewClusterIdentifier("c1") {
		t.Errorf("cluster PlatformIDs = %v", got)
	}
	if got := connWithOptions(map[string]string{"node-id": "n1"}).PlatformIDs(); got[0] != NewNodeIdentifier("n1") {
		t.Errorf("node PlatformIDs = %v", got)
	}
}
