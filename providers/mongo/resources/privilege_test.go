// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// loadRolesInfo reads the rolesInfo documents captured from a MongoDB 8.0
// server: the built-in roles plus the custom roles of the sweep fixtures
// (godmode: anyAction on anyResource; anyres: find on anyResource; escalator
// and lvl1: inherit userAdminAnyDatabase / root).
func loadRolesInfo(t *testing.T) map[string]bson.M {
	t.Helper()
	raw, err := os.ReadFile("testdata/rolesinfo-admin-8.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc bson.M
	if err := bson.UnmarshalExtJSON(raw, false, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]bson.M{}
	for _, r := range asArray(doc["roles"]) {
		m := asMap(r)
		out[toStr(m["role"])] = m
	}
	return out
}

func TestRoleDocGrantsPrivilegedAccess(t *testing.T) {
	roles := loadRolesInfo(t)
	tests := map[string]bool{
		// custom roles that are root in all but name
		"godmode": true, // anyAction on anyResource
		"anyres":  true, // find on anyResource reads admin.system.users
		// built-in roles whose privileges amount to a privileged one
		"root":              true,
		"userAdmin":         true, // createUser, grantRole on its database
		"readAnyDatabase":   true, // find on every database
		"searchCoordinator": true, // find on every database
		"clusterManager":    true, // dbCheck on anyResource
		// built-in roles that must stay unprivileged
		"read":           false,
		"readWrite":      false,
		"dbAdmin":        false,
		"clusterMonitor": false, // has {db:"", system_buckets:""} and {db:"", collection:""} monitoring actions
		"enableSharding": false,
	}
	for name, want := range tests {
		doc, ok := roles[name]
		if !ok {
			t.Fatalf("fixture lacks role %s", name)
		}
		if got := roleDocGrantsPrivilegedAccess(doc); got != want {
			t.Errorf("%s: privileged = %v, want %v", name, got, want)
		}
	}
}

func TestPrivilegeIsPrivilegedShapes(t *testing.T) {
	tests := []struct {
		name string
		priv bson.M
		want bool
	}{
		{"every database, monitoring only", bson.M{"resource": bson.M{"db": "", "collection": ""}, "actions": bson.A{"collStats", "dbStats"}}, false},
		{"every database, find", bson.M{"resource": bson.M{"db": "", "collection": ""}, "actions": bson.A{"find"}}, true},
		{"one database, find", bson.M{"resource": bson.M{"db": "app", "collection": ""}, "actions": bson.A{"find", "insert"}}, false},
		{"buckets everywhere, find", bson.M{"resource": bson.M{"db": "", "system_buckets": ""}, "actions": bson.A{"find"}}, false},
		{"grantRole on one database", bson.M{"resource": bson.M{"db": "app", "collection": ""}, "actions": bson.A{"grantRole"}}, true},
		{"viewUser on the cluster", bson.M{"resource": bson.M{"cluster": true}, "actions": bson.A{"viewUser"}}, false},
		{"anyResource without actions", bson.M{"resource": bson.M{"anyResource": true}, "actions": bson.A{}}, false},
		{"missing resource", bson.M{"actions": bson.A{"find"}}, false},
	}
	for _, tt := range tests {
		if got := privilegeIsPrivileged(tt.priv); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSystemBucketsData(t *testing.T) {
	if v := systemBucketsData(bson.M{"db": "", "system_buckets": ""}); v.Value != "" {
		t.Errorf("every-bucket resource: got %v, want \"\"", v.Value)
	}
	if v := systemBucketsData(bson.M{"db": "app", "system_buckets": "weather"}); v.Value != "weather" {
		t.Errorf("named bucket: got %v", v.Value)
	}
	if v := systemBucketsData(bson.M{"db": "", "collection": ""}); v.Value != nil {
		t.Errorf("collection resource: got %v, want null", v.Value)
	}
}

// getCmdLineOpts "parsed" documents captured from MongoDB 8.0.32.
func TestAuthEnforced(t *testing.T) {
	tests := []struct {
		name   string
		parsed bson.M
		want   bool
	}{
		{"authorization enabled", bson.M{"security": bson.M{"authorization": "enabled", "javascriptEnabled": false}}, true},
		{"keyFile only", bson.M{"net": bson.M{"bindIp": "127.0.0.1", "port": int32(27117)}, "security": bson.M{"keyFile": "/etc/mongod-sweep/keyfile"}}, true},
		{"x509 cluster auth", bson.M{"security": bson.M{"clusterAuthMode": "x509"}}, true},
		{"sendX509 migration step without keyFile", bson.M{"security": bson.M{"clusterAuthMode": "sendX509"}}, true},
		{"keyFile in transition", bson.M{"security": bson.M{"keyFile": "/k", "transitionToAuth": true}}, false},
		{"nothing set", bson.M{"net": bson.M{"port": int32(27117)}}, false},
		{"authorization disabled", bson.M{"security": bson.M{"authorization": "disabled"}}, false},
	}
	for _, tt := range tests {
		if got := authEnforced(tt.parsed); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
