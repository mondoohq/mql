// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

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
