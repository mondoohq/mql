// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "go.mongodb.org/mongo-driver/v2/bson"

// authEnforced reports whether the server requires clients to authenticate.
// security.authorization (or --auth) turns it on, and so does internal
// authentication: a keyFile or any cluster auth mode (including the sendKeyFile
// and sendX509 steps of a keyFile-to-x509 migration) implies authorization
// even when security.authorization is not set. transitionToAuth is the
// exception, it accepts unauthenticated clients while a deployment migrates.
func authEnforced(parsed bson.M) bool {
	if toBool(deepGet(parsed, "security", "transitionToAuth")) {
		return false
	}
	if toStr(deepGet(parsed, "security", "authorization")) == "enabled" {
		return true
	}
	if toStr(deepGet(parsed, "security", "keyFile")) != "" {
		return true
	}
	switch toStr(deepGet(parsed, "security", "clusterAuthMode")) {
	case "keyFile", "sendKeyFile", "x509", "sendX509":
		return true
	}
	return false
}
