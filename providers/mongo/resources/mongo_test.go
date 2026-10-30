// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func TestDeepGet(t *testing.T) {
	m := bson.M{"net": bson.M{"tls": bson.M{"mode": "requireTLS"}}, "security": bson.M{"authorization": "enabled"}}
	if got := toStr(deepGet(m, "net", "tls", "mode")); got != "requireTLS" {
		t.Errorf("deepGet mode = %q", got)
	}
	if got := toStr(deepGet(m, "security", "authorization")); got != "enabled" {
		t.Errorf("deepGet authorization = %q", got)
	}
	// missing paths return nil without panicking
	if deepGet(m, "net", "ssl", "mode") != nil {
		t.Error("expected nil for missing path")
	}
	if deepGet(nil, "a", "b") != nil {
		t.Error("expected nil for nil root")
	}
}

func TestToIntBool(t *testing.T) {
	if toInt(int32(5)) != 5 || toInt(int64(7)) != 7 || toInt(float64(9)) != 9 || toInt("x") != 0 {
		t.Error("toInt conversions wrong")
	}
	if !toBool(true) || toBool("nope") {
		t.Error("toBool conversions wrong")
	}
}

func TestPrivilegedAndBuiltinRoles(t *testing.T) {
	for _, r := range []string{"root", "readWriteAnyDatabase", "userAdminAnyDatabase"} {
		if _, ok := privilegedRoles[r]; !ok {
			t.Errorf("%q should be a privileged role", r)
		}
	}
	if _, ok := privilegedRoles["read"]; ok {
		t.Error("read should not be a privileged role")
	}
	if _, ok := builtinRoles["read"]; !ok {
		t.Error("read should be a built-in role")
	}
	if _, ok := builtinRoles["appReadMetrics"]; ok {
		t.Error("a custom role should not be in builtinRoles")
	}
}

func TestIDBuilders(t *testing.T) {
	if got := roleResourceID("SRV", "appdb", "appReadMetrics"); got != "SRV/role/appdb.appReadMetrics" {
		t.Errorf("roleResourceID = %q", got)
	}
	if got := userResourceID("SRV", "admin", "opsadmin"); got != "SRV/user/admin.opsadmin" {
		t.Errorf("userResourceID = %q", got)
	}
}

// The messages are the server's own, captured from MongoDB 8.0 for an account
// without clusterMonitor and for a connection without credentials.
func TestClassifyRefusal(t *testing.T) {
	forbidden := mongo.CommandError{Code: 13, Name: "Unauthorized",
		Message: `not authorized on admin to execute command { getCmdLineOpts: 1, lsid: { id: UUID("35d25205-fad1-4393-98ad-9bdbb983fee2") }, $db: "admin" }`}
	err := classifyRefusal(forbidden, "getCmdLineOpts")
	if !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("want forbidden, got %v (%v)", llx.KindOf(err), err)
	}
	var le *llx.Error
	if !errors.As(err, &le) || len(le.Permissions) != 1 || le.Permissions[0] != "getCmdLineOpts" {
		t.Errorf("want the getCmdLineOpts permission named, got %+v", le)
	}

	unauth := mongo.CommandError{Code: 13, Name: "Unauthorized", Message: "Command getCmdLineOpts requires authentication"}
	if err := classifyRefusal(unauth, "getCmdLineOpts"); !errors.Is(err, llx.ErrUnauthenticated) {
		t.Errorf("want unauthenticated, got %v (%v)", llx.KindOf(err), err)
	}

	// Anything that is not a refusal keeps its own error and no kind.
	other := mongo.CommandError{Code: 59, Name: "CommandNotFound", Message: "no such command"}
	if err := classifyRefusal(other, "getCmdLineOpts"); llx.KindOf(err) != llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		t.Errorf("want unclassified, got %v", llx.KindOf(err))
	}
	transport := errors.New("connection reset by peer")
	if err := classifyRefusal(transport, "getCmdLineOpts"); err != transport {
		t.Errorf("transport error must pass through, got %v", err)
	}
}
