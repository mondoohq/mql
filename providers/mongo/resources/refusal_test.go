// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

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

// A refused getCmdLineOpts must not leave a single default behind: every
// derived field carries the error, and none of them reads as false/"disabled".
func TestSetCmdLineErrorCoversEveryDerivedField(t *testing.T) {
	refusal := llx.Forbidden(errors.New("not authorized"))
	args := map[string]*llx.RawData{
		"__id":       llx.StringData("127.0.0.1:27117"),
		"version":    llx.StringData("8.0.32"),
		"gitVersion": llx.StringData("f9eb55a7"),
		"port":       llx.IntData(27117),
	}
	setCmdLineError(args, refusal)

	res := &mqlMongoInstance{}
	if err := SetAllData(res, args); err != nil {
		t.Fatalf("SetAllData: %v", err)
	}
	for name, field := range map[string]error{
		"bindIp":                res.BindIp.Error,
		"authenticationEnabled": res.AuthenticationEnabled.Error,
		"authorizationEnabled":  res.AuthorizationEnabled.Error,
		"clusterAuthMode":       res.ClusterAuthMode.Error,
		"tlsMode":               res.TlsMode.Error,
		"tlsDisabledProtocols":  res.TlsDisabledProtocols.Error,
		"tlsFIPSMode":           res.TlsFIPSMode.Error,
		"javascriptEnabled":     res.JavascriptEnabled.Error,
		"auditLogDestination":   res.AuditLogDestination.Error,
		"logVerbosity":          res.LogVerbosity.Error,
		"logAppend":             res.LogAppend.Error,
	} {
		if !errors.Is(field, llx.ErrForbidden) {
			t.Errorf("%s: want the refusal, got %v", name, field)
		}
	}
	if res.AuthorizationEnabled.Data || !res.AuthorizationEnabled.IsNull() {
		t.Error("authorizationEnabled must be null, not a value")
	}
	if res.Version.Error != nil || res.Version.Data != "8.0.32" || res.Port.Data != 27117 {
		t.Error("buildInfo fields and port must keep their values")
	}
}
