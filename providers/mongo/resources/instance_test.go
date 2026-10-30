// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/llx"
)

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
