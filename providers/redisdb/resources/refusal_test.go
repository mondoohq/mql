// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func setStructuredErrors(t *testing.T, on bool) {
	t.Helper()
	if on {
		plugin.ReadFeatures(mql.Features{byte(mql.StructuredErrors)})
	} else {
		// a non-empty feature set without the flag turns it off
		plugin.ReadFeatures(mql.Features{byte(mql.MassQueries)})
	}
	t.Cleanup(func() { plugin.ReadFeatures(mql.Features{byte(mql.MassQueries)}) })
}

// The replies Redis 7.2 gave the ACL-restricted users noacl and noconf.
var (
	errACLDenied    = errors.New("NOPERM User noacl has no permissions to run the 'acl|list' command")
	errConfigDenied = errors.New("NOPERM User noconf has no permissions to run the 'config|get' command")
	// Redis 6.2 words it differently
	errConfigDenied62 = errors.New("NOPERM this user has no permissions to run the 'config' command or its subcommand")
)

func TestRefusedListV13KeepsEmptyList(t *testing.T) {
	setStructuredErrors(t, false)
	list, err := refusedList(errACLDenied, "+acl|list")
	if err != nil {
		t.Fatalf("refusedList returned %v with StructuredErrors off", err)
	}
	if list == nil || len(list) != 0 {
		t.Errorf("refusedList = %#v, want an empty non-nil list", list)
	}
}

func TestRefusedListIsForbidden(t *testing.T) {
	setStructuredErrors(t, true)
	list, err := refusedList(errACLDenied, "+acl|list")
	if list != nil {
		t.Errorf("refusedList returned a list %#v alongside the refusal", list)
	}
	if !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("refusedList error kind = %v, want forbidden", llx.KindOf(err))
	}
	var e *llx.Error
	if !errors.As(err, &e) || len(e.Permissions) != 1 || e.Permissions[0] != "+acl|list" {
		t.Errorf("permissions = %+v", e)
	}
	if !errors.Is(err, errACLDenied) {
		t.Errorf("the server's reply was not kept: %v", err)
	}
}

func TestRefusedField(t *testing.T) {
	setStructuredErrors(t, false)
	if err := refusedField(errConfigDenied, "+config|get"); err != nil {
		t.Errorf("refusedField = %v with StructuredErrors off, want nil (field stays null)", err)
	}
	setStructuredErrors(t, true)
	for _, denied := range []error{errConfigDenied, errConfigDenied62} {
		if err := refusedField(denied, "+config|get"); !errors.Is(err, llx.ErrForbidden) {
			t.Errorf("refusedField(%v) kind = %v, want forbidden", denied, llx.KindOf(err))
		}
	}
}

func TestClassifyRefusal(t *testing.T) {
	if err := classifyRefusal(errors.New("WRONGPASS invalid username-password pair or user is disabled."), "+acl|list"); !errors.Is(err, llx.ErrUnauthenticated) {
		t.Errorf("WRONGPASS kind = %v, want unauthenticated", llx.KindOf(err))
	}
	transport := errors.New("dial tcp 192.0.2.1:6379: i/o timeout")
	if err := classifyRefusal(transport, "+acl|list"); llx.KindOf(err) != llx.KindOf(transport) || err != transport {
		t.Errorf("a transport error was classified: %v", err)
	}
}

func TestSetConfigFieldsCarriesRefusal(t *testing.T) {
	setStructuredErrors(t, true)
	r := &mqlRedisdbInstance{}
	r.configErr = refusedField(errConfigDenied, "+config|get")
	r.setConfigFields(map[string]string{}, false)

	if !r.ProtectedMode.IsNull() || !errors.Is(r.ProtectedMode.Error, llx.ErrForbidden) {
		t.Errorf("protectedMode = %+v, want null with a forbidden error", r.ProtectedMode)
	}
	if !errors.Is(r.RequirepassSet.Error, llx.ErrForbidden) || !errors.Is(r.BindsAllInterfaces.Error, llx.ErrForbidden) ||
		!errors.Is(r.TlsAuthClients.Error, llx.ErrForbidden) {
		t.Error("a CONFIG-derived posture field lost the refusal")
	}
	if _, err := r.config(); !errors.Is(err, llx.ErrForbidden) {
		t.Errorf("config() error = %v, want forbidden", err)
	}
}

func TestSetConfigFieldsV13LeavesNull(t *testing.T) {
	setStructuredErrors(t, false)
	r := &mqlRedisdbInstance{}
	r.configErr = refusedField(errConfigDenied, "+config|get")
	r.setConfigFields(map[string]string{}, false)
	if !r.ProtectedMode.IsNull() || r.ProtectedMode.Error != nil {
		t.Errorf("protectedMode = %+v, want a plain null", r.ProtectedMode)
	}
	if res, err := r.config(); res != nil || err != nil || !r.Config.IsNull() {
		t.Errorf("config() = %v, %v; want null", res, err)
	}
}
