// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func str(v string) plugin.TValue[string] {
	return plugin.TValue[string]{Data: v, State: plugin.StateIsSet}
}

// TestSnmpGroupIDSeparatesSecurityLevels pins the cache key against the shape
// that collapsed it. A v3 group name may be defined once per security level,
// each with its own views, so a key built from name and version alone returns
// the cached first instance for the second definition: the priv group granting
// write disappears behind the noauth group that only reads. That is an
// under-report of a privilege, which no assertion on the list can detect.
func TestSnmpGroupIDSeparatesSecurityLevels(t *testing.T) {
	noauth := &mqlAristaEosSnmpGroup{
		Name: str("MONITORING"), Version: str("v3"), SecurityLevel: str("noauth"),
	}
	priv := &mqlAristaEosSnmpGroup{
		Name: str("MONITORING"), Version: str("v3"), SecurityLevel: str("priv"),
	}

	a, err := noauth.id()
	if err != nil {
		t.Fatalf("noauth id: %v", err)
	}
	b, err := priv.id()
	if err != nil {
		t.Fatalf("priv id: %v", err)
	}
	if a == b {
		t.Fatalf("both security levels share the cache key %q, so one is dropped", a)
	}

	// Context qualifies the same statement and must separate too.
	withCtx := &mqlAristaEosSnmpGroup{
		Name: str("MONITORING"), Version: str("v3"), SecurityLevel: str("priv"),
		Context: str("vrf-mgmt"),
	}
	c, err := withCtx.id()
	if err != nil {
		t.Fatalf("context id: %v", err)
	}
	if c == b {
		t.Fatalf("a context-qualified group shares the cache key %q", c)
	}

	// The same definition read twice must still collapse.
	again, _ := (&mqlAristaEosSnmpGroup{
		Name: str("MONITORING"), Version: str("v3"), SecurityLevel: str("priv"),
	}).id()
	if again != b {
		t.Fatalf("the same group produced two keys: %q and %q", b, again)
	}
}
