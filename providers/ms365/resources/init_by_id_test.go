// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func riskyUserWithId(id string) *mqlMicrosoftSecurityRiskyUser {
	return &mqlMicrosoftSecurityRiskyUser{Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet}}
}

func riskyUserId(r *mqlMicrosoftSecurityRiskyUser) string { return r.Id.Data }

func TestInitFromParentList(t *testing.T) {
	listFrom := func(items ...any) func() ([]any, error) {
		return func() ([]any, error) { return items, nil }
	}
	mustNotList := func() ([]any, error) {
		t.Fatal("list must not be called")
		return nil, nil
	}

	t.Run("found returns the listed resource", func(t *testing.T) {
		want := riskyUserWithId("b")
		args := map[string]*llx.RawData{"id": llx.StringData("b")}
		gotArgs, res, err := initFromParentList("microsoft.security.riskyUser", args,
			listFrom(riskyUserWithId("a"), want, riskyUserWithId("c")), riskyUserId)
		require.NoError(t, err)
		assert.Nil(t, gotArgs)
		assert.Same(t, want, res)
	})

	t.Run("missing id is a not-found error", func(t *testing.T) {
		args := map[string]*llx.RawData{"id": llx.StringData("zzz")}
		gotArgs, res, err := initFromParentList("microsoft.security.riskyUser", args,
			listFrom(riskyUserWithId("a")), riskyUserId)
		require.Error(t, err)
		assert.Equal(t, `microsoft.security.riskyUser with id "zzz" not found`, err.Error())
		assert.Nil(t, gotArgs)
		assert.Nil(t, res)
	})

	t.Run("empty list is a not-found error", func(t *testing.T) {
		args := map[string]*llx.RawData{"id": llx.StringData("a")}
		_, res, err := initFromParentList("microsoft.security.riskyUser", args, listFrom(), riskyUserId)
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("items of another type are skipped", func(t *testing.T) {
		args := map[string]*llx.RawData{"id": llx.StringData("a")}
		other := &mqlMicrosoftSecurityRiskDetection{Id: plugin.TValue[string]{Data: "a"}}
		_, res, err := initFromParentList("microsoft.security.riskyUser", args, listFrom(other), riskyUserId)
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("list error propagates", func(t *testing.T) {
		listErr := errors.New("forbidden")
		args := map[string]*llx.RawData{"id": llx.StringData("a")}
		_, res, err := initFromParentList("microsoft.security.riskyUser", args,
			func() ([]any, error) { return nil, listErr }, riskyUserId)
		require.ErrorIs(t, err, listErr)
		assert.Nil(t, res)
	})

	t.Run("fully populated args pass through without listing", func(t *testing.T) {
		args := map[string]*llx.RawData{
			"id":        llx.StringData("a"),
			"riskLevel": llx.StringData("high"),
		}
		gotArgs, res, err := initFromParentList("microsoft.security.riskyUser", args, mustNotList, riskyUserId)
		require.NoError(t, err)
		assert.Equal(t, args, gotArgs)
		assert.Nil(t, res)
	})

	t.Run("no id passes through without listing", func(t *testing.T) {
		args := map[string]*llx.RawData{}
		gotArgs, res, err := initFromParentList("microsoft.security.riskyUser", args, mustNotList, riskyUserId)
		require.NoError(t, err)
		assert.Equal(t, args, gotArgs)
		assert.Nil(t, res)
	})

	t.Run("empty id passes through without listing", func(t *testing.T) {
		args := map[string]*llx.RawData{"id": llx.StringData("")}
		gotArgs, res, err := initFromParentList("microsoft.security.riskyUser", args, mustNotList, riskyUserId)
		require.NoError(t, err)
		assert.Equal(t, args, gotArgs)
		assert.Nil(t, res)
	})
}

// Each of these resources is listed by a parent and carries an id. Without an
// init, a direct query such as microsoft.security.riskyUser(id: "...") builds
// a resource with every field null.
func TestResourcesQueryableByIdHaveInit(t *testing.T) {
	for _, name := range []string{
		ResourceMicrosoftConditionalAccessPolicy,
		ResourceMicrosoftConditionalAccessIpNamedLocation,
		ResourceMicrosoftConditionalAccessCountryNamedLocation,
		ResourceMicrosoftOauth2PermissionGrant,
		ResourceMicrosoftSecurityRiskyUser,
		ResourceMicrosoftSecurityRiskDetection,
		ResourceMicrosoftSecurityRiskyServicePrincipal,
		ResourceMicrosoftSecurityServicePrincipalRiskDetection,
		ResourceMicrosoftSecurityAlert,
		ResourceMicrosoftSecurityInformationProtectionSensitivityLabel,
		ResourceMicrosoftPoliciesActivityBasedTimeoutPolicy,
		ResourceMicrosoftPoliciesTokenLifetimePolicy,
		ResourceMicrosoftPoliciesClaimsMappingPolicy,
		ResourceMicrosoftPoliciesTokenIssuancePolicy,
		ResourceMicrosoftPoliciesHomeRealmDiscoveryPolicy,
	} {
		f, ok := resourceFactories[name]
		require.True(t, ok, name)
		assert.NotNil(t, f.Init, name)
	}
}
