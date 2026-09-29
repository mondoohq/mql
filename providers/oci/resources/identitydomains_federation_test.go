// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestOciIdentityProviderArgs(t *testing.T) {
	provider := &identitydomains.IdentityProvider{
		Id:                                common.String("idp-1"),
		PartnerName:                       common.String("Corporate Entra ID"),
		Enabled:                           common.Bool(true),
		Type:                              identitydomains.IdentityProviderTypeSaml,
		PartnerProviderId:                 common.String("https://sts.windows.net/tenant/"),
		SignatureHashAlgorithm:            identitydomains.IdentityProviderSignatureHashAlgorithm1,
		JitUserProvEnabled:                common.Bool(true),
		JitUserProvCreateUserEnabled:      common.Bool(true),
		JitUserProvGroupAssignmentMethod:  identitydomains.IdentityProviderJitUserProvGroupAssignmentMethodMerge,
		SigningCertificate:                common.String("MIIC-signing-cert"),
		Metadata:                          common.String("<EntityDescriptor/>"),
		JitUserProvGroupSAMLAttributeName: common.String("groups"),
		UrnIetfParamsScimSchemasOracleIdcsExtensionSocialIdentityProvider: &identitydomains.ExtensionSocialIdentityProvider{
			ConsumerKey:    common.String("client-id"),
			ConsumerSecret: common.String("s3cr3t-consumer-value"),
		},
	}

	args := ociIdentityProviderArgs("domain-1", provider)

	t.Run("fields are mapped from the provider", func(t *testing.T) {
		assert.Equal(t, "domain-1/identityProvider/idp-1", args["__id"].Value)
		assert.Equal(t, "Corporate Entra ID", args["name"].Value)
		assert.Equal(t, "SAML", args["type"].Value)
		assert.Equal(t, "SHA-1", args["signatureHashAlgorithm"].Value)
		assert.Equal(t, true, args["jitUserProvCreateUserEnabled"].Value)
		assert.Equal(t, "Merge", args["jitUserProvGroupAssignmentMethod"].Value)
	})

	t.Run("an unset flag is null, not false", func(t *testing.T) {
		assert.Nil(t, args["requiresEncryptedAssertion"].Value)
		assert.Nil(t, args["jitUserProvGroupAssertionAttributeEnabled"].Value)
	})

	t.Run("the social provider's client secret is not emitted", func(t *testing.T) {
		serialized, err := json.Marshal(argValues(args))
		require.NoError(t, err)
		assert.NotContains(t, string(serialized), "s3cr3t-consumer-value")
		assert.NotContains(t, string(serialized), "MIIC-signing-cert")
	})
}

// argValues extracts the values a resource would be created with, which is
// what ends up in scan results.
func argValues(args map[string]*llx.RawData) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = v.Value
	}
	return out
}

func TestOciSettingBoolAndInt(t *testing.T) {
	signingCert := func(s *identitydomains.Setting) *bool { return s.SigningCertPublicAccess }
	retention := func(s *identitydomains.Setting) *int { return s.AuditEventRetentionPeriod }

	t.Run("no settings record reads null", func(t *testing.T) {
		var b plugin.TValue[bool]
		assert.False(t, ociSettingBool(nil, &b, signingCert))
		assert.True(t, b.IsNull())

		var i plugin.TValue[int64]
		assert.Zero(t, ociSettingInt(nil, &i, retention))
		assert.True(t, i.IsNull())
	})

	t.Run("an unset value reads null", func(t *testing.T) {
		var b plugin.TValue[bool]
		ociSettingBool(&identitydomains.Setting{}, &b, signingCert)
		assert.True(t, b.IsNull())

		var i plugin.TValue[int64]
		ociSettingInt(&identitydomains.Setting{}, &i, retention)
		assert.True(t, i.IsNull())
	})

	t.Run("a set value is reported", func(t *testing.T) {
		setting := &identitydomains.Setting{
			SigningCertPublicAccess:   common.Bool(true),
			AuditEventRetentionPeriod: common.Int(90),
		}
		var b plugin.TValue[bool]
		assert.True(t, ociSettingBool(setting, &b, signingCert))
		assert.False(t, b.IsNull())

		var i plugin.TValue[int64]
		assert.Equal(t, int64(90), ociSettingInt(setting, &i, retention))
		assert.False(t, i.IsNull())
	})
}
