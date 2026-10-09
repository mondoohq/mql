// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"github.com/stretchr/testify/assert"
)

const secretValue = "never-read-secret"

func TestCredentialMappingNeverReadsSecrets(t *testing.T) {
	meta := &identitydomains.Meta{Created: common.String("2026-01-02T03:04:05Z")}
	creds := []ociDomainCredential{
		apiKeyCredential(identitydomains.ApiKey{Id: common.String("k1"), Fingerprint: common.String("aa:bb"), Key: common.String(secretValue), Meta: meta,
			User: &identitydomains.ApiKeyUser{Value: common.String("u1"), Ocid: common.String("ocid1.user..u1")}}),
		authTokenCredential(identitydomains.AuthToken{Id: common.String("t1"), Token: common.String(secretValue), Status: identitydomains.AuthTokenStatusActive,
			ExpiresOn: common.String("2027-01-01T00:00:00Z"), Meta: meta}),
		customerSecretKeyCredential(identitydomains.CustomerSecretKey{Id: common.String("s1"), SecretKey: common.String(secretValue), DisplayName: common.String("s3 key")}),
		oauth2ClientCredential(identitydomains.OAuth2ClientCredential{Id: common.String("o1"), Secret: common.String(secretValue), Name: common.String("ci")}),
		smtpCredential(identitydomains.SmtpCredential{Id: common.String("m1"), Password: common.String(secretValue), UserName: common.String("smtp-user")}),
		dbCredential(identitydomains.UserDbCredential{Id: common.String("d1"), DbPassword: common.String(secretValue), MixedDbPassword: common.String(secretValue)}),
	}
	for _, c := range creds {
		assert.NotContains(t, fmt.Sprintf("%+v", c), secretValue, "credential %s must not carry its secret", c.typ)
	}

	key := creds[0]
	assert.Equal(t, "apiKey", key.typ)
	assert.Equal(t, "aa:bb", key.fingerprint)
	assert.Equal(t, "u1", key.userID)
	assert.Equal(t, 2026, key.created.Year())
	assert.Nil(t, key.expires, "an API key does not expire")

	token := creds[1]
	assert.Equal(t, "ACTIVE", token.status)
	assert.Equal(t, 2027, token.expires.Year())

	assert.Equal(t, "s3 key", creds[2].name)
	assert.Equal(t, "smtp-user", creds[4].name)
	assert.Nil(t, creds[2].created, "a credential without meta has no creation time, not year 1")
}

func TestOciScimUserFilter(t *testing.T) {
	assert.Equal(t, `user.value eq "abc123"`, ociScimUserFilter("abc123"))
	assert.Equal(t, `user.value eq "a\"b\\c"`, ociScimUserFilter(`a"b\c`), "a quote or backslash cannot end the filter value")
}

func TestSocialIdentityProviderArgsNeverReadsSecret(t *testing.T) {
	args := socialIdentityProviderArgs("dom", 0, identitydomains.SocialIdentityProvider{
		Id: common.String("p1"), Name: common.String("Google"), ConsumerSecret: common.String(secretValue),
		Enabled: common.Bool(true), RegistrationEnabled: common.Bool(true),
	})
	for k, v := range args {
		assert.NotEqual(t, secretValue, v.Value, "the consumer secret must not reach field %s", k)
	}
	assert.Equal(t, true, args["registrationEnabled"].Value)
	assert.Equal(t, false, args["accountLinkingEnabled"].Value)
}
