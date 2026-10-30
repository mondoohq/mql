// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"github.com/stretchr/testify/assert"
)

const secretValue = "never-read-secret"

func TestCredentialMappingNeverReadsSecrets(t *testing.T) {
	meta := &identitydomains.Meta{Created: new("2026-01-02T03:04:05Z")}
	creds := []ociDomainCredential{
		apiKeyCredential(identitydomains.ApiKey{Id: new("k1"), Fingerprint: new("aa:bb"), Key: new(secretValue), Meta: meta,
			User: &identitydomains.ApiKeyUser{Value: new("u1"), Ocid: new("ocid1.user..u1")}}),
		authTokenCredential(identitydomains.AuthToken{Id: new("t1"), Token: new(secretValue), Status: identitydomains.AuthTokenStatusActive,
			ExpiresOn: new("2027-01-01T00:00:00Z"), Meta: meta}),
		customerSecretKeyCredential(identitydomains.CustomerSecretKey{Id: new("s1"), SecretKey: new(secretValue), DisplayName: new("s3 key")}),
		oauth2ClientCredential(identitydomains.OAuth2ClientCredential{Id: new("o1"), Secret: new(secretValue), Name: new("ci")}),
		smtpCredential(identitydomains.SmtpCredential{Id: new("m1"), Password: new(secretValue), UserName: new("smtp-user")}),
		dbCredential(identitydomains.UserDbCredential{Id: new("d1"), DbPassword: new(secretValue), MixedDbPassword: new(secretValue)}),
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
		Id: new("p1"), Name: new("Google"), ConsumerSecret: new(secretValue),
		Enabled: new(true), RegistrationEnabled: new(true),
	})
	for k, v := range args {
		assert.NotEqual(t, secretValue, v.Value, "the consumer secret must not reach field %s", k)
	}
	assert.Equal(t, true, args["registrationEnabled"].Value)
	assert.Equal(t, false, args["accountLinkingEnabled"].Value)
}
