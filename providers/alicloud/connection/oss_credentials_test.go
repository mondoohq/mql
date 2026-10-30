// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"testing"

	credential "github.com/aliyun/credentials-go/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCredential is a credential.Credential whose GetCredential result is
// controlled by the test.
type fakeCredential struct {
	credential.Credential
	model *credential.CredentialModel
	err   error
	calls int
}

func (f *fakeCredential) GetCredential() (*credential.CredentialModel, error) {
	f.calls++
	return f.model, f.err
}

// TestDarabonbaOssCredentials covers the adapter that lets OSS see the same
// credential every other service client uses. Without it OSS only ever saw a
// static access key, so the shared credentials file and an ECS instance RAM role
// reached every service except OSS, and OSS reported the key as empty on an
// account whose credentials were working everywhere else.
func TestDarabonbaOssCredentials(t *testing.T) {
	t.Run("an access key pair is passed through", func(t *testing.T) {
		p := &darabonbaOssCredentials{cred: &fakeCredential{
			model: &credential.CredentialModel{
				AccessKeyId:     new("akid"),
				AccessKeySecret: new("aksecret"),
			},
		}}
		creds, err := p.GetCredentials(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "akid", creds.AccessKeyID)
		assert.Equal(t, "aksecret", creds.AccessKeySecret)
		assert.Equal(t, "", creds.SecurityToken)
	})

	t.Run("a session token is carried too", func(t *testing.T) {
		p := &darabonbaOssCredentials{cred: &fakeCredential{
			model: &credential.CredentialModel{
				AccessKeyId:     new("akid"),
				AccessKeySecret: new("aksecret"),
				SecurityToken:   new("token"),
			},
		}}
		creds, err := p.GetCredentials(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "token", creds.SecurityToken)
	})

	t.Run("a resolution error surfaces rather than yielding empty credentials", func(t *testing.T) {
		p := &darabonbaOssCredentials{cred: &fakeCredential{err: errors.New("no credential source")}}
		_, err := p.GetCredentials(context.Background())
		assert.Error(t, err)
	})

	t.Run("a nil model is an error, not a silent empty key", func(t *testing.T) {
		// This is the shape the old code failed on: empty strings reached the
		// OSS SDK and surfaced as "access key id or access key secret is empty",
		// which reads like a configuration mistake rather than a resolution one.
		p := &darabonbaOssCredentials{cred: &fakeCredential{model: nil}}
		_, err := p.GetCredentials(context.Background())
		assert.Error(t, err)
	})

	t.Run("the credential is resolved on every call so a refreshed token is seen", func(t *testing.T) {
		f := &fakeCredential{model: &credential.CredentialModel{
			AccessKeyId:     new("akid"),
			AccessKeySecret: new("aksecret"),
		}}
		p := &darabonbaOssCredentials{cred: f}
		_, err := p.GetCredentials(context.Background())
		require.NoError(t, err)
		_, err = p.GetCredentials(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 2, f.calls, "caching would pin an expired session token")
	})
}
