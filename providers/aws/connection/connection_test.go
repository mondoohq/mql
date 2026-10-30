// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestNewAwsConnection(t *testing.T) {
	conn, err := NewAwsConnection(123, &inventory.Asset{}, &inventory.Config{})
	require.Nil(t, err)
	require.NotNil(t, conn)
}

// TestConnectionHashDistinguishesConnections guards the account-id memoization
// in provider.connect, which is keyed on Hash(). hashstructure ignores
// unexported struct fields, so if awsConnectionOptions ever loses its exported
// fields every connection in a process hashes identically and account #2
// silently inherits account #1's account id.
func TestConnectionHashDistinguishesConnections(t *testing.T) {
	base := func() *AwsConnection {
		return &AwsConnection{opts: awsConnectionOptions{
			Scope:   "s1",
			Profile: "p1",
			Options: map[string]string{"role": "arn:aws:iam::111111111111:role/Scan"},
		}}
	}

	tests := []struct {
		name   string
		mutate func(*AwsConnection)
	}{
		{"profile differs", func(c *AwsConnection) { c.opts.Profile = "p2" }},
		{"scope differs", func(c *AwsConnection) { c.opts.Scope = "s2" }},
		{"assumed role differs", func(c *AwsConnection) {
			c.opts.Options = map[string]string{"role": "arn:aws:iam::222222222222:role/Scan"}
		}},
		{"credentials differ", func(c *AwsConnection) { c.opts.CredentialFingerprint = "deadbeef" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := base()
			b := base()
			tt.mutate(b)
			require.NotEqual(t, a.Hash(), b.Hash(),
				"connections differing by %s must not share a Hash()", tt.name)
		})
	}

	// A zero connection must not collide with a configured one either.
	require.NotEqual(t, (&AwsConnection{}).Hash(), base().Hash())
}

func TestCredentialFingerprint(t *testing.T) {
	require.Empty(t, credentialFingerprint(nil), "no credentials should yield no fingerprint")
	require.Empty(t, credentialFingerprint([]*vault.Credential{}))

	// a nil element must not panic
	require.NotPanics(t, func() { credentialFingerprint([]*vault.Credential{nil}) })

	acct1 := []*vault.Credential{{User: "AKIAONE", Secret: []byte("secret-one")}}
	acct2 := []*vault.Credential{{User: "AKIATWO", Secret: []byte("secret-two")}}
	require.NotEqual(t, credentialFingerprint(acct1), credentialFingerprint(acct2))

	// same input is stable across calls
	require.Equal(t, credentialFingerprint(acct1), credentialFingerprint(acct1))

	// the secret must not be recoverable from the fingerprint
	require.NotContains(t, credentialFingerprint(acct1), "secret-one")
}

func TestGetRegionsFromRegionalTable(t *testing.T) {
	t.Run("Successful region extraction and deduplication", func(t *testing.T) {
		regions, err := getRegionsFromRegionalTable()
		require.NoError(t, err)
		fewExpectedRegions := []string{
			"ap-east-1",
			"ap-northeast-1",
			"ap-south-1",
			"ap-southeast-1",
			"ca-central-1",
			"ca-west-1",
			"eu-central-1",
			"eu-central-2",
			"eu-north-1",
			"eu-south-1",
			"eu-south-2",
			"eu-west-1",
			"eu-west-2",
			"eu-west-3",
			"il-central-1",
			"me-central-1",
			"me-south-1",
			"mx-central-1",
			"sa-east-1",
			"us-east-1",
			"us-east-2",
			"us-gov-east-1",
			"us-gov-west-1",
			"us-west-1",
			"us-west-2",
		}
		for _, expectedRegion := range fewExpectedRegions {
			require.Contains(t, regions, expectedRegion)
		}
	})
}

func TestFetchRegionsFromRegionalTable(t *testing.T) {
	require.Greater(t, regionalTableHTTPClient.Timeout, time.Duration(0))
	for _, tc := range []struct {
		name, body string
		status     int
		want       []string
		fail       bool
	}{
		{"complete", `{"prices":[{"attributes":{"aws:region":"eu-west-1"}},{"attributes":{"aws:region":"us-east-1"}},{"attributes":{"aws:region":"eu-west-1"}}]}`, 200, []string{"eu-west-1", "us-east-1"}, false},
		{"invalid", `{`, 200, nil, true}, {"refusal", `{}`, 503, nil, true}, {"oversize", strings.Repeat(" ", (16<<20)+1), 200, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			got, err := fetchRegionsFromRegionalTable(t.Context(), srv.Client(), srv.URL)
			if tc.fail {
				require.Error(t, err)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
}
func TestFetchRegionsFromRegionalTableCancellation(t *testing.T) {
	for _, phase := range []string{"headers", "body"} {
		t.Run(phase, func(t *testing.T) {
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "body" {
					w.Header().Set("Content-Length", "20")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			defer srv.Close()
			defer close(release)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := fetchRegionsFromRegionalTable(ctx, srv.Client(), srv.URL); done <- err }()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case <-time.After(time.Second):
				t.Fatal("regional table ignored cancellation")
			}
		})
	}
}
