// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestHash(t *testing.T) {
	claim1 := &Claims{
		Subject:  "foo",
		Resource: "bar",
		Exp:      "baz",
		Iat:      "quux",
	}

	h1a, err := HashClaimsSha256(claim1)
	require.NoError(t, err)
	h1b, err := HashClaimsSha256(claim1)
	require.NoError(t, err)
	require.Equal(t, h1a, h1b)

	claim2 := &Claims{
		Subject:  "f",
		Resource: "oobar",
		Exp:      "b",
		Iat:      "azquux",
	}

	h2, err := HashClaimsSha256(claim2)
	require.NoError(t, err)
	require.NotEqual(t, h1a, h2)
}

// exchangeServer answers ExchangeExternalToken with the given credential and
// records the request it received, as raw bytes.
func exchangeServer(t *testing.T, credential string) (*httptest.Server, *[]byte) {
	t.Helper()
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/SecureTokenService/ExchangeExternalToken" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = body

		resp := &ExchangeExternalTokenResponse{
			Base64Credential: base64.StdEncoding.EncodeToString([]byte(credential)),
		}
		out, err := resp.MarshalVT()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/protobuf")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// wireField returns the wire type and varint value of a field in an encoded
// message, read without the generated code. found is false when the field is
// not on the wire.
func wireField(t *testing.T, msg []byte, want protowire.Number) (typ protowire.Type, value uint64, found bool) {
	t.Helper()
	for len(msg) > 0 {
		num, wtyp, n := protowire.ConsumeTag(msg)
		require.GreaterOrEqual(t, n, 0, "invalid tag")
		msg = msg[n:]
		if num == want {
			found, typ = true, wtyp
			if wtyp == protowire.VarintType {
				value, _ = protowire.ConsumeVarint(msg)
			}
		}
		n = protowire.ConsumeFieldValue(num, wtyp, msg)
		require.GreaterOrEqual(t, n, 0, "invalid field value")
		msg = msg[n:]
	}
	return typ, value, found
}

func TestExchangeExternalToken_ResponseFormatOnTheWire(t *testing.T) {
	// Measured: the platform's SecureTokenService request schema, 2026-11-24.
	// It declares field 4 as an enum with TOKEN = 1. A request that carried the
	// string "TOKEN" in field 4 decoded there with the format left at
	// CREDENTIAL, so the server answered with a private key.
	const responseFormatField = 4
	const formatToken = 1

	// Synthetic: the credential values; no server issued them. The keys are
	// the ones the platform writes.
	const tokenCredential = `{"mrn":"service-account-mrn","space_mrn":"space-mrn","api_endpoint":"https://api.example.com","token":"signed.jwt.value"}`

	t.Run("a token response is requested as the TOKEN enum value", func(t *testing.T) {
		srv, got := exchangeServer(t, tokenCredential)

		creds, err := ExchangeExternalToken(srv.URL, "space-mrn", "https://issuer.example.com", "external.jwt", true)
		require.NoError(t, err)

		typ, value, found := wireField(t, *got, responseFormatField)
		require.True(t, found, "response format is not on the wire")
		require.Equal(t, protowire.VarintType, typ)
		require.Equal(t, uint64(formatToken), value)

		require.Equal(t, "signed.jwt.value", creds.Token)
		require.Empty(t, creds.PrivateKey)
		require.Equal(t, "space-mrn", creds.ScopeMrn)
	})

	t.Run("a credential response leaves the format unset", func(t *testing.T) {
		srv, got := exchangeServer(t, `{"mrn":"service-account-mrn","space_mrn":"space-mrn","private_key":"key","certificate":"cert","api_endpoint":"https://api.example.com"}`)

		creds, err := ExchangeExternalToken(srv.URL, "space-mrn", "https://issuer.example.com", "external.jwt", false)
		require.NoError(t, err)

		_, _, found := wireField(t, *got, responseFormatField)
		require.False(t, found)
		require.Equal(t, "key", creds.PrivateKey)
		require.Empty(t, creds.Token)
	})
}

func TestDecodeExchangedCredentials(t *testing.T) {
	// Synthetic: a server that does not know the TOKEN format answers a token
	// request with a private key.
	t.Run("a private key is kept when a token was asked for", func(t *testing.T) {
		srv, _ := exchangeServer(t, `{"mrn":"m","space_mrn":"space-mrn","private_key":"key","certificate":"cert","api_endpoint":"https://api.example.com"}`)

		creds, err := ExchangeExternalToken(srv.URL, "space-mrn", "https://issuer.example.com", "external.jwt", true)
		require.NoError(t, err)
		require.Equal(t, "key", creds.PrivateKey)
		require.Equal(t, "cert", creds.Certificate)
		require.Empty(t, creds.Token)
	})

	// Synthetic: a credential nothing can authenticate with.
	t.Run("a credential with neither a token nor a private key is refused", func(t *testing.T) {
		_, err := decodeExchangedCredentials([]byte(`{"mrn":"m","space_mrn":"s","api_endpoint":"https://api.example.com"}`))
		require.Error(t, err)
	})

	// Synthetic: malformed input.
	t.Run("a credential that is not JSON is refused", func(t *testing.T) {
		_, err := decodeExchangedCredentials([]byte(`not json`))
		require.Error(t, err)
	})
}
