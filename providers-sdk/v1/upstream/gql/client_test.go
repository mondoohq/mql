// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gql

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
)

func TestNewClientSendsUserAgent(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Get("User-Agent"):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	// the same client mql passes in production
	hc := upstream.DefaultHttpClient()
	cfg := &upstream.UpstreamConfig{
		ApiEndpoint: srv.URL,
		Creds: &upstream.ServiceAccountCredentials{
			Mrn: "//agents.api.mondoo.app/spaces/x/serviceaccounts/y", PrivateKey: pemKey,
		},
	}
	c, err := NewClient(cfg, hc, WithProvider("os"))
	require.NoError(t, err)

	var q struct {
		Foo string
	}
	qErr := c.Query(context.Background(), &q, nil)
	select {
	case ua := <-got:
		assert.Equal(t, upstream.UserAgent("os"), ua)
	default:
		t.Fatalf("request never reached the server: %v", qErr)
	}
}
