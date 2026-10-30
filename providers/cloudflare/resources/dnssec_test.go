// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestDNSSEC_active(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/dnssec", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("dnssec_active"))
	})

	ds, err := zone.dnssec()
	require.NoError(t, err)
	require.NotNil(t, ds)

	assert.Equal(t, "active", ds.Status.Data)
	assert.Equal(t, int64(257), ds.Flags.Data)
	assert.Equal(t, "13", ds.Algorithm.Data)
	assert.Equal(t, "ECDSAP256SHA256", ds.KeyType.Data)
	assert.Equal(t, "2", ds.DigestType.Data)
	assert.Equal(t, "SHA256", ds.DigestAlgorithm.Data)
	assert.Contains(t, ds.Digest.Data, "48E939042E82C22542CB377B580DFDC52A361CEFDC72E7F9107E2B6BD9306A45")
	assert.Equal(t, int64(2371), ds.KeyTag.Data)
	assert.NotEmpty(t, ds.PublicKey.Data)
}

func TestDNSSEC_disabled(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/dnssec", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("dnssec_disabled"))
	})

	ds, err := zone.dnssec()
	require.NoError(t, err)
	require.NotNil(t, ds)

	assert.Equal(t, "disabled", ds.Status.Data)
	// When DNSSEC is disabled, the algorithm/key/digest fields should be
	// surfaced as null, not empty strings — so a policy can distinguish
	// "DNSSEC turned off" from "DNSSEC active with empty algorithm".
	nullState := plugin.StateIsSet | plugin.StateIsNull
	assert.Equal(t, nullState, ds.Algorithm.State)
	assert.Equal(t, nullState, ds.KeyType.State)
	assert.Equal(t, nullState, ds.DigestType.State)
	assert.Equal(t, nullState, ds.DigestAlgorithm.State)
	assert.Equal(t, nullState, ds.Digest.State)
	assert.Equal(t, nullState, ds.Ds.State)
	assert.Equal(t, nullState, ds.KeyTag.State)
	assert.Equal(t, nullState, ds.PublicKey.State)
}

func TestDNSSEC_unavailable(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/dnssec", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
	})

	ds, err := zone.dnssec()
	require.NoError(t, err, "Forbidden should surface as nil, not error")
	assert.Nil(t, ds)
}
