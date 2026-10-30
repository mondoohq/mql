// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsmanager "github.com/stackitcloud/stackit-sdk-go/services/secretsmanager/v1api"
)

// ===== ttlSeconds =====
//
// The Secrets Manager API reports a secret ID lifetime as a duration string
// constrained to ^[0-9]+[smh]$. A wrong unit multiplier turns a 15 minute
// lifetime into a 15 second one (or a 15 hour one) with no error anywhere, so
// each documented unit is pinned by value.

func TestTtlSecondsUnits(t *testing.T) {
	for _, tc := range []struct {
		ttl  string
		want int64
	}{
		{"30s", 30},
		{"15m", 900},
		{"1h", 3600},
		{"24h", 86400},
		// zero is a real setting the service accepts: the credential never
		// expires. It must not be confused with an absent lifetime.
		{"0s", 0},
		{"0h", 0},
	} {
		got := ttlSeconds(tc.ttl)
		require.NotNil(t, got, "ttl %q should parse", tc.ttl)
		assert.Equal(t, tc.want, *got, "ttl %q", tc.ttl)
	}
}

// An absent or unparseable lifetime has to read as null. Returning 0 would
// claim the service said "never expires" when it said nothing at all, and a
// policy looking for unbounded credentials would then flag every approle the
// call could not read a lifetime for.
func TestTtlSecondsUnreadableIsNull(t *testing.T) {
	for _, ttl := range []string{
		"",      // the field the service left empty
		"m",     // unit with no count
		"15",    // count with no unit
		"15d",   // a unit outside the documented set
		"15 m",  // the space defeats the digit scan
		"-15m",  // a negative lifetime is not a duration the service emits
		"+15m",  // ParseInt accepts a leading sign; the field never carries one
		"1.5h",  // fractional durations are outside the pattern
		"15m30", // trailing junk
		"s",
	} {
		assert.Nil(t, ttlSeconds(ttl), "ttl %q should read as null", ttl)
	}
}

// ===== nonEmpty =====

func TestNonEmptyKeepsAbsentValueNull(t *testing.T) {
	assert.Nil(t, nonEmpty(""))
	got := nonEmpty("15m")
	require.NotNil(t, got)
	assert.Equal(t, "15m", *got)
}

// ===== usesUnlimited =====
//
// The API models "may authenticate any number of times" as a count of zero.
// Inverting this predicate reports every unbounded credential as bounded,
// which is the direction that makes an audit pass on a finding.

func TestUsesUnlimited(t *testing.T) {
	assert.True(t, usesUnlimited(0))
	assert.False(t, usesUnlimited(1))
	assert.False(t, usesUnlimited(100))
}

// ===== struct-tag decoding =====
//
// Every field below is required by the API and non-pointer in the SDK model,
// so a mistyped json tag yields a zero value rather than an error: write would
// read false on an approle that can delete secrets, and secret_id_num_uses
// would read 0, which is the unlimited sentinel. Each tag is pinned against a
// payload shaped like the documented response.

func TestApproleDecodesDocumentedPayload(t *testing.T) {
	var role secretsmanager.Approle
	require.NoError(t, json.Unmarshal([]byte(`{
		"description": "ci pipeline",
		"role_id": "3f1c0f4e-0d3b-4f0a-9c1e-2a5b6c7d8e9f",
		"secret_id_num_uses": 5,
		"secret_id_ttl": "15m",
		"write": true
	}`), &role))

	assert.Equal(t, "ci pipeline", role.GetDescription())
	assert.Equal(t, "3f1c0f4e-0d3b-4f0a-9c1e-2a5b6c7d8e9f", role.GetRoleId())
	assert.Equal(t, int32(5), role.GetSecretIdNumUses())
	assert.Equal(t, "15m", role.GetSecretIdTtl())
	assert.True(t, role.GetWrite())
}

func TestApproleSecretDecodesDocumentedPayload(t *testing.T) {
	var secret secretsmanager.ApproleSecret
	require.NoError(t, json.Unmarshal([]byte(`{
		"description": "rotated 2026-09",
		"num_uses": 3,
		"ttl": "1h",
		"version": 7
	}`), &secret))

	assert.Equal(t, "rotated 2026-09", secret.GetDescription())
	assert.Equal(t, int32(3), secret.GetNumUses())
	assert.Equal(t, "1h", secret.GetTtl())
	assert.Equal(t, int32(7), secret.GetVersion())
	// the credential is absent on a read, which is why it is not modeled
	assert.Nil(t, secret.SecretId)
}

// ===== field mapping =====

func TestApproleArgsMapEveryField(t *testing.T) {
	role := secretsmanager.Approle{
		Description:     "ci pipeline",
		RoleId:          "role-1",
		SecretIdNumUses: 5,
		SecretIdTtl:     "15m",
		Write:           true,
	}
	args := approleArgs("instance-a", &role)

	assert.Equal(t, "stackit.secretsManager.approle/instance-a/role-1", args["__id"].Value)
	assert.Equal(t, "role-1", args["roleId"].Value)
	assert.Equal(t, "ci pipeline", args["description"].Value)
	assert.Equal(t, true, args["write"].Value)
	assert.Equal(t, "15m", args["secretIdTtl"].Value)
	assert.Equal(t, int64(900), args["secretIdTtlSeconds"].Value)
	assert.Equal(t, int64(5), args["secretIdNumUses"].Value)
	assert.Equal(t, false, args["secretIdUsesUnlimited"].Value)
}

// A lifetime the service did not report has to reach MQL as null. Mapping it
// as an empty string or as 0 seconds would report a bound the instance never
// stated, and 0 seconds specifically reads as "never expires".
func TestApproleArgsAbsentTtlIsNullNotZero(t *testing.T) {
	role := secretsmanager.Approle{RoleId: "role-1", SecretIdTtl: "", SecretIdNumUses: 0}
	args := approleArgs("instance-a", &role)

	assert.Nil(t, args["secretIdTtl"].Value, "absent secretIdTtl must read null")
	assert.Nil(t, args["secretIdTtlSeconds"].Value, "absent secretIdTtlSeconds must read null")
	// an explicit zero-length lifetime is a different statement and stays a value
	withZero := approleArgs("instance-a", &secretsmanager.Approle{RoleId: "role-1", SecretIdTtl: "0s"})
	assert.Equal(t, "0s", withZero["secretIdTtl"].Value)
	assert.Equal(t, int64(0), withZero["secretIdTtlSeconds"].Value)
	// zero uses is a real sentinel, not an absent value, so it stays an int
	assert.Equal(t, int64(0), args["secretIdNumUses"].Value)
	assert.Equal(t, true, args["secretIdUsesUnlimited"].Value)
}

func TestApproleSecretIdArgsMapEveryField(t *testing.T) {
	secret := secretsmanager.ApproleSecret{
		Description: "rotated 2026-09",
		NumUses:     3,
		Ttl:         "1h",
		Version:     7,
	}
	args := approleSecretIdArgs("instance-a", "role-1", &secret)

	assert.Equal(t, "stackit.secretsManager.approle.secretId/instance-a/role-1/7", args["__id"].Value)
	assert.Equal(t, int64(7), args["version"].Value)
	assert.Equal(t, "rotated 2026-09", args["description"].Value)
	assert.Equal(t, "1h", args["ttl"].Value)
	assert.Equal(t, int64(3600), args["ttlSeconds"].Value)
	assert.Equal(t, int64(3), args["numUses"].Value)
	assert.Equal(t, false, args["usesUnlimited"].Value)
}

func TestApproleSecretIdArgsAbsentTtlIsNullNotZero(t *testing.T) {
	args := approleSecretIdArgs("instance-a", "role-1", &secretsmanager.ApproleSecret{Version: 1})
	assert.Nil(t, args["ttl"].Value, "absent ttl must read null")
	assert.Nil(t, args["ttlSeconds"].Value, "absent ttlSeconds must read null")
	assert.Equal(t, true, args["usesUnlimited"].Value)
}

// The secret ID value is the credential. The API returns it only at creation,
// so on a read it is empty anyway, but modeling it would reproduce a machine
// credential in every scan result the moment the API changed its mind. This
// fails the instant any mapped field carries the value.
func TestApproleSecretIdArgsNeverCarryCredential(t *testing.T) {
	credential := "s.SECRET-ID-VALUE-MUST-NOT-LEAK"
	secret := secretsmanager.ApproleSecret{
		Description: "rotated 2026-09",
		NumUses:     3,
		SecretId:    &credential,
		Ttl:         "1h",
		Version:     7,
	}
	args := approleSecretIdArgs("instance-a", "role-1", &secret)

	for key, raw := range args {
		if raw == nil {
			continue
		}
		s, ok := raw.Value.(string)
		if !ok {
			continue
		}
		assert.NotContains(t, s, credential, "field %q carries the approle secret id", key)
	}
	_, mapped := args["secretId"]
	assert.False(t, mapped, "the approle secret id value must not be a schema field")
}

// The same version number under two approles, and the same approle under two
// instances, must not collide in the resource cache: CreateResource returns
// the first instance cached under a key, so a collision reports one record's
// values under another record's identity.
func TestApproleIdsAreDistinctPerParent(t *testing.T) {
	role := secretsmanager.Approle{RoleId: "role-1"}
	a := approleArgs("instance-a", &role)["__id"].Value
	b := approleArgs("instance-b", &role)["__id"].Value
	assert.NotEqual(t, a, b)

	secret := secretsmanager.ApproleSecret{Version: 1}
	x := approleSecretIdArgs("instance-a", "role-1", &secret)["__id"].Value
	y := approleSecretIdArgs("instance-a", "role-2", &secret)["__id"].Value
	z := approleSecretIdArgs("instance-b", "role-1", &secret)["__id"].Value
	assert.NotEqual(t, x, y)
	assert.NotEqual(t, x, z)
}
