// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestValidUntilTime(t *testing.T) {
	finite := time.Date(2031, 5, 6, 7, 8, 9, 0, time.UTC)

	got := validUntilTime(pgtype.Timestamptz{Time: finite, Valid: true})
	require.NotNil(t, got)
	assert.True(t, got.Equal(finite))

	// NULL: no expiry
	assert.Nil(t, validUntilTime(pgtype.Timestamptz{}))
	// VALID UNTIL 'infinity' also means no expiry
	assert.Nil(t, validUntilTime(pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}))
	// VALID UNTIL '-infinity' is always expired: it must compare before any real time
	neg := validUntilTime(pgtype.Timestamptz{InfinityModifier: pgtype.NegativeInfinity, Valid: true})
	require.NotNil(t, neg)
	assert.True(t, neg.Equal(llx.NeverPastTime))
	assert.True(t, neg.Before(time.Unix(0, 0)))
}

func TestPasswordTypeField(t *testing.T) {
	denied := &pgconn.PgError{Code: "42501", Message: "permission denied for table pg_authid"}
	types := map[int64]string{10: "scram-sha-256", 20: "md5"}

	t.Run("readable", func(t *testing.T) {
		got := passwordTypeField(types, nil, 20)
		require.NoError(t, got.Error)
		assert.Equal(t, "md5", got.Value)
	})

	t.Run("refused, structured errors on", func(t *testing.T) {
		withStructuredErrors(t, true)
		got := passwordTypeField(nil, denied, 20)
		require.Error(t, got.Error)
		assert.True(t, errors.Is(got.Error, llx.ErrForbidden), "want Forbidden, got %v", got.Error)
		assert.Nil(t, got.Value)
	})

	t.Run("refused, structured errors off keeps the v13 null", func(t *testing.T) {
		withStructuredErrors(t, false)
		got := passwordTypeField(nil, denied, 20)
		assert.NoError(t, got.Error)
		assert.Nil(t, got.Value)
	})

	t.Run("other failure is returned unclassified", func(t *testing.T) {
		withStructuredErrors(t, false)
		boom := errors.New("connection reset")
		got := passwordTypeField(nil, boom, 20)
		require.ErrorIs(t, got.Error, boom)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(got.Error))
	})
}

func TestSettingsRefusal(t *testing.T) {
	withStructuredErrors(t, true)
	assert.NoError(t, settingsRefusal(true))
	err := settingsRefusal(false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden), "want Forbidden, got %v", err)

	withStructuredErrors(t, false)
	assert.NoError(t, settingsRefusal(false), "v13 behavior: the visible subset is returned")
}

func TestMembershipQueriesFoldGrantors(t *testing.T) {
	// PostgreSQL 16+ stores one pg_auth_members row per grantor
	for _, q := range []string{memberOfQuery, membersQuery} {
		assert.Contains(t, q, "SELECT DISTINCT")
	}
}

func TestRoleColumnsSelectBypassRLS(t *testing.T) {
	// roleColumnsFor swaps exactly this column; keep the two in step
	assert.Contains(t, roleColumns, "r.rolbypassrls,")
	assert.Equal(t, "false AS rolbypassrls", columnForVersion(90224, pgVersion95, "r.rolbypassrls", "false"))
}
