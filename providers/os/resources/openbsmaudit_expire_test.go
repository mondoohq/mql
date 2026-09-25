// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func bsmI64(v int64) *int64 { return &v }

const (
	bsmDay = int64(86400)
	bsmKiB = int64(1024)
	bsmMiB = 1024 * bsmKiB
	bsmGiB = 1024 * bsmMiB
)

func TestParseAuditExpireAfter(t *testing.T) {
	tests := []struct {
		value    string
		age      *int64
		bytes    *int64
		operator string
	}{
		// one term, every unit
		{value: "60d", age: bsmI64(60 * bsmDay)},
		{value: "59d", age: bsmI64(59 * bsmDay)},
		{value: "30s", age: bsmI64(30)},
		{value: "1440h", age: bsmI64(60 * bsmDay)},
		// a year is 364 days plus a bsmDay for every fourth year
		{value: "1y", age: bsmI64(364 * bsmDay)},
		{value: "4y", age: bsmI64((4*364 + 1) * bsmDay)},
		{value: "5G", bytes: bsmI64(5 * bsmGiB)},
		{value: "1G", bytes: bsmI64(bsmGiB)},
		{value: "1023M", bytes: bsmI64(1023 * bsmMiB)},
		{value: "1024M", bytes: bsmI64(bsmGiB)},
		{value: "10M", bytes: bsmI64(10 * bsmMiB)},
		{value: "512K", bytes: bsmI64(512 * bsmKiB)},
		{value: "100B", bytes: bsmI64(100)},
		// a number alone is bytes
		{value: "4096", bytes: bsmI64(4096)},
		// the character after the number is the unit, so a space means bytes
		{value: "60 ", bytes: bsmI64(60)},
		{value: "60 x", bytes: bsmI64(60)},
		{value: "0d", age: bsmI64(0)},
		// leading whitespace is skipped, and trailing text that cannot start
		// a joiner is ignored
		{value: "  \t60d", age: bsmI64(60 * bsmDay)},
		{value: "60d,", age: bsmI64(60 * bsmDay)},
		{value: "60d5G", age: bsmI64(60 * bsmDay)},
		{value: "+60d", age: bsmI64(60 * bsmDay)},

		// two terms, the joiner is case-insensitive and may use tabs
		{value: "60d OR 5G", age: bsmI64(60 * bsmDay), bytes: bsmI64(5 * bsmGiB), operator: "OR"},
		{value: "60d AND 10M", age: bsmI64(60 * bsmDay), bytes: bsmI64(10 * bsmMiB), operator: "AND"},
		{value: "10M and 60d", age: bsmI64(60 * bsmDay), bytes: bsmI64(10 * bsmMiB), operator: "AND"},
		{value: "60d or 10M", age: bsmI64(60 * bsmDay), bytes: bsmI64(10 * bsmMiB), operator: "OR"},
		{value: "60d Or 1G", age: bsmI64(60 * bsmDay), bytes: bsmI64(bsmGiB), operator: "OR"},
		{value: "60d\tOR\t5G", age: bsmI64(60 * bsmDay), bytes: bsmI64(5 * bsmGiB), operator: "OR"},
		{value: "60dAND5G", age: bsmI64(60 * bsmDay), bytes: bsmI64(5 * bsmGiB), operator: "AND"},
		{value: "60d   AND   5G", age: bsmI64(60 * bsmDay), bytes: bsmI64(5 * bsmGiB), operator: "AND"},
		// AND wins when the joiner holds both words
		{value: "60d OR AND 5G", age: bsmI64(60 * bsmDay), bytes: bsmI64(5 * bsmGiB), operator: "AND"},
		// a space as the first unit makes it a size
		{value: "60 AND 5G", bytes: bsmI64(5 * bsmGiB), operator: "AND"},
		// a later term of the same kind overwrites the earlier one
		{value: "10d OR 60d", age: bsmI64(60 * bsmDay), operator: "OR"},
		{value: "5G AND 10M", bytes: bsmI64(10 * bsmMiB), operator: "AND"},
		// only two terms are read
		{value: "60d AND 5G OR 1s", age: bsmI64(60 * bsmDay), bytes: bsmI64(5 * bsmGiB), operator: "AND"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := parseAuditExpireAfter(tt.value)
			require.NotNil(t, got)
			assert.Equal(t, tt.age, got.ageSeconds, "age")
			assert.Equal(t, tt.bytes, got.bytes, "bytes")
			assert.Equal(t, tt.operator, got.operator, "operator")
		})
	}
}

func TestParseAuditExpireAfterInvalid(t *testing.T) {
	for _, value := range []string{
		"",
		"   ",
		"garbage",
		"sixty days",
		// units are case-sensitive: an upper-case letter is a size unit and a
		// lower-case one an age unit
		"60D",
		"5g",
		"10m",
		"60x",
		// a tab right after the number is taken as the unit
		"60\tAND 5G",
		// a space after the number is the bytes unit, which leaves "d" as a
		// joiner with no second term
		"60 d",
		// a joiner with no second term, or a second number with no unit
		"60d AND",
		"60d ",
		"60d AND 5",
		"60d AND x",
		// a joiner with neither word
		"60d 5G",
		"60d NAD 5G",
		"60d AND 5x",
		"-60d",
		"99999999999999999999d",
		"999999999999999y",
	} {
		t.Run(value, func(t *testing.T) {
			assert.Nil(t, parseAuditExpireAfter(value))
		})
	}
}

func TestAuditExpireAfterRetention(t *testing.T) {
	tests := []struct {
		value string
		age   *int64
		bytes *int64
	}{
		{value: "60d", age: bsmI64(60 * bsmDay)},
		{value: "5G", bytes: bsmI64(5 * bsmGiB)},
		// with AND a file goes only once both are exceeded, so each is a floor
		{value: "60d AND 10M", age: bsmI64(60 * bsmDay), bytes: bsmI64(10 * bsmMiB)},
		{value: "10M and 60d", age: bsmI64(60 * bsmDay), bytes: bsmI64(10 * bsmMiB)},
		// with OR either threshold removes a file, so neither is a floor
		{value: "60d OR 5G"},
		{value: "60d OR 10M"},
		// auditd skips a zero threshold, leaving the other one on its own
		{value: "60d OR 0G", age: bsmI64(60 * bsmDay)},
		{value: "0d OR 5G", bytes: bsmI64(5 * bsmGiB)},
		{value: "10d AND 0G", age: bsmI64(10 * bsmDay)},
		// a threshold overwritten by a later one of the same kind leaves a
		// single dimension
		{value: "10d OR 60d", age: bsmI64(60 * bsmDay)},
		// no nonzero threshold: auditd expires nothing, and no floor is claimed
		{value: "0d"},
		{value: "0d AND 0G"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			e := parseAuditExpireAfter(tt.value)
			require.NotNil(t, e)
			age, size := e.retention()
			assert.Equal(t, tt.age, age, "age")
			assert.Equal(t, tt.bytes, size, "bytes")
		})
	}
}

func TestAuditControlValue(t *testing.T) {
	content := "#expire-after:1d\n" +
		"  expire-after:2d\n" +
		"expire-after:10M\n" +
		"expire-after:60d\n"

	// the first matching line wins, a commented line and a key with leading
	// whitespace do not match
	for _, apple := range []bool{false, true} {
		v, ok := auditControlValue(content, "expire-after", apple)
		require.True(t, ok)
		assert.Equal(t, "10M", v)
	}

	_, ok := auditControlValue("dir:/var/audit\n", "expire-after", false)
	assert.False(t, ok)

	// upstream strips trailing whitespace and keeps text after a second colon,
	// Apple does neither
	v, ok := auditControlValue("expire-after:60d \t\n", "expire-after", false)
	require.True(t, ok)
	assert.Equal(t, "60d", v)
	v, ok = auditControlValue("expire-after:60d \t\n", "expire-after", true)
	require.True(t, ok)
	assert.Equal(t, "60d \t", v)
	v, ok = auditControlValue("expire-after:60d:5G\n", "expire-after", false)
	require.True(t, ok)
	assert.Equal(t, "60d:5G", v)
	v, ok = auditControlValue("expire-after:60d:5G\n", "expire-after", true)
	require.True(t, ok)
	assert.Equal(t, "60d", v)

	// an empty value is an empty string upstream and a lookup error on Apple
	v, ok = auditControlValue("expire-after:\n", "expire-after", false)
	require.True(t, ok)
	assert.Equal(t, "", v)
	_, ok = auditControlValue("expire-after:\n", "expire-after", true)
	assert.False(t, ok)
}

func newOpenBSMAuditForPlatform(t *testing.T, family string) *mqlOpenBSMAudit {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: family, Family: []string{family}},
	})
	require.NoError(t, err)
	return &mqlOpenBSMAudit{MqlRuntime: &plugin.Runtime{Connection: conn}}
}

func TestOpenBSMAuditExpireAfterFields(t *testing.T) {
	x := newOpenBSMAuditForPlatform(t, "freebsd")
	content := "dir:/var/audit\nexpire-after:60d AND 1G\n"

	age, err := x.expireAfterAge(content)
	require.NoError(t, err)
	require.NotNil(t, age)
	assert.Equal(t, 60*bsmDay, llx.TimeToDuration(age))

	size, err := x.expireAfterBytes(content)
	require.NoError(t, err)
	assert.Equal(t, bsmGiB, size)

	op, err := x.expireAfterOperator(content)
	require.NoError(t, err)
	assert.Equal(t, "AND", op)

	minAge, err := x.minRetentionAge(content)
	require.NoError(t, err)
	require.NotNil(t, minAge)
	assert.Equal(t, 60*bsmDay, llx.TimeToDuration(minAge))

	minSize, err := x.minRetentionBytes(content)
	require.NoError(t, err)
	assert.Equal(t, bsmGiB, minSize)

	for _, s := range []plugin.State{x.ExpireAfterAge.State, x.ExpireAfterBytes.State, x.ExpireAfterOperator.State, x.MinRetentionAge.State, x.MinRetentionBytes.State} {
		assert.Zero(t, s&plugin.StateIsNull)
	}
}

func TestOpenBSMAuditExpireAfterFieldsNull(t *testing.T) {
	for name, content := range map[string]string{
		"absent":   "dir:/var/audit\n",
		"empty":    "expire-after:\n",
		"invalid":  "expire-after:garbage\n",
		"or":       "expire-after:60d OR 5G\n",
		"size":     "expire-after:5G\n",
		"age only": "expire-after:60d\n",
	} {
		t.Run(name, func(t *testing.T) {
			x := newOpenBSMAuditForPlatform(t, "darwin")
			_, err := x.expireAfterAge(content)
			require.NoError(t, err)
			_, err = x.expireAfterBytes(content)
			require.NoError(t, err)
			_, err = x.expireAfterOperator(content)
			require.NoError(t, err)
			_, err = x.minRetentionAge(content)
			require.NoError(t, err)
			_, err = x.minRetentionBytes(content)
			require.NoError(t, err)

			isNull := func(s plugin.State) bool { return s&plugin.StateIsNull != 0 }
			switch name {
			case "absent", "empty", "invalid":
				assert.True(t, isNull(x.ExpireAfterAge.State))
				assert.True(t, isNull(x.ExpireAfterBytes.State))
				assert.True(t, isNull(x.ExpireAfterOperator.State))
				assert.True(t, isNull(x.MinRetentionAge.State))
				assert.True(t, isNull(x.MinRetentionBytes.State))
			case "or":
				assert.False(t, isNull(x.ExpireAfterAge.State))
				assert.False(t, isNull(x.ExpireAfterBytes.State))
				assert.False(t, isNull(x.ExpireAfterOperator.State))
				assert.True(t, isNull(x.MinRetentionAge.State))
				assert.True(t, isNull(x.MinRetentionBytes.State))
			case "size":
				assert.True(t, isNull(x.ExpireAfterAge.State))
				assert.False(t, isNull(x.ExpireAfterBytes.State))
				assert.True(t, isNull(x.ExpireAfterOperator.State))
				assert.True(t, isNull(x.MinRetentionAge.State))
				assert.False(t, isNull(x.MinRetentionBytes.State))
			case "age only":
				assert.False(t, isNull(x.ExpireAfterAge.State))
				assert.True(t, isNull(x.ExpireAfterBytes.State))
				assert.True(t, isNull(x.ExpireAfterOperator.State))
				assert.False(t, isNull(x.MinRetentionAge.State))
				assert.True(t, isNull(x.MinRetentionBytes.State))
			}
		})
	}
}

func TestOpenBSMAuditExpireAfterPlatformLookup(t *testing.T) {
	// Apple's auditd keeps the trailing space, which leaves a joiner with no
	// second term; upstream strips it
	content := "expire-after:60d \n"

	bsd := newOpenBSMAuditForPlatform(t, "freebsd")
	age, err := bsd.expireAfterAge(content)
	require.NoError(t, err)
	require.NotNil(t, age)
	assert.Equal(t, 60*bsmDay, llx.TimeToDuration(age))

	mac := newOpenBSMAuditForPlatform(t, "darwin")
	_, err = mac.expireAfterAge(content)
	require.NoError(t, err)
	assert.NotZero(t, mac.ExpireAfterAge.State&plugin.StateIsNull)
}

func TestOpenBSMAuditExpireAfterFirstLineWins(t *testing.T) {
	// the shipped params map keeps the last line; auditd and the typed fields
	// use the first
	content := "expire-after:10M\nexpire-after:60d\n"
	x := newOpenBSMAuditForPlatform(t, "darwin")

	size, err := x.expireAfterBytes(content)
	require.NoError(t, err)
	assert.Equal(t, 10*bsmMiB, size)

	_, err = x.expireAfterAge(content)
	require.NoError(t, err)
	assert.NotZero(t, x.ExpireAfterAge.State&plugin.StateIsNull)
}
