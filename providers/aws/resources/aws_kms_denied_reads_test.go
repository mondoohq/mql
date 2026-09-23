// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// kmsDeniedErr is the shape KMS answers with when a key policy withholds an
// operation from the caller. Every test below routes through the production
// classifier via this error rather than building a classified error by hand,
// so a change to the classifier moves the tests with it.
func kmsDeniedErr(operation string) error {
	return awsAPIError(400, "AccessDeniedException", "User is not authorized to perform "+
		operation+" on this resource because the resource-based policy does not allow it")
}

// kmsThrottleErr is a failure that is not a denial: it must never be reported
// as one, because nothing about the key's permissions was established.
func kmsThrottleErr() error {
	return awsAPIError(400, "ThrottlingException", "Rate exceeded")
}

// requireKmsForbidden asserts err is a denial that names the grant it needed.
func requireKmsForbidden(t *testing.T, err error, permission string) {
	t.Helper()
	require.ErrorIs(t, err, llx.ErrForbidden)
	assert.Equal(t, []string{permission}, llx.ErrorDetailOf(err).GetPermissions())
}

func TestKmsDeniedErrIsClassifiedAsADenial(t *testing.T) {
	assert.True(t, Is400AccessDeniedError(kmsDeniedErr("kms:GetKeyRotationStatus")),
		"the fixture must be the shape the production classifier recognizes, or every test below proves nothing")
	assert.False(t, Is400AccessDeniedError(kmsThrottleErr()),
		"a throttle is not a denial")
}

func TestKmsRotationReadingFrom(t *testing.T) {
	t.Run("a refused GetKeyRotationStatus is an error, not rotation-off", func(t *testing.T) {
		// alias/aws/acm answers this way to an account administrator, and it
		// rotates. Reporting keyRotationEnabled:false here states the opposite
		// of the truth about that key.
		got, err := kmsRotationReadingFrom(nil, kmsDeniedErr("kms:GetKeyRotationStatus"))
		requireKmsForbidden(t, err, "kms:GetKeyRotationStatus")
		assert.False(t, got.known)
	})

	t.Run("rotation on reports the period and the dates AWS gave", func(t *testing.T) {
		next := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
		started := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
		period := int32(180)
		got, err := kmsRotationReadingFrom(&kms.GetKeyRotationStatusOutput{
			KeyRotationEnabled:        true,
			RotationPeriodInDays:      &period,
			NextRotationDate:          &next,
			OnDemandRotationStartDate: &started,
		}, nil)
		require.NoError(t, err)
		assert.True(t, got.known)
		assert.True(t, got.enabled)
		require.NotNil(t, got.periodDays)
		assert.Equal(t, int64(180), *got.periodDays)
		assert.Equal(t, &next, got.nextRotationAt)
		assert.Equal(t, &started, got.onDemandRotationStartedAt)
	})

	t.Run("rotation off is a real false with no invented period", func(t *testing.T) {
		// AWS omits RotationPeriodInDays whenever rotation is off. The reading
		// must stay known so keyRotationEnabled publishes a measured false,
		// while the period stays absent: 0 is not a rotation period.
		got, err := kmsRotationReadingFrom(&kms.GetKeyRotationStatusOutput{
			KeyRotationEnabled: false,
		}, nil)
		require.NoError(t, err)
		assert.True(t, got.known)
		assert.False(t, got.enabled)
		assert.Nil(t, got.periodDays)
		assert.Nil(t, got.nextRotationAt)
	})

	t.Run("a throttle is an error, not an answer", func(t *testing.T) {
		_, err := kmsRotationReadingFrom(nil, kmsThrottleErr())
		require.Error(t, err)
		assert.NotErrorIs(t, err, llx.ErrForbidden)
	})
}

func TestKmsRotationFieldsReturnTheDenial(t *testing.T) {
	denied, deniedErr := kmsRotationReadingFrom(nil, kmsDeniedErr("kms:GetKeyRotationStatus"))
	require.Error(t, deniedErr)

	key := &mqlAwsKmsKey{}
	key.cachedRotationStatus = denied
	key.cachedRotationStatusErr = deniedErr
	key.rotationStatusFetched = true

	_, err := key.keyRotationEnabled()
	requireKmsForbidden(t, err, "kms:GetKeyRotationStatus")
	assert.False(t, key.KeyRotationEnabled.IsSet(),
		"a denied rotation read must surface the denial, never a null or a measured false")

	_, err = key.rotationPeriodInDays()
	requireKmsForbidden(t, err, "kms:GetKeyRotationStatus")
	assert.False(t, key.RotationPeriodInDays.IsSet())

	_, err = key.nextRotationAt()
	requireKmsForbidden(t, err, "kms:GetKeyRotationStatus")
	assert.False(t, key.NextRotationAt.IsSet())

	_, err = key.onDemandRotationStartedAt()
	requireKmsForbidden(t, err, "kms:GetKeyRotationStatus")
	assert.False(t, key.OnDemandRotationStartedAt.IsSet())
}

func TestKmsRotationDisabledPublishesRealFalse(t *testing.T) {
	// The counterpart of the test above: the two situations must stay
	// distinguishable, so a key that genuinely does not rotate keeps reporting
	// a measured false rather than being swept into null.
	off, err := kmsRotationReadingFrom(&kms.GetKeyRotationStatusOutput{KeyRotationEnabled: false}, nil)
	require.NoError(t, err)

	key := &mqlAwsKmsKey{}
	key.cachedRotationStatus = off
	key.rotationStatusFetched = true

	enabled, err := key.keyRotationEnabled()
	require.NoError(t, err)
	assert.False(t, enabled)
	assert.False(t, key.KeyRotationEnabled.IsNull(),
		"rotation that is genuinely off is a measured false, not an unknown")

	// AWS reports no period for a key with rotation off, and 0 is not a
	// rotation period.
	period, err := key.rotationPeriodInDays()
	require.NoError(t, err)
	assert.Equal(t, int64(0), period)
	assert.True(t, key.RotationPeriodInDays.IsNull(),
		"an absent RotationPeriodInDays must be null, not a hard 0")
}

func TestKmsRotationEnabledPublishesTheReportedPeriod(t *testing.T) {
	period := int32(180)
	next := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	on, err := kmsRotationReadingFrom(&kms.GetKeyRotationStatusOutput{
		KeyRotationEnabled:   true,
		RotationPeriodInDays: &period,
		NextRotationDate:     &next,
	}, nil)
	require.NoError(t, err)

	key := &mqlAwsKmsKey{}
	key.cachedRotationStatus = on
	key.rotationStatusFetched = true

	enabled, err := key.keyRotationEnabled()
	require.NoError(t, err)
	assert.True(t, enabled)
	assert.False(t, key.KeyRotationEnabled.IsNull())

	got, err := key.rotationPeriodInDays()
	require.NoError(t, err)
	assert.Equal(t, int64(180), got)
	assert.False(t, key.RotationPeriodInDays.IsNull())

	at, err := key.nextRotationAt()
	require.NoError(t, err)
	assert.Equal(t, &next, at)
	assert.False(t, key.NextRotationAt.IsNull())
}

func TestKmsLastUsageReadingFrom(t *testing.T) {
	t.Run("a refused GetKeyLastUsage is an error", func(t *testing.T) {
		got, err := kmsLastUsageReadingFrom(nil, kmsDeniedErr("kms:GetKeyLastUsage"))
		requireKmsForbidden(t, err, "kms:GetKeyLastUsage")
		assert.False(t, got.known)
	})

	t.Run("a key that has never been used is known with no operation", func(t *testing.T) {
		// This is the distinction the empty string erased: both cases publish
		// null, but only one of them established anything about the key.
		got, err := kmsLastUsageReadingFrom(&kms.GetKeyLastUsageOutput{}, nil)
		require.NoError(t, err)
		assert.True(t, got.known)
		assert.Nil(t, got.operation)
		assert.Nil(t, got.lastUsedAt)
	})

	t.Run("an empty operation string is treated as never used", func(t *testing.T) {
		got, err := kmsLastUsageReadingFrom(&kms.GetKeyLastUsageOutput{
			KeyLastUsage: &kmstypes.KeyLastUsageData{},
		}, nil)
		require.NoError(t, err)
		assert.True(t, got.known)
		assert.Nil(t, got.operation)
	})

	t.Run("a used key reports the operation and the timestamp", func(t *testing.T) {
		used := time.Date(2026, 8, 20, 9, 30, 0, 0, time.UTC)
		got, err := kmsLastUsageReadingFrom(&kms.GetKeyLastUsageOutput{
			KeyLastUsage: &kmstypes.KeyLastUsageData{
				Operation: kmstypes.KeyLastUsageTrackingOperationDecrypt,
				Timestamp: &used,
			},
		}, nil)
		require.NoError(t, err)
		assert.True(t, got.known)
		require.NotNil(t, got.operation)
		assert.Equal(t, "Decrypt", *got.operation)
		assert.Equal(t, &used, got.lastUsedAt)
	})

	t.Run("a throttle is an error, not an answer", func(t *testing.T) {
		_, err := kmsLastUsageReadingFrom(nil, kmsThrottleErr())
		require.Error(t, err)
		assert.NotErrorIs(t, err, llx.ErrForbidden)
	})
}

func TestKmsLastUsageFields(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		denied, deniedErr := kmsLastUsageReadingFrom(nil, kmsDeniedErr("kms:GetKeyLastUsage"))
		require.Error(t, deniedErr)

		key := &mqlAwsKmsKey{}
		key.cachedLastUsage = denied
		key.cachedLastUsageErr = deniedErr
		key.lastUsageFetched = true

		_, err := key.lastUsageOperation()
		requireKmsForbidden(t, err, "kms:GetKeyLastUsage")
		assert.False(t, key.LastUsageOperation.IsSet(),
			"a denied last-usage read must surface the denial, not read like a key that was never used")

		_, err = key.lastUsedAt()
		requireKmsForbidden(t, err, "kms:GetKeyLastUsage")
		assert.False(t, key.LastUsedAt.IsSet())
	})

	t.Run("never used", func(t *testing.T) {
		never, err := kmsLastUsageReadingFrom(&kms.GetKeyLastUsageOutput{}, nil)
		require.NoError(t, err)

		key := &mqlAwsKmsKey{}
		key.cachedLastUsage = never
		key.lastUsageFetched = true

		op, err := key.lastUsageOperation()
		require.NoError(t, err)
		assert.Equal(t, "", op)
		assert.True(t, key.LastUsageOperation.IsNull())
	})

	t.Run("used", func(t *testing.T) {
		used := time.Date(2026, 8, 20, 9, 30, 0, 0, time.UTC)
		reading, err := kmsLastUsageReadingFrom(&kms.GetKeyLastUsageOutput{
			KeyLastUsage: &kmstypes.KeyLastUsageData{
				Operation: kmstypes.KeyLastUsageTrackingOperationGenerateDataKey,
				Timestamp: &used,
			},
		}, nil)
		require.NoError(t, err)

		key := &mqlAwsKmsKey{}
		key.cachedLastUsage = reading
		key.lastUsageFetched = true

		op, err := key.lastUsageOperation()
		require.NoError(t, err)
		assert.Equal(t, "GenerateDataKey", op)
		assert.False(t, key.LastUsageOperation.IsNull())

		at, err := key.lastUsedAt()
		require.NoError(t, err)
		assert.Equal(t, &used, at)
		assert.False(t, key.LastUsedAt.IsNull())
	})
}

func TestKmsPolicyOrUnreadable(t *testing.T) {
	const keyArn = "arn:aws:kms:us-east-1:123456789012:key/7a4eb143-c07b-4e24-b0b7-f3abfdbbb2c2"

	t.Run("a denied GetKeyPolicy is an error", func(t *testing.T) {
		key := &mqlAwsKmsKey{}
		_, err := kmsPolicyOrUnreadable(&key.Policy, keyArn, nil, kmsDeniedErr("kms:GetKeyPolicy"))
		requireKmsForbidden(t, err, "kms:GetKeyPolicy")
		assert.Contains(t, err.Error(), keyArn)
		assert.False(t, key.Policy.IsSet(),
			`every KMS key has a key policy, so neither "" nor null is a truthful reading of a refused one`)
	})

	t.Run("no policy in the answer publishes null", func(t *testing.T) {
		key := &mqlAwsKmsKey{}
		got, err := kmsPolicyOrUnreadable(&key.Policy, keyArn, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "", got)
		assert.True(t, key.Policy.IsNull())
	})

	t.Run("a policy that was read is published verbatim", func(t *testing.T) {
		doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:*","Resource":"*"}]}`
		key := &mqlAwsKmsKey{}
		got, err := kmsPolicyOrUnreadable(&key.Policy, keyArn, &kms.GetKeyPolicyOutput{Policy: &doc}, nil)
		require.NoError(t, err)
		assert.Equal(t, doc, got)
		assert.False(t, key.Policy.IsNull())
	})

	t.Run("a throttle is an error, not a denial", func(t *testing.T) {
		key := &mqlAwsKmsKey{}
		_, err := kmsPolicyOrUnreadable(&key.Policy, keyArn, nil, kmsThrottleErr())
		require.Error(t, err)
		assert.NotErrorIs(t, err, llx.ErrForbidden)
		assert.False(t, key.Policy.IsSet())
	})
}

// TestKmsDeniedPolicyFailsIsPublic walks the whole collapse the fix breaks: a
// denied GetKeyPolicy used to publish policy:"", which parsed to an empty
// statement list, which statementsAllowPublic answered "not public" for. The
// key whose policy names "Principal": "*" reported isPublic:false.
func TestKmsDeniedPolicyFailsIsPublic(t *testing.T) {
	const keyArn = "arn:aws:kms:us-east-1:123456789012:key/7a4eb143-c07b-4e24-b0b7-f3abfdbbb2c2"
	key := &mqlAwsKmsKey{MqlRuntime: &plugin.Runtime{}, Arn: setString(keyArn)}

	_, deniedErr := kmsPolicyOrUnreadable(&key.Policy, keyArn, nil, kmsDeniedErr("kms:GetKeyPolicy"))
	require.Error(t, deniedErr)
	// What GetOrCompute stores for a policy accessor that returned deniedErr.
	key.Policy = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull, Error: deniedErr}

	_, err := key.policyStatements()
	requireKmsForbidden(t, err, "kms:GetKeyPolicy")

	_, err = key.isPublic()
	requireKmsForbidden(t, err, "kms:GetKeyPolicy")
	assert.False(t, key.IsPublic.IsSet(),
		"a key whose policy could not be read must never be reported as not public")
}

func TestResourceIsPublicOrUnknown(t *testing.T) {
	wildcard := &mqlAwsIamPolicyStatement{
		Effect:     setString("Allow"),
		Principals: setMap(map[string]any{"AWS": []any{"*"}}),
	}
	scoped := &mqlAwsIamPolicyStatement{
		Effect:     setString("Allow"),
		Principals: setMap(map[string]any{"AWS": []any{"arn:aws:iam::123456789012:root"}}),
	}

	t.Run("a null statement list leaves isPublic null", func(t *testing.T) {
		statements := plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		var field plugin.TValue[bool]
		got, err := resourceIsPublicOrUnknown(&statements, &field)
		require.NoError(t, err)
		assert.False(t, got)
		assert.True(t, field.IsNull())
	})

	t.Run("a statement list that was read and grants nobody is a real false", func(t *testing.T) {
		// The regression guard on the fix: nulling the denied case must not
		// sweep the measured "not public" case along with it.
		statements := plugin.TValue[[]any]{Data: []any{scoped}, State: plugin.StateIsSet}
		var field plugin.TValue[bool]
		got, err := resourceIsPublicOrUnknown(&statements, &field)
		require.NoError(t, err)
		assert.False(t, got)
		assert.False(t, field.IsNull())
	})

	t.Run("an empty statement list that was read is a real false", func(t *testing.T) {
		statements := plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
		var field plugin.TValue[bool]
		got, err := resourceIsPublicOrUnknown(&statements, &field)
		require.NoError(t, err)
		assert.False(t, got)
		assert.False(t, field.IsNull())
	})

	t.Run("a wildcard principal is public", func(t *testing.T) {
		statements := plugin.TValue[[]any]{Data: []any{wildcard}, State: plugin.StateIsSet}
		var field plugin.TValue[bool]
		got, err := resourceIsPublicOrUnknown(&statements, &field)
		require.NoError(t, err)
		assert.True(t, got)
		assert.False(t, field.IsNull())
	})

	t.Run("an error on the statement list is returned, not swallowed", func(t *testing.T) {
		boom := errors.New("boom")
		statements := plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull, Error: boom}
		var field plugin.TValue[bool]
		_, err := resourceIsPublicOrUnknown(&statements, &field)
		assert.ErrorIs(t, err, boom)
	})
}

func TestKmsListGrantsError(t *testing.T) {
	const keyArn = "arn:aws:kms:us-east-1:123456789012:key/7a4eb143-c07b-4e24-b0b7-f3abfdbbb2c2"

	t.Run("a denial is forbidden and names the key", func(t *testing.T) {
		err := kmsListGrantsError(keyArn, kmsDeniedErr("kms:ListGrants"))
		requireKmsForbidden(t, err, "kms:ListGrants")
		assert.Contains(t, err.Error(), keyArn)
	})

	t.Run("a throttle is not a denial", func(t *testing.T) {
		err := kmsListGrantsError(keyArn, kmsThrottleErr())
		require.Error(t, err)
		assert.NotErrorIs(t, err, llx.ErrForbidden,
			"only a refusal is forbidden; a throttle established nothing about the grants")
	})

	t.Run("no error stays no error", func(t *testing.T) {
		assert.NoError(t, kmsListGrantsError(keyArn, nil))
	})
}

// TestKmsGrantsOrUnreadable covers the account-wide aws.kms.grants list, which
// joins per-key failures. aws.kms.key.grants returns the classified error.
func TestKmsGrantsOrUnreadable(t *testing.T) {
	const keyArn = "arn:aws:kms:us-east-1:123456789012:key/7a4eb143-c07b-4e24-b0b7-f3abfdbbb2c2"

	t.Run("one refused key nulls the account-wide list", func(t *testing.T) {
		agg := &mqlAwsKms{}
		joined := errors.Join(
			kmsListGrantsError(keyArn, kmsDeniedErr("kms:ListGrants")),
			errors.New("some other key was fine"),
		)
		got, err := kmsGrantsOrUnreadable(&agg.Grants, nil, joined)
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.True(t, agg.Grants.IsNull(),
			"an account-wide list missing one key's grants must not report the rest as the whole")
	})

	t.Run("a list that was read is published", func(t *testing.T) {
		agg := &mqlAwsKms{}
		grants := []any{&mqlAwsKmsGrant{}, &mqlAwsKmsGrant{}}
		got, err := kmsGrantsOrUnreadable(&agg.Grants, grants, nil)
		require.NoError(t, err)
		assert.Len(t, got, 2)
		assert.False(t, agg.Grants.IsNull())
	})

	t.Run("an account with no grants is a real empty list", func(t *testing.T) {
		agg := &mqlAwsKms{}
		got, err := kmsGrantsOrUnreadable(&agg.Grants, []any{}, nil)
		require.NoError(t, err)
		assert.Empty(t, got)
		assert.False(t, agg.Grants.IsNull())
	})

	t.Run("a throttle surfaces as an error", func(t *testing.T) {
		agg := &mqlAwsKms{}
		_, err := kmsGrantsOrUnreadable(&agg.Grants, nil, kmsListGrantsError(keyArn, kmsThrottleErr()))
		require.Error(t, err)
		assert.False(t, agg.Grants.IsNull())
	})
}

func TestMarkKmsUnreadableSetsSetAndNull(t *testing.T) {
	// GetOrCompute keeps a field the accessor set proactively, so the state has
	// to carry both bits: StateIsSet alone caches the zero value as fact, and
	// StateIsNull alone leaves the field looking unresolved.
	var b plugin.TValue[bool]
	got, err := markKmsUnreadable(&b)
	require.NoError(t, err)
	assert.False(t, got)
	assert.True(t, b.IsSet())
	assert.True(t, b.IsNull())

	var i plugin.TValue[int64]
	gotInt, err := markKmsUnreadable(&i)
	require.NoError(t, err)
	assert.Equal(t, int64(0), gotInt)
	assert.True(t, i.IsSet())
	assert.True(t, i.IsNull())
}
