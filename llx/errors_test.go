// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

func TestKindOf(t *testing.T) {
	t.Run("nil and unclassified answer the same", func(t *testing.T) {
		assert.Equal(t, ErrorKind_ERROR_KIND_UNSPECIFIED, KindOf(nil))
		assert.Equal(t, ErrorKind_ERROR_KIND_UNSPECIFIED, KindOf(errors.New("boom")))
	})

	t.Run("survives wrapping", func(t *testing.T) {
		// The reason the kind is a type and not a message: a caller that adds
		// context must not destroy the classification.
		err := fmt.Errorf("listing buckets: %w", Forbidden(errors.New("AccessDenied")))
		assert.Equal(t, ErrorKind_ERROR_KIND_FORBIDDEN, KindOf(err))
	})
}

func TestErrorIs(t *testing.T) {
	err := fmt.Errorf("reading policy: %w", NotApplicable(errors.New("API not enabled")))

	assert.True(t, errors.Is(err, ErrNotApplicable))
	assert.False(t, errors.Is(err, ErrForbidden))
	assert.False(t, errors.Is(errors.New("API not enabled"), ErrNotApplicable))
}

func TestErrorKeepsTheTargetsWords(t *testing.T) {
	err := Forbidden(errors.New("AccessDenied: not authorized to perform ec2:DescribeInstances"))
	assert.Equal(t, "AccessDenied: not authorized to perform ec2:DescribeInstances", err.Error())
	assert.Equal(t, "AccessDenied: not authorized to perform ec2:DescribeInstances", errors.Unwrap(err).Error())
}

func TestErrorWithoutCause(t *testing.T) {
	// A kind with no underlying error still has to render as something a human
	// can read, since the message is what every existing consumer prints.
	assert.Equal(t, "access denied", Forbidden(nil).Error())
}

func TestErrorDetailOf(t *testing.T) {
	t.Run("unclassified encodes nothing", func(t *testing.T) {
		assert.Nil(t, ErrorDetailOf(nil))
		assert.Nil(t, ErrorDetailOf(errors.New("boom")))
	})

	t.Run("carries every field", func(t *testing.T) {
		err := Forbidden(errors.New("AccessDenied"),
			WithScope(ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"),
			WithPermissions("ec2:DescribeInstances", "ec2:DescribeTags"),
			WithRetryAfter(1500*time.Millisecond),
		)

		detail := ErrorDetailOf(err)
		require.NotNil(t, detail)
		assert.Equal(t, ErrorKind_ERROR_KIND_FORBIDDEN, detail.Kind)
		assert.Equal(t, ErrorScope_ERROR_SCOPE_PARTITION, detail.Scope)
		assert.Equal(t, "eu-west-1", detail.ScopeId)
		assert.Equal(t, []string{"ec2:DescribeInstances", "ec2:DescribeTags"}, detail.Permissions)
		assert.Equal(t, int64(1500), detail.RetryAfterMs)
	})

	t.Run("reads through a wrap", func(t *testing.T) {
		err := fmt.Errorf("listing instances: %w", TooManyRequests(errors.New("Throttling")))
		require.NotNil(t, ErrorDetailOf(err))
		assert.Equal(t, ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS, ErrorDetailOf(err).Kind)
	})
}

func TestErrorFromDetail(t *testing.T) {
	t.Run("nothing at all", func(t *testing.T) {
		assert.NoError(t, ErrorFromDetail("", nil))
	})

	t.Run("a message with no detail stays unclassified", func(t *testing.T) {
		// Results written before this field existed, and every provider that
		// has not been migrated yet, land here. They must not acquire a kind.
		err := ErrorFromDetail("something broke", nil)
		require.Error(t, err)
		assert.Equal(t, "something broke", err.Error())
		assert.Equal(t, ErrorKind_ERROR_KIND_UNSPECIFIED, KindOf(err))
	})

	t.Run("an unspecified kind stays unclassified", func(t *testing.T) {
		err := ErrorFromDetail("something broke", &ErrorDetail{Permissions: []string{"s3:GetObject"}})
		require.Error(t, err)
		assert.Equal(t, ErrorKind_ERROR_KIND_UNSPECIFIED, KindOf(err))
	})
}

func TestErrorRoundTrip(t *testing.T) {
	// The property the whole design rests on: a classified error crosses a
	// process boundary as (message, detail) and comes back classified, with the
	// target's own words intact.
	original := Unauthenticated(errors.New("token expired"),
		WithScope(ErrorScope_ERROR_SCOPE_ASSET, ""),
		WithRetryAfter(30*time.Second),
	)

	back := ErrorFromDetail(original.Error(), ErrorDetailOf(original))
	require.Error(t, back)
	assert.Equal(t, "token expired", back.Error())
	assert.True(t, errors.Is(back, ErrUnauthenticated))

	var typed *Error
	require.True(t, errors.As(back, &typed))
	assert.Equal(t, ErrorScope_ERROR_SCOPE_ASSET, typed.Scope)
	assert.Equal(t, 30*time.Second, typed.RetryAfter)
}

func TestResultRoundTripCarriesTheKind(t *testing.T) {
	// RawData -> Result -> RawData is the recording and upstream path.
	raw := &RawData{
		Type: types.String,
		Error: NotFound(errors.New("bucket does not exist"),
			WithScope(ErrorScope_ERROR_SCOPE_RESOURCE, "")),
	}

	res := raw.Result()
	require.NotNil(t, res.ErrorDetail)
	assert.Equal(t, ErrorKind_ERROR_KIND_NOT_FOUND, res.ErrorDetail.Kind)
	assert.Equal(t, "bucket does not exist", res.Error)

	back := res.RawData()
	require.Error(t, back.Error)
	assert.True(t, errors.Is(back.Error, ErrNotFound))
	assert.Equal(t, "bucket does not exist", back.Error.Error())
}

func TestResultRoundTripWithoutAKind(t *testing.T) {
	raw := &RawData{Type: types.String, Error: errors.New("plain failure")}

	res := raw.Result()
	assert.Nil(t, res.ErrorDetail)

	back := res.RawData()
	require.Error(t, back.Error)
	assert.Equal(t, "plain failure", back.Error.Error())
	assert.Equal(t, ErrorKind_ERROR_KIND_UNSPECIFIED, KindOf(back.Error))
}

func TestErrorNames(t *testing.T) {
	assert.Equal(t, "forbidden", ErrorKind_ERROR_KIND_FORBIDDEN.Name())
	assert.Equal(t, "too_many_requests", ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS.Name())
	assert.Equal(t, "unspecified", ErrorKind_ERROR_KIND_UNSPECIFIED.Name())
	assert.Equal(t, "partition", ErrorScope_ERROR_SCOPE_PARTITION.Name())
}

func TestErrorMarshalZerologObject(t *testing.T) {
	t.Run("writes the classification", func(t *testing.T) {
		var buf bytes.Buffer
		e := Forbidden(errors.New("AccessDenied"),
			WithScope(ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"),
			WithPermissions("ec2:DescribeAddresses"),
			WithRetryAfter(2*time.Second))
		logTo(&buf).EmbedObject(e).Send()

		var got map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
		assert.Equal(t, "forbidden", got["kind"])
		assert.Equal(t, "partition", got["scope"])
		assert.Equal(t, "eu-west-1", got["scope_id"])
		assert.Equal(t, []any{"ec2:DescribeAddresses"}, got["permissions"])
		assert.Contains(t, got, "retry_after")
		// the message is the caller's Err, not written twice
		assert.NotContains(t, got, "error")
	})

	t.Run("leaves out what is not set", func(t *testing.T) {
		var buf bytes.Buffer
		logTo(&buf).EmbedObject(NotFound(nil)).Send()
		assert.JSONEq(t, `{"kind":"not_found"}`, buf.String())
	})

	t.Run("a nil error writes nothing", func(t *testing.T) {
		var buf bytes.Buffer
		var e *Error
		logTo(&buf).EmbedObject(e).Send()
		assert.JSONEq(t, `{}`, buf.String())
	})
}

func logTo(buf *bytes.Buffer) *zerolog.Event {
	l := zerolog.New(buf)
	return l.Log()
}
