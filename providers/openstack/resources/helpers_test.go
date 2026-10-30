// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func TestUserOptionBool(t *testing.T) {
	t.Run("nil map returns false", func(t *testing.T) {
		assert.False(t, userOptionBool(nil, "any"))
	})
	t.Run("missing key returns false", func(t *testing.T) {
		assert.False(t, userOptionBool(map[string]any{"other": true}, "missing"))
	})
	t.Run("true value", func(t *testing.T) {
		assert.True(t, userOptionBool(map[string]any{"k": true}, "k"))
	})
	t.Run("false value", func(t *testing.T) {
		assert.False(t, userOptionBool(map[string]any{"k": false}, "k"))
	})
	t.Run("non-bool string is treated as false", func(t *testing.T) {
		// Keystone may return "true" as a string in some payloads; we
		// treat it as false rather than guess at coercion semantics.
		assert.False(t, userOptionBool(map[string]any{"k": "true"}, "k"))
	})
	t.Run("non-bool number is treated as false", func(t *testing.T) {
		assert.False(t, userOptionBool(map[string]any{"k": 1}, "k"))
	})
}

func TestTimePtr(t *testing.T) {
	t.Run("zero time returns nil", func(t *testing.T) {
		assert.Nil(t, timePtr(time.Time{}))
	})
	t.Run("non-zero time returns pointer", func(t *testing.T) {
		now := time.Now()
		got := timePtr(now)
		if assert.NotNil(t, got) {
			assert.Equal(t, now, *got)
		}
	})
}

func TestStringArg(t *testing.T) {
	t.Run("missing key returns false", func(t *testing.T) {
		_, ok := stringArg(map[string]*llx.RawData{}, "id")
		assert.False(t, ok)
	})
	t.Run("nil RawData returns false", func(t *testing.T) {
		_, ok := stringArg(map[string]*llx.RawData{"id": nil}, "id")
		assert.False(t, ok)
	})
	t.Run("string value returns true", func(t *testing.T) {
		v, ok := stringArg(map[string]*llx.RawData{"id": llx.StringData("x")}, "id")
		assert.True(t, ok)
		assert.Equal(t, "x", v)
	})
	t.Run("non-string value returns false", func(t *testing.T) {
		_, ok := stringArg(map[string]*llx.RawData{"id": llx.IntData(7)}, "id")
		assert.False(t, ok)
	})
}

func TestTranslateOpenstackError(t *testing.T) {
	t.Run("nil passes through", func(t *testing.T) {
		assert.NoError(t, translateOpenstackError(nil))
	})
	t.Run("401 swallowed", func(t *testing.T) {
		err := gophercloud.ErrUnexpectedResponseCode{Actual: 401}
		assert.NoError(t, translateOpenstackError(err))
	})
	t.Run("403 swallowed", func(t *testing.T) {
		err := gophercloud.ErrUnexpectedResponseCode{Actual: 403}
		assert.NoError(t, translateOpenstackError(err))
	})
	t.Run("404 swallowed (list endpoints treat absent service as empty)", func(t *testing.T) {
		err := gophercloud.ErrUnexpectedResponseCode{Actual: 404}
		assert.NoError(t, translateOpenstackError(err))
	})
	t.Run("500 propagates", func(t *testing.T) {
		err := gophercloud.ErrUnexpectedResponseCode{Actual: 500}
		assert.Error(t, translateOpenstackError(err))
	})
	t.Run("non-HTTP error propagates", func(t *testing.T) {
		err := errors.New("dial tcp: connection refused")
		assert.Error(t, translateOpenstackError(err))
	})
}

func TestTranslateGetError(t *testing.T) {
	t.Run("nil passes through", func(t *testing.T) {
		assert.NoError(t, translateGetError(nil))
	})
	t.Run("401 swallowed", func(t *testing.T) {
		err := gophercloud.ErrUnexpectedResponseCode{Actual: 401}
		assert.NoError(t, translateGetError(err))
	})
	t.Run("403 swallowed", func(t *testing.T) {
		err := gophercloud.ErrUnexpectedResponseCode{Actual: 403}
		assert.NoError(t, translateGetError(err))
	})
	t.Run("404 propagates so genuine missing resource surfaces", func(t *testing.T) {
		err := gophercloud.ErrUnexpectedResponseCode{Actual: 404}
		assert.Error(t, translateGetError(err))
	})
	t.Run("500 propagates", func(t *testing.T) {
		err := gophercloud.ErrUnexpectedResponseCode{Actual: 500}
		assert.Error(t, translateGetError(err))
	})
}
