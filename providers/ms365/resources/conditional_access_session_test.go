// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func TestSecureSignInSessionDict(t *testing.T) {
	t.Run("nil session controls", func(t *testing.T) {
		assert.Nil(t, secureSignInSessionDict(nil))
	})

	t.Run("control not set", func(t *testing.T) {
		sc := models.NewConditionalAccessSessionControls()
		assert.Nil(t, secureSignInSessionDict(sc),
			"a policy that does not set the control reads as null, not as an empty dict")
	})

	t.Run("control enabled", func(t *testing.T) {
		control := models.NewSecureSignInSessionControl()
		control.SetIsEnabled(new(true))
		sc := models.NewConditionalAccessSessionControls()
		sc.SetSecureSignInSession(control)

		assert.Equal(t, map[string]any{"isEnabled": true}, secureSignInSessionDict(sc))
	})

	t.Run("control present but isEnabled absent", func(t *testing.T) {
		sc := models.NewConditionalAccessSessionControls()
		sc.SetSecureSignInSession(models.NewSecureSignInSessionControl())

		assert.Equal(t, map[string]any{"isEnabled": false}, secureSignInSessionDict(sc),
			"an absent flag reads false so a { isEnabled && ... } assertion cannot pass vacuously")
	})

	// disableResilienceDefaults is a separate scalar on sessionControls and is
	// surfaced as its own field -- it must not leak back into this dict, which
	// is what the previous implementation did.
	t.Run("disableResilienceDefaults does not populate the dict", func(t *testing.T) {
		sc := models.NewConditionalAccessSessionControls()
		sc.SetDisableResilienceDefaults(new(true))

		assert.Nil(t, secureSignInSessionDict(sc))
	})
}

// The field is declared `dict` in the .lr, so whatever it holds has to survive
// conversion to an llx primitive. A dict carrying a resource (the previous
// behaviour) fails here with "unsupported child type", which is why every
// policy that set the control errored on read.
func TestSecureSignInSessionDictIsJSONNative(t *testing.T) {
	control := models.NewSecureSignInSessionControl()
	control.SetIsEnabled(new(true))
	sc := models.NewConditionalAccessSessionControls()
	sc.SetSecureSignInSession(control)

	raw := llx.DictData(secureSignInSessionDict(sc))
	result := raw.Result()
	require.NotNil(t, result)
	assert.Empty(t, result.Error, "the dict must convert cleanly to an llx primitive")

	// and the nil case still converts
	nilResult := llx.DictData(secureSignInSessionDict(nil)).Result()
	require.NotNil(t, nilResult)
	assert.Empty(t, nilResult.Error)
	assert.Equal(t, types.Dict, types.Type(nilResult.Data.Type))
}
