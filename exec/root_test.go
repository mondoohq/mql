// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package exec_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// Content narrowed to a set of asset roots (ADR 031) must not hard-fail on an
// asset outside that set until a caller opts into the model: "not applicable to
// this asset" and "this check failed" are different answers, and a caller that
// cannot tell them apart would report the first as the second.
func TestRootMismatchRefusalIsOptIn(t *testing.T) {
	rt := testutils.LinuxMock()

	// A bundle that targets a platform this asset is not. Built directly rather
	// than compiled, because compiling it here would resolve against this
	// asset's own root and never produce the mismatch.
	bundle, err := mqlc.Compile("asset.platform", nil, mqlc.NewConfigFrom(rt, testutils.Features))
	require.NoError(t, err)
	bundle.AssetRoot = "os.any"
	bundle.CompatibleRoots = []string{"os.windows"}

	t.Run("v14 runs it", func(t *testing.T) {
		_, err := exec.ExecuteCode(rt, bundle, nil, testutils.Features)
		assert.NoError(t, err, "execution is unchanged until the model is opted into")
	})

	t.Run("rooted mode refuses it", func(t *testing.T) {
		features := append(mql.Features{}, testutils.Features...)
		features = append(features, byte(mql.RootedNamespace))

		_, err := exec.ExecuteCode(rt, bundle, nil, features)
		require.Error(t, err)
		assert.True(t, errors.Is(err, mqlc.ErrRootMismatch),
			"the caller has to be able to tell this apart from a failure")
	})

	// A bundle that derived no requirement runs everywhere, which is every
	// bundle compiled before this existed.
	t.Run("content with no requirement is never refused", func(t *testing.T) {
		features := append(mql.Features{}, testutils.Features...)
		features = append(features, byte(mql.RootedNamespace))

		plain := &llx.CodeBundle{CodeV2: bundle.CodeV2, Labels: bundle.Labels}
		_, err := exec.ExecuteCode(rt, plain, nil, features)
		assert.NoError(t, err)
	})
}
