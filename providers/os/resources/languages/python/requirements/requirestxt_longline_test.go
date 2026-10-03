// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package requirements

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRequiresTxtDependenciesKeepsNamesAfterLongLine(t *testing.T) {
	content := "requests\n# " + strings.Repeat("x", 70000) + "\nurllib3\n"
	deps, err := ParseRequiresTxtDependencies(strings.NewReader(content))
	require.NoError(t, err)
	assert.Contains(t, deps, "urllib3")
}

func TestParseRequiresTxtDependenciesReturnsReadError(t *testing.T) {
	_, err := ParseRequiresTxtDependencies(io.MultiReader(strings.NewReader("requests\n"), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
}
