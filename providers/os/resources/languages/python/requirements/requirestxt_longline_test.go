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

// A long hash or URL line must not end the parse: before it would fail the
// whole file with bufio.ErrTooLong.
func TestParseRequirementsTxtKeepsRequirementsAfterLongLine(t *testing.T) {
	content := "requests==2.31.0\n# " + strings.Repeat("x", 70000) + "\nurllib3==2.0.7\n"
	reqs, err := ParseRequirementsTxt(strings.NewReader(content))
	require.NoError(t, err)
	require.Len(t, reqs, 2)
	assert.Equal(t, "urllib3", reqs[1].Name)
}
