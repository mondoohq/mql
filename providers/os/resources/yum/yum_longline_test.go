// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package yum

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A repository with a long baseurl list must not hide the repositories
// listed after it.
func TestParseReposKeepsReposAfterLongLine(t *testing.T) {
	out := "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-status        : enabled\n" +
		"Repo-baseurl       : " + strings.Repeat("https://mirror.example.com/x/,", 3000) + "https://mirror.example.com/y/\n\n" +
		"Repo-id            : thirdparty\nRepo-name          : Third party\nRepo-status        : enabled\n"

	repos, err := ParseRepos(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, repos, 2)
	assert.Equal(t, "thirdparty", repos[1].Id)
}

func TestParseReposReturnsReadError(t *testing.T) {
	_, err := ParseRepos(io.MultiReader(strings.NewReader("Repo-id            : baseos\n"), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
}
