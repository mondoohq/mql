// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr[T any](v T) *T { return &v }

// Synthetic: repository URL shapes a workspace can be created from; no live
// Codesphere account was available.
func TestRedactGitURL(t *testing.T) {
	assert.Nil(t, redactGitURL(nil))

	cases := map[string]string{
		"https://github.com/acme/app.git":                        "https://github.com/acme/app.git",
		"https://ghp_secret@github.com/acme/app.git":             "https://xxxxx@github.com/acme/app.git",
		"https://x-access-token:ghp_secret@github.com/acme/app":  "https://xxxxx@github.com/acme/app",
		"ssh://git:hunter2@gitlab.example.com/acme/app.git":      "ssh://xxxxx@gitlab.example.com/acme/app.git",
		"ssh://git@gitlab.example.com/acme/app.git":              "ssh://git@gitlab.example.com/acme/app.git",
		"ssh://ghp_secret@gitlab.example.com/acme/app.git":       "ssh://xxxxx@gitlab.example.com/acme/app.git",
		"git://ghp_secret@git.example.com/acme/app.git":          "git://xxxxx@git.example.com/acme/app.git",
		"git@github.com:acme/app.git":                            "git@github.com:acme/app.git",
		"ghp_secret@github.com:acme/app.git":                     "xxxxx@github.com:acme/app.git",
		"":                                                       "",
		"not a url with a ghp_secret":                            "",
		"https://user:pa%zzss@github.com/acme/app.git (garbage)": "",
	}
	for in, want := range cases {
		got := redactGitURL(ptr(in))
		require.NotNil(t, got, in)
		assert.Equal(t, want, *got, in)
		assert.NotContains(t, *got, "secret", in)
		assert.NotContains(t, *got, "hunter2", in)
	}
}

// Synthetic: the numeric roles the Codesphere CLI maps (0 and -1 admin, 1
// member) plus a value it does not know.
func TestRoleName(t *testing.T) {
	assert.Equal(t, "admin", roleName(0))
	assert.Equal(t, "admin", roleName(-1))
	assert.Equal(t, "member", roleName(1))
	assert.Equal(t, "unknown(7)", roleName(7))
}

// Synthetic: an absent optional number stays null instead of reading as zero.
func TestFloatDataPtr(t *testing.T) {
	assert.Nil(t, floatDataPtr(nil).Value)
	assert.Equal(t, float64(2.5), floatDataPtr(ptr(float32(2.5))).Value)
}
