// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepoFilter(t *testing.T) {
	cases := []struct {
		name    string
		include string
		exclude string
		project string
		repo    string
		want    bool
	}{
		{name: "empty keeps everything", project: "scan-test", repo: "ado-scan-test-iac", want: true},
		{name: "include a whole project", include: "scan-test/*", project: "scan-test", repo: "ado-scan-test-iac", want: true},
		{name: "include does not match another project", include: "scan-test/*", project: "legacy-apps", repo: "ado-scan-test-docs", want: false},
		{name: "star does not cross the slash", include: "*", project: "scan-test", repo: "ado-scan-test-iac", want: false},
		{name: "double star crosses the slash", include: "**", project: "scan-test", repo: "ado-scan-test-iac", want: true},
		{name: "any project, repo prefix", include: "*/ado-*", project: "legacy-apps", repo: "ado-scan-test-docs", want: true},
		{name: "project name with a space", include: "scan test/*", project: "scan test", repo: "ado-scan-test-iac", want: true},
		{name: "two includes, second matches", include: "legacy-apps/*, scan-test/ado-scan-test-app", project: "scan-test", repo: "ado-scan-test-app", want: true},
		{name: "exclude removes a match", exclude: "scan-test/ado-scan-test-retired", project: "scan-test", repo: "ado-scan-test-retired", want: false},
		{name: "exclude keeps the rest", exclude: "scan-test/ado-scan-test-retired", project: "scan-test", repo: "ado-scan-test-app", want: true},
		{name: "exclude wins over include", include: "scan-test/*", exclude: "scan-test/ado-scan-test-empty", project: "scan-test", repo: "ado-scan-test-empty", want: false},
		{name: "blank entries are ignored", include: " , scan-test/* ,", project: "scan-test", repo: "x", want: true},
		{name: "case-insensitive include", include: "Scan-Test/ADO-*", project: "scan-test", repo: "ado-scan-test-iac", want: true},
		{name: "case-insensitive exclude", exclude: "scan-test/ado-scan-test-retired", project: "Scan-Test", repo: "ADO-Scan-Test-Retired", want: false},
		{name: "trailing star does not cross the slash", include: "scan*", project: "scan-test", repo: "ado-scan-test-iac", want: false},
		{name: "trailing star stays in the project segment", include: "scan*/*", project: "scan-test", repo: "ado-scan-test-iac", want: true},
		{name: "question mark does not match the slash", include: "scan-test?ado-scan-test-app", project: "scan-test", repo: "ado-scan-test-app", want: false},
		{name: "question mark matches one character in a segment", include: "scan?test/ado-scan-test-app", project: "scan test", repo: "ado-scan-test-app", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := NewRepoFilter(tc.include, tc.exclude)
			require.NoError(t, err)
			assert.Equal(t, tc.want, f.Keep(tc.project, tc.repo))
		})
	}
}

func TestRepoFilterEmpty(t *testing.T) {
	f, err := NewRepoFilter("", "")
	require.NoError(t, err)
	assert.True(t, f.Empty())

	var nilFilter *RepoFilter
	assert.True(t, nilFilter.Empty())
	assert.True(t, nilFilter.Keep("p", "r"))

	f, err = NewRepoFilter("a/*", "")
	require.NoError(t, err)
	assert.False(t, f.Empty())
}

func TestRepoFilterRejectsABadGlob(t *testing.T) {
	_, err := NewRepoFilter("scan-test/[", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad repos pattern")

	_, err = NewRepoFilter("", "{unclosed")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad repos-exclude pattern")
}
