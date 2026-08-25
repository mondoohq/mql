// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mycnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitPathList(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{
			// The reported case: MySQL and MariaDB separate tmpdir with ':' on
			// Unix, so this used to come back as one element holding both paths.
			name:  "unix colon separated",
			value: "/srv/mqlprobe/tmp1:/srv/mqlprobe/tmp2",
			want:  []string{"/srv/mqlprobe/tmp1", "/srv/mqlprobe/tmp2"},
		},
		{
			name:  "three unix paths",
			value: "/var/tmp:/tmp:/mnt/fast",
			want:  []string{"/var/tmp", "/tmp", "/mnt/fast"},
		},
		{
			name:  "single path is unchanged",
			value: "/var/tmp",
			want:  []string{"/var/tmp"},
		},
		{
			name:  "surrounding whitespace and quotes are trimmed",
			value: `  "/var/tmp" : '/tmp'  `,
			want:  []string{"/var/tmp", "/tmp"},
		},
		{
			name:  "empty elements are dropped",
			value: "/var/tmp::/tmp:",
			want:  []string{"/var/tmp", "/tmp"},
		},
		{
			name:  "empty value",
			value: "",
			want:  nil,
		},
		{
			name:  "whitespace only",
			value: "   ",
			want:  nil,
		},
		{
			// Windows uses ';'. A drive letter's own colon must survive.
			name:  "windows semicolon separated",
			value: `C:\temp;D:\scratch`,
			want:  []string{`C:\temp`, `D:\scratch`},
		},
		{
			name:  "single windows path keeps its drive colon",
			value: `C:\temp`,
			want:  []string{`C:\temp`},
		},
		{
			name:  "windows forward slashes",
			value: `C:/temp`,
			want:  []string{`C:/temp`},
		},
		{
			// A comma is a legal directory character and must NOT split here,
			// which is exactly why tmpdir cannot reuse SplitList.
			name:  "comma is not a separator for paths",
			value: "/var/tmp,odd",
			want:  []string{"/var/tmp,odd"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SplitPathList(tc.value))
		})
	}
}

// SplitList must keep its comma/space behaviour: it still backs tls_version,
// sql_mode and friends, where ':' is not a delimiter.
func TestSplitListUnchangedForCommaLists(t *testing.T) {
	assert.Equal(t, []string{"TLSv1.2", "TLSv1.3"}, SplitList("TLSv1.2,TLSv1.3"))
	assert.Equal(t, []string{"NO_ENGINE_SUBSTITUTION", "STRICT_TRANS_TABLES"},
		SplitList("NO_ENGINE_SUBSTITUTION STRICT_TRANS_TABLES"))
	assert.Equal(t, []string{"a:b"}, SplitList("a:b"), "SplitList must not split on a colon")
	assert.Nil(t, SplitList(""))
}
