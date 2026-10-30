// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFreeBSDLoaderConf(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  map[string]string
	}{
		{
			name: "defaults with ${module_blacklist} expansion",
			files: []string{`# Loader module blacklist
module_blacklist="drm drm2"	# Loader module blacklist
module_blacklist="${module_blacklist} nvidia-drm"
`},
			want: map[string]string{"module_blacklist": "drm drm2 nvidia-drm"},
		},
		{
			name: "unquoted values, comments and dotted names",
			files: []string{`zfs_load=NO # unquoted, with a comment
  hint.atkbd.0.disabled=1
not an assignment
`},
			want: map[string]string{"zfs_load": "NO", "hint.atkbd.0.disabled": "1"},
		},
		{
			name: "a later file extends the value",
			files: []string{
				`module_blacklist="drm"`,
				`module_blacklist="${module_blacklist};sctp"`,
			},
			want: map[string]string{"module_blacklist": "drm;sctp"},
		},
		{
			name: "a later file replaces the value",
			files: []string{
				`module_blacklist="drm"`,
				`module_blacklist=""`,
			},
			want: map[string]string{"module_blacklist": ""},
		},
		{
			name:  "an unset variable expands to nothing",
			files: []string{`module_blacklist="${module_blacklist} sctp"`},
			want:  map[string]string{"module_blacklist": " sctp"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := map[string]string{}
			for _, f := range c.files {
				ParseFreeBSDLoaderConf(f, env)
			}
			assert.Equal(t, c.want, env)
		})
	}
}

func TestParseFreeBSDModuleBlacklist(t *testing.T) {
	cases := []struct {
		value string
		want  map[string]bool
	}{
		// the loader splits on anything but letters, digits, '-' and '_'
		{" drm,nvidia-drm;sctp  if_rtw88 ", map[string]bool{"drm": true, "nvidia-drm": true, "sctp": true, "if_rtw88": true}},
		{"", map[string]bool{}},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, ParseFreeBSDModuleBlacklist(c.value), c.value)
	}
}

func TestFreeBSDLoaderConfFiles(t *testing.T) {
	assert.Equal(t, []string{
		"/boot/defaults/loader.conf",
		"/boot/loader.conf",
		"/boot/loader.conf.d/a.conf",
		"/boot/loader.conf.d/b.conf",
		"/boot/loader.conf.local",
	}, FreeBSDLoaderConfFiles([]string{"/boot/loader.conf.d/a.conf", "/boot/loader.conf.d/b.conf"}))
}
