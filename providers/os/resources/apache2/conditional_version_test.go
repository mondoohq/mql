// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mod_version's <IfVersion [[!]operator] version>, against httpd 2.4.62 (RHEL 9).
func TestIfVersionHolds(t *testing.T) {
	for _, tt := range []struct {
		arg  string
		want bool
	}{
		{"< 2.0", false},
		{">= 2.4", true},
		{"> 2.4", true}, // 2.4 reads as 2.4.0
		{"> 2.4.62", false},
		{">= 2.4.62", true},
		{"<= 2.4.61", false},
		{"2.4.62", true},
		{"= 2.4.62", true},
		{"== 2.4", false},
		{"!= 2.4.62", false},
		{"!< 2.0", true},
		{"!>= 2.4", false},
		{"= /^2\\.4\\./", true},
		{"/^2\\.2\\./", false},
		{"~ ^2\\.4", true},
		{"!~ ^2\\.4", false},
		{"2", false}, // 2 reads as 2.0.0
		{"> 2", true},
	} {
		st := newParseState(nil, nil, nil, ParseOptions{Version: "2.4.62"})
		assert.Equalf(t, tt.want, st.holds("IfVersion", tt.arg), "<IfVersion %s>", tt.arg)
	}

	t.Run("without a known version the contents apply", func(t *testing.T) {
		st := newParseState(nil, nil, nil, ParseOptions{})
		assert.True(t, st.holds("IfVersion", "< 2.0"))
	})

	t.Run("an argument httpd would reject applies", func(t *testing.T) {
		st := newParseState(nil, nil, nil, ParseOptions{Version: "2.4.62"})
		assert.True(t, st.holds("IfVersion", "< 2.x"))
	})
}

func TestIfFileHolds(t *testing.T) {
	var asked []string
	exists := func(p string) bool {
		asked = append(asked, p)
		return p == "/etc/httpd/conf.d/ssl.conf" || p == "conf/httpd.conf"
	}
	st := newParseState(nil, nil, nil, ParseOptions{FileExists: exists})
	assert.False(t, st.holds("IfFile", "/nonexistent-sweep"))
	assert.True(t, st.holds("IfFile", "!/nonexistent-sweep"))
	assert.True(t, st.holds("IfFile", `"/etc/httpd/conf.d/ssl.conf"`))
	assert.False(t, st.holds("IfFile", "!/etc/httpd/conf.d/ssl.conf"))
	// a relative path is resolved by the caller against ServerRoot
	assert.True(t, st.holds("IfFile", "conf/httpd.conf"))
	assert.Equal(t, []string{"/nonexistent-sweep", "/nonexistent-sweep", "/etc/httpd/conf.d/ssl.conf", "/etc/httpd/conf.d/ssl.conf", "conf/httpd.conf"}, asked)

	t.Run("without a filesystem the contents apply", func(t *testing.T) {
		st := newParseState(nil, nil, nil, ParseOptions{})
		assert.True(t, st.holds("IfFile", "/nonexistent-sweep"))
	})
}

// The sweep's A14 fixture: ServerTokens set only inside a false <IfVersion>
// and a false <IfFile>; the server sends its full banner.
func TestParseIfVersionIfFile(t *testing.T) {
	files := map[string]string{
		"/etc/httpd/conf/httpd.conf": "ServerRoot \"/etc/httpd\"\nIncludeOptional conf.d/*.conf\n",
		"/etc/httpd/conf.d/zz-sweep-flip.conf": "<IfVersion < 2.0>\n  ServerTokens Prod\n</IfVersion>\n" +
			"<IfFile /nonexistent-sweep>\n  TraceEnable Off\n</IfFile>\n" +
			"<IfVersion >= 2.4>\n  ServerSignature On\n</IfVersion>\n",
	}
	fileContent := func(p string) (string, error) { return files[p], nil }
	glob := func(p string) ([]string, error) {
		if p == "conf.d/*.conf" {
			return []string{"/etc/httpd/conf.d/zz-sweep-flip.conf"}, nil
		}
		return []string{p}, nil
	}
	cfg, err := ParseWithGlobOptions("/etc/httpd/conf/httpd.conf", fileContent, glob, nil, ParseOptions{
		Version:    "2.4.62",
		FileExists: func(string) bool { return false },
	})
	require.NoError(t, err)
	assert.NotContains(t, cfg.Params, "ServerTokens")
	assert.NotContains(t, cfg.Params, "TraceEnable")
	assert.Equal(t, "On", cfg.Params["ServerSignature"])
}
