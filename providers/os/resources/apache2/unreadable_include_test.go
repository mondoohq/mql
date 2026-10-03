// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// httpd refuses to start when an included file cannot be read, so a non-root
// scan that skips one reports a configuration httpd would not run. A file that
// is simply missing is not a refusal.
func TestParseUnreadableIncludes(t *testing.T) {
	files := map[string]string{
		"/etc/httpd/conf/httpd.conf": "ServerRoot \"/etc/httpd\"\nTraceEnable Off\n" +
			"IncludeOptional conf.d/*.conf\nInclude conf.modules.d/*.conf\nInclude /etc/httpd/missing.conf\n",
		"/etc/httpd/conf.d/a.conf": "ServerTokens Prod\n",
	}
	denied := map[string]bool{"/etc/httpd/conf.d/zz.conf": true}
	fileContent := func(path string) (string, error) {
		if denied[path] {
			return "", &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
		}
		c, ok := files[path]
		if !ok {
			return "", &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		}
		return c, nil
	}
	globExpand := func(pattern string) ([]string, error) {
		switch pattern {
		case "conf.d/*.conf":
			return []string{"/etc/httpd/conf.d/a.conf", "/etc/httpd/conf.d/zz.conf"}, nil
		case "conf.modules.d/*.conf":
			return nil, &fs.PathError{Op: "open", Path: "/etc/httpd/conf.modules.d", Err: fs.ErrPermission}
		}
		return []string{pattern}, nil
	}

	cfg, err := ParseWithGlob("/etc/httpd/conf/httpd.conf", fileContent, globExpand, nil)
	require.NoError(t, err)
	assert.Equal(t, "Prod", cfg.Params["ServerTokens"])

	require.Len(t, cfg.Unreadable, 2)
	for _, e := range cfg.Unreadable {
		assert.True(t, errors.Is(e, fs.ErrPermission), e.Error())
	}
	assert.ErrorContains(t, cfg.Unreadable[0], "/etc/httpd/conf.d/zz.conf")
	assert.ErrorContains(t, cfg.Unreadable[1], "/etc/httpd/conf.modules.d")
}
