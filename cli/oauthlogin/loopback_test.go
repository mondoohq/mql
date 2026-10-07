// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func renderResultPage(t *testing.T, status int, ok bool, msg string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	writeResultPage(rec, status, ok, msg)
	require.Equal(t, status, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	return rec.Body.String()
}

func TestResultPage_Success(t *testing.T) {
	page := renderResultPage(t, http.StatusOK, true, "")

	assert.Contains(t, page, "You're logged in")
	// the still is in the page, escaped, so it shows without scripts
	assert.Contains(t, page, `<pre id="cat" aria-hidden="true"> /\_/\  `+"\n( *v* ) \n &gt; ^ &lt;  </pre>")
	// every frame is in the script, JSON-encoded by html/template
	assert.Contains(t, page, `( *v* )/`)
	assert.Contains(t, page, `( *v* )~`)
	assert.Contains(t, page, `( *.* )~`)
	assert.Contains(t, page, `( *.* )\\`)
	assert.Contains(t, page, "@media (prefers-reduced-motion:reduce)")
	assert.Contains(t, page, `matchMedia("(prefers-reduced-motion: reduce)")`)
	assert.NotContains(t, page, "Login not completed")
}

func TestResultPage_FailureEscapesMessage(t *testing.T) {
	page := renderResultPage(t, http.StatusBadRequest, false, `login failed: <script>alert("x")</script>`)

	assert.Contains(t, page, "Login not completed")
	assert.Contains(t, page, "login failed: &lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;")
	assert.NotContains(t, page, `<script>alert`)
	assert.Contains(t, page, `( T.T )`)
	assert.Contains(t, page, `class="fail"`)
	assert.Contains(t, page, "@media (prefers-reduced-motion:reduce)")
}

func TestCatFrames_FixedSize(t *testing.T) {
	for name, c := range map[string]catSet{"love": catLove, "cry": catCry} {
		all := append([][]string{c.still}, c.frames...)
		for _, f := range all {
			require.Len(t, f, len(c.still), name)
			for i, row := range f {
				assert.Equal(t, utf8.RuneCountInString(c.still[i]), utf8.RuneCountInString(row), "%s row %q", name, row)
			}
		}
	}
	for _, f := range inlineCatFrames {
		assert.Equal(t, utf8.RuneCountInString(inlineCatFrames[0]), utf8.RuneCountInString(f), f)
	}
}
