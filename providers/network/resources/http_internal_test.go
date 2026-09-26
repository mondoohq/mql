// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net"
	"net/url"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestDefaultHTTPScheme(t *testing.T) {
	tests := []struct {
		name string
		port int32
		want string
	}{
		// A bare `host <domain>` (no scheme, no port) now inspects HTTPS, so the
		// tls and http policies both target the same endpoint.
		{"bare domain, no port", 0, "https"},
		{"standard https port", 443, "https"},
		// An explicit http port stays plain HTTP.
		{"explicit http port", 80, "http"},
		{"non-standard port", 8080, "http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, defaultHTTPScheme(tt.port))
		})
	}
}

func TestHttpNotReachable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		// Connection-level failures against a target that does not speak HTTP:
		// these resolve http.get.header to null so policies skip instead of error.
		{"connection refused", &url.Error{Op: "Get", Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}, true},
		{"connection reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, true},
		{"dns not found", &url.Error{Op: "Get", Err: &net.DNSError{Err: "no such host", IsNotFound: true}}, true},
		{"dial timeout", &url.Error{Op: "Get", Err: timeoutErr{}}, true},
		// Genuine errors stay errors (not "no HTTP here").
		{"redirect loop", &url.Error{Op: "Get", Err: errors.New("stopped after 10 redirects")}, false},
		{"generic", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, httpNotReachable(tt.err))
		})
	}
}

func TestHttpHeaderServer(t *testing.T) {
	t.Run("returns the Server header value", func(t *testing.T) {
		h := &mqlHttpHeader{
			Params: plugin.TValue[map[string]any]{
				Data:  map[string]any{"Server": []any{"nginx"}},
				State: plugin.StateIsSet,
			},
		}
		v, err := h.server()
		require.NoError(t, err)
		assert.Equal(t, "nginx", v)
	})

	t.Run("is null when the Server header is absent", func(t *testing.T) {
		h := &mqlHttpHeader{
			Params: plugin.TValue[map[string]any]{
				Data:  map[string]any{},
				State: plugin.StateIsSet,
			},
		}
		v, err := h.server()
		require.NoError(t, err)
		assert.Equal(t, "", v)
		assert.NotEqual(t, 0, h.Server.State&plugin.StateIsNull)
	})
}

func TestParseXssProtectionDirectives(t *testing.T) {
	t.Run("parses enabled, mode, and report", func(t *testing.T) {
		enabled, mode, report := parseXssProtectionDirectives([]any{"1; mode=block; report=https://example.com/r"})
		assert.Equal(t, llx.BoolTrue, enabled)
		assert.Equal(t, llx.StringData("block"), mode)
		assert.Equal(t, llx.StringData("https://example.com/r"), report)
	})

	t.Run("parses a disabled header", func(t *testing.T) {
		enabled, mode, report := parseXssProtectionDirectives([]any{"0"})
		assert.Equal(t, llx.BoolFalse, enabled)
		assert.Equal(t, llx.NilData, mode)
		assert.Equal(t, llx.NilData, report)
	})

	t.Run("ignores directives that are not part of the header syntax", func(t *testing.T) {
		enabled, _, report := parseXssProtectionDirectives([]any{"1; max-age=99"})
		assert.Equal(t, llx.BoolTrue, enabled)
		assert.Equal(t, llx.NilData, report)
	})

	t.Run("matches directive names case-insensitively", func(t *testing.T) {
		_, mode, report := parseXssProtectionDirectives([]any{"1; Mode=Block; Report=https://example.com/r"})
		assert.Equal(t, llx.StringData("Block"), mode)
		assert.Equal(t, llx.StringData("https://example.com/r"), report)
	})
}

func TestParseStsDirectives(t *testing.T) {
	t.Run("parses max-age, includeSubDomains, and preload", func(t *testing.T) {
		preload, includeSubDomains, maxAge := parseStsDirectives([]any{"max-age=31536000; includeSubDomains; preload"})
		assert.True(t, preload)
		assert.True(t, includeSubDomains)
		assert.Equal(t, llx.TimeData(llx.DurationToTime(31536000)), maxAge)
	})

	t.Run("matches directive names case-insensitively", func(t *testing.T) {
		preload, includeSubDomains, maxAge := parseStsDirectives([]any{"Max-Age=31536000; includeSubdomains; Preload"})
		assert.True(t, preload)
		assert.True(t, includeSubDomains)
		assert.Equal(t, llx.TimeData(llx.DurationToTime(31536000)), maxAge)
	})

	t.Run("reports an invalid max-age value", func(t *testing.T) {
		preload, includeSubDomains, maxAge := parseStsDirectives([]any{"max-age=oops"})
		assert.False(t, preload)
		assert.False(t, includeSubDomains)
		require.Error(t, maxAge.Error)
		assert.Contains(t, maxAge.Error.Error(), "oops")
	})

	t.Run("leaves absent directives unset", func(t *testing.T) {
		preload, includeSubDomains, maxAge := parseStsDirectives([]any{"max-age=600"})
		assert.False(t, preload)
		assert.False(t, includeSubDomains)
		assert.Equal(t, llx.TimeData(llx.DurationToTime(600)), maxAge)
	})
}

func TestParseContentTypeDirectives(t *testing.T) {
	t.Run("parses the media type and parameters", func(t *testing.T) {
		typ, params := parseContentTypeDirectives([]any{"text/html; charset=UTF-8"})
		assert.Equal(t, llx.StringData("text/html"), typ)
		assert.Equal(t, map[string]any{"charset": "UTF-8"}, params.Value)
	})

	t.Run("normalizes the media type and parameter names, keeps values as sent", func(t *testing.T) {
		typ, params := parseContentTypeDirectives([]any{"Text/HTML; CHARSET=UTF-8"})
		assert.Equal(t, llx.StringData("text/html"), typ)
		assert.Equal(t, map[string]any{"charset": "UTF-8"}, params.Value)
	})

	t.Run("has no parameters when none are sent", func(t *testing.T) {
		typ, params := parseContentTypeDirectives([]any{"application/json"})
		assert.Equal(t, llx.StringData("application/json"), typ)
		assert.Equal(t, llx.NilData, params)
	})
}

func TestParseSetCookieDirectives(t *testing.T) {
	t.Run("parses the cookie name, value, and attributes", func(t *testing.T) {
		name, value, params := parseSetCookieDirectives("sid=abc123; Secure; HttpOnly; Max-Age=100")
		assert.Equal(t, llx.StringData("sid"), name)
		assert.Equal(t, llx.StringData("abc123"), value)
		assert.Equal(t, map[string]any{"secure": "", "httponly": "", "max-age": "100"}, params.Value)
	})

	t.Run("keeps cookie name and value casing, normalizes attribute names", func(t *testing.T) {
		name, value, params := parseSetCookieDirectives("SessionId=AbC123; SECURE; httpOnly")
		assert.Equal(t, llx.StringData("SessionId"), name)
		assert.Equal(t, llx.StringData("AbC123"), value)
		assert.Equal(t, map[string]any{"secure": "", "httponly": ""}, params.Value)
	})

	t.Run("keeps attribute value casing", func(t *testing.T) {
		_, _, params := parseSetCookieDirectives("sid=1; Domain=Example.COM; SameSite=Strict")
		assert.Equal(t, map[string]any{"domain": "Example.COM", "samesite": "Strict"}, params.Value)
	})

	t.Run("names a cookie that is set to an empty value", func(t *testing.T) {
		// Clearing a cookie by setting it to the empty string is ordinary, and
		// the header still names the cookie being cleared. Reading the empty
		// value as "not the name-value pair" promoted the first attribute into
		// the cookie and shifted every attribute after it onto the wrong key.
		name, value, params := parseSetCookieDirectives(
			"ct0=; Max-Age=-1; Path=/; Domain=.example.com; Secure; SameSite=Lax")
		assert.Equal(t, llx.StringData("ct0"), name)
		assert.Equal(t, llx.StringData(""), value)
		assert.Equal(t, map[string]any{
			"max-age":  "-1",
			"path":     "/",
			"domain":   ".example.com",
			"secure":   "",
			"samesite": "Lax",
		}, params.Value)
	})

	t.Run("names a cookie whose only field is an empty value", func(t *testing.T) {
		name, value, params := parseSetCookieDirectives("sid=")
		assert.Equal(t, llx.StringData("sid"), name)
		assert.Equal(t, llx.StringData(""), value)
		assert.Equal(t, llx.NilData, params)
	})

	t.Run("keeps a value that contains its own equals signs", func(t *testing.T) {
		name, value, _ := parseSetCookieDirectives("token=a=b=c; Path=/")
		assert.Equal(t, llx.StringData("token"), name)
		assert.Equal(t, llx.StringData("a=b=c"), value)
	})

	t.Run("sets no cookie when the first field is not a name-value pair", func(t *testing.T) {
		// RFC 6265 section 5.2 step 2: a cookie-string with no "=" in its
		// name-value pair is ignored entirely.
		name, value, _ := parseSetCookieDirectives("justaflag; Path=/")
		assert.Equal(t, llx.NilData, name)
		assert.Equal(t, llx.NilData, value)
	})
}

func TestHttpHeaderSetCookie(t *testing.T) {
	t.Run("returns only the first cookie, without absorbing the rest", func(t *testing.T) {
		h := &mqlHttpHeader{
			MqlRuntime: &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}},
			__id:       "https://example.com",
			Params: plugin.TValue[map[string]any]{
				Data: map[string]any{"Set-Cookie": []any{
					"NEXT_LOCALE=en; Path=/; Secure",
					"consent_region=other; Path=/; Secure; HttpOnly",
				}},
				State: plugin.StateIsSet,
			},
		}
		cookie, err := h.setCookie()
		require.NoError(t, err)
		require.NotNil(t, cookie)
		assert.Equal(t, "NEXT_LOCALE", cookie.Name.Data)
		assert.Equal(t, "en", cookie.Value.Data)
		assert.Equal(t, map[string]any{"path": "/", "secure": ""}, cookie.Params.Data)
	})

	t.Run("is null when the response sets no cookies", func(t *testing.T) {
		h := &mqlHttpHeader{
			MqlRuntime: &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}},
			__id:       "https://example.com",
			Params: plugin.TValue[map[string]any]{
				Data:  map[string]any{"Content-Type": []any{"text/html"}},
				State: plugin.StateIsSet,
			},
		}
		cookie, err := h.setCookie()
		require.NoError(t, err)
		assert.Nil(t, cookie)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, h.SetCookie.State)
	})
}

func TestHttpHeaderSetCookies(t *testing.T) {
	newHeader := func(vals ...any) *mqlHttpHeader {
		return &mqlHttpHeader{
			MqlRuntime: &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}},
			__id:       "https://example.com",
			Params: plugin.TValue[map[string]any]{
				Data:  map[string]any{"Set-Cookie": vals},
				State: plugin.StateIsSet,
			},
		}
	}

	t.Run("returns one entry per Set-Cookie header", func(t *testing.T) {
		cookies, err := newHeader(
			"NEXT_LOCALE=en; Path=/; Secure",
			"consent_region=other; Path=/; Secure; HttpOnly",
		).setCookies()
		require.NoError(t, err)
		require.Len(t, cookies, 2)

		first := cookies[0].(*mqlHttpHeaderSetCookie)
		assert.Equal(t, "NEXT_LOCALE", first.Name.Data)
		assert.Equal(t, "en", first.Value.Data)
		assert.Equal(t, map[string]any{"path": "/", "secure": ""}, first.Params.Data)

		second := cookies[1].(*mqlHttpHeaderSetCookie)
		assert.Equal(t, "consent_region", second.Name.Data)
		assert.Equal(t, "other", second.Value.Data)
		assert.Equal(t, map[string]any{"path": "/", "secure": "", "httponly": ""}, second.Params.Data)
	})

	t.Run("is null when the response sets no cookies", func(t *testing.T) {
		h := &mqlHttpHeader{
			MqlRuntime: &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}},
			__id:       "https://example.com",
			Params: plugin.TValue[map[string]any]{
				Data:  map[string]any{"Content-Type": []any{"text/html"}},
				State: plugin.StateIsSet,
			},
		}
		cookies, err := h.setCookies()
		require.NoError(t, err)
		assert.Nil(t, cookies)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, h.SetCookies.State)
	})
}

func TestParseCspDirectives(t *testing.T) {
	t.Run("parses directives into a map", func(t *testing.T) {
		m := parseCspDirectives([]any{"default-src 'self'; script-src 'none'"})
		assert.Equal(t, map[string]any{"default-src": "'self'", "script-src": "'none'"}, m)
	})

	t.Run("normalizes directive names, keeps values as sent", func(t *testing.T) {
		m := parseCspDirectives([]any{"Default-Src 'self'; SCRIPT-SRC https://CDN.example.com"})
		assert.Equal(t, map[string]any{"default-src": "'self'", "script-src": "https://CDN.example.com"}, m)
	})
}
