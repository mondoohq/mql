// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ghErrorResponse(status int) error {
	return &github.ErrorResponse{
		Response: &http.Response{StatusCode: status},
	}
}

func TestIsAccessDeniedOrNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil error", err: nil, want: false},
		{name: "404 not found", err: ghErrorResponse(http.StatusNotFound), want: true},
		{name: "403 forbidden", err: ghErrorResponse(http.StatusForbidden), want: true},
		{name: "500 server error", err: ghErrorResponse(http.StatusInternalServerError), want: false},
		{name: "200 ok", err: ghErrorResponse(http.StatusOK), want: false},
		{name: "plain error", err: errors.New("boom"), want: false},
		{name: "no available registrations fallback", err: errors.New("no available registrations"), want: true},
		{name: "wrapped 404", err: errors.Join(errors.New("ctx"), ghErrorResponse(http.StatusNotFound)), want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isAccessDeniedOrNotFound(tc.err))
		})
	}
}

type samlErr = struct {
	Type       string         `json:"type"`
	Message    string         `json:"message"`
	Extensions map[string]any `json:"extensions"`
}

func TestIsSamlScopeOrPermissionError(t *testing.T) {
	tests := []struct {
		name string
		errs []samlErr
		want bool
	}{
		{name: "no errors", errs: nil, want: false},
		{name: "unrelated error", errs: []samlErr{{Type: "NOT_FOUND", Message: "missing"}}, want: false},
		{name: "type INSUFFICIENT_SCOPES", errs: []samlErr{{Type: "INSUFFICIENT_SCOPES"}}, want: true},
		{name: "type lowercase forbidden", errs: []samlErr{{Type: "forbidden"}}, want: true},
		{name: "type unauthorized", errs: []samlErr{{Type: "UNAUTHORIZED"}}, want: true},
		{name: "extensions code", errs: []samlErr{{Extensions: map[string]any{"code": "insufficient_scopes"}}}, want: true},
		{name: "message contains scope", errs: []samlErr{{Message: "Your token is missing the required scope"}}, want: true},
		{name: "message must have admin", errs: []samlErr{{Message: "You must have admin access"}}, want: true},
		{name: "first benign, second matches", errs: []samlErr{{Type: "OTHER"}, {Type: "FORBIDDEN"}}, want: true},
		{name: "non-string extension code ignored", errs: []samlErr{{Extensions: map[string]any{"code": 42}}}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isSamlScopeOrPermissionError(tc.errs))
		})
	}
}

func TestKeyAgeInDays(t *testing.T) {
	tests := []struct {
		name      string
		createdAt *github.Timestamp
		want      int64
	}{
		{name: "nil timestamp", createdAt: nil, want: -1},
		{name: "zero timestamp", createdAt: &github.Timestamp{}, want: -1},
		{name: "two days old", createdAt: &github.Timestamp{Time: time.Now().Add(-48 * time.Hour)}, want: 2},
		{name: "ten days old", createdAt: &github.Timestamp{Time: time.Now().Add(-10 * 24 * time.Hour)}, want: 10},
		{name: "younger than a day", createdAt: &github.Timestamp{Time: time.Now().Add(-1 * time.Hour)}, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, keyAgeInDays(tc.createdAt))
		})
	}
}

func TestIsCodeownersCommentLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{name: "empty line", line: "", want: false},
		{name: "leading hash", line: "# comment", want: true},
		{name: "indented hash with spaces", line: "   # comment", want: true},
		{name: "indented hash with tab", line: "\t# comment", want: true},
		{name: "rule line", line: "*.go @team", want: false},
		{name: "inline hash is not a comment", line: "path/to/#special @owner", want: false},
		{name: "whitespace only", line: "   ", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isCodeownersCommentLine(tc.line))
		})
	}
}

func TestParseCodeowners(t *testing.T) {
	content := "# top comment\n" +
		"\n" +
		"*.go      @org/go-team @alice\n" +
		"   # indented comment\n" +
		"/docs/    @org/docs-team\n" +
		"path/to/#special   @owner\r\n" +
		"   \n" +
		"*.js\n"

	rules := parseCodeowners(content)

	assert.Equal(t, []codeownersRule{
		{pattern: "*.go", owners: []string{"@org/go-team", "@alice"}, lineNumber: 3},
		{pattern: "/docs/", owners: []string{"@org/docs-team"}, lineNumber: 5},
		{pattern: "path/to/#special", owners: []string{"@owner"}, lineNumber: 6},
		{pattern: "*.js", owners: []string{}, lineNumber: 8},
	}, rules)
}

func TestParseCodeowners_Empty(t *testing.T) {
	assert.Empty(t, parseCodeowners(""))
	assert.Empty(t, parseCodeowners("# only a comment\n\n   \n"))
}

func TestHttpStatusOf(t *testing.T) {
	tests := []struct {
		name string
		resp *github.Response
		err  error
		want int
	}{
		{name: "no response, no typed error", resp: nil, err: errors.New("dial tcp: connection refused"), want: 0},
		{name: "status from the response", resp: &github.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, err: errors.New("boom"), want: http.StatusNotFound},
		{name: "response without an http response falls back to the error", resp: &github.Response{}, err: ghErrorResponse(http.StatusForbidden), want: http.StatusForbidden},
		{name: "status from a wrapped typed error", resp: nil, err: errors.Join(errors.New("ctx"), ghErrorResponse(http.StatusUnauthorized)), want: http.StatusUnauthorized},
		{name: "typed error without a response", resp: nil, err: &github.ErrorResponse{}, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, httpStatusOf(tc.resp, tc.err))
		})
	}
}

func TestAuditLogStreamConfigError(t *testing.T) {
	const enterprisePath = "/enterprises/{enterprise}/audit-log/streams"

	t.Run("no error stays no error", func(t *testing.T) {
		assert.NoError(t, auditLogStreamConfigError("acme", nil, nil))
	})

	t.Run("404 names the enterprise endpoint", func(t *testing.T) {
		inner := ghErrorResponse(http.StatusNotFound)
		err := auditLogStreamConfigError("acme", nil, inner)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), enterprisePath)
		assert.Contains(t, err.Error(), `"acme"`)
		assert.ErrorIs(t, err, inner)
	})

	t.Run("404 carried by the response only", func(t *testing.T) {
		resp := &github.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}
		err := auditLogStreamConfigError("acme", resp, errors.New("unexpected end of JSON input"))
		assert.Contains(t, err.Error(), enterprisePath)
	})

	t.Run("403 reports access, not a missing endpoint", func(t *testing.T) {
		inner := ghErrorResponse(http.StatusForbidden)
		err := auditLogStreamConfigError("acme", nil, inner)
		assert.Contains(t, err.Error(), "access denied")
		assert.NotContains(t, err.Error(), enterprisePath)
		assert.ErrorIs(t, err, inner)
	})

	t.Run("transport error is not classified as a missing endpoint", func(t *testing.T) {
		inner := errors.New("dial tcp 140.82.121.6:443: connect: connection refused")
		err := auditLogStreamConfigError("acme", nil, inner)
		assert.NotContains(t, err.Error(), enterprisePath)
		assert.NotContains(t, err.Error(), "access denied")
		assert.Contains(t, err.Error(), "connection refused")
		assert.ErrorIs(t, err, inner)
	})

	t.Run("server error is not classified as a missing endpoint", func(t *testing.T) {
		inner := ghErrorResponse(http.StatusInternalServerError)
		err := auditLogStreamConfigError("acme", nil, inner)
		assert.NotContains(t, err.Error(), enterprisePath)
		assert.ErrorIs(t, err, inner)
	})
}

func TestAuditLogStreamDecode(t *testing.T) {
	body := `{
		"id": 42,
		"stream_type": "Splunk",
		"enabled": false,
		"paused_at": "2026-04-01T10:00:00Z",
		"created_at": "2026-03-01T09:00:00Z",
		"updated_at": "2026-04-02T11:30:00Z"
	}`

	var stream ghAuditLogStream
	require.NoError(t, json.Unmarshal([]byte(body), &stream))

	assert.Equal(t, int64(42), stream.ID)
	assert.Equal(t, "Splunk", stream.StreamType)
	require.NotNil(t, stream.Enabled)
	assert.False(t, *stream.Enabled)
	require.NotNil(t, stream.PausedAt)
	assert.Equal(t, time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC), stream.PausedAt.UTC())
	require.NotNil(t, stream.CreatedAt)
	assert.Equal(t, time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC), stream.CreatedAt.UTC())
	require.NotNil(t, stream.UpdatedAt)
	assert.Equal(t, time.Date(2026, 4, 2, 11, 30, 0, 0, time.UTC), stream.UpdatedAt.UTC())
}

func TestAuditLogStreamDecodeOmittedFields(t *testing.T) {
	var stream ghAuditLogStream
	require.NoError(t, json.Unmarshal([]byte(`{"id": 7, "stream_type": "Datadog"}`), &stream))

	assert.Nil(t, stream.Enabled)
	assert.Nil(t, stream.PausedAt)
	assert.Nil(t, stream.CreatedAt)
	assert.Nil(t, stream.UpdatedAt)
}
