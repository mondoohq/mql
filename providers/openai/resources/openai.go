// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"time"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/openai/connection"
)

func openaiConn(runtime *plugin.Runtime) *connection.OpenaiConnection {
	return runtime.Connection.(*connection.OpenaiConnection)
}

func unixToTime(ts int64) time.Time {
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

// unixToNullableTime converts a Unix timestamp to a time pointer, returning nil
// for a zero timestamp. The OpenAI API surfaces absent times as 0; wrapping the
// result through llx.TimeDataPtr then emits null instead of a year-1 timestamp.
func unixToNullableTime(ts int64) *time.Time {
	if ts == 0 {
		return nil
	}
	t := unixToTime(ts)
	return &t
}

// emptyToNil maps an empty string to nil so an absent enum reaches MQL as null
// rather than as "". The OpenAI API omits these fields entirely when unset, and
// an empty string would read as a real value the project does not have.
func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// stringArg reads a non-empty string init argument. It reports false when the
// argument is absent, null, of another type, or empty, which are the cases an
// init has to hand back to the runtime rather than turn into a lookup.
func stringArg(args map[string]*llx.RawData, name string) (string, bool) {
	raw, ok := args[name]
	if !ok || raw == nil || raw.Value == nil {
		return "", false
	}
	s, ok := raw.Value.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// dataPlaneClient returns the project-scoped client used for data-plane
// collections (models, files, vector stores, fine-tuning). It returns a
// descriptive error when the connection was built from an admin key (which
// cannot read data-plane resources), and (nil, nil) when no credentials exist.
func dataPlaneClient(conn *connection.OpenaiConnection, resource string) (*openai.Client, error) {
	if c := conn.Client(); c != nil {
		return c, nil
	}
	if conn.AdminClient() != nil {
		return nil, fmt.Errorf("%s requires a project API key (sk-proj-...); the configured admin key cannot read data-plane resources", resource)
	}
	return nil, nil
}

// adminPlaneClient returns the admin client used for organization collections
// (users, invites, audit logs, projects). It returns a descriptive error when
// the connection was built from a project key (which cannot read organization
// resources), and (nil, nil) when no credentials exist.
func adminPlaneClient(conn *connection.OpenaiConnection, resource string) (*openai.Client, error) {
	if c := conn.AdminClient(); c != nil {
		return c, nil
	}
	if conn.Client() != nil {
		return nil, fmt.Errorf("%s requires an admin API key (sk-admin-...); the configured project key cannot read organization resources", resource)
	}
	return nil, nil
}

func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *openai.Error
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 401 || apiErr.StatusCode == 403
	}
	return false
}

func (r *mqlOpenai) id() (string, error) {
	return "openai", nil
}

func (r *mqlOpenai) organization() (string, error) {
	return openaiConn(r.MqlRuntime).Organization(), nil
}

func (r *mqlOpenai) projectId() (string, error) {
	return openaiConn(r.MqlRuntime).Project(), nil
}
