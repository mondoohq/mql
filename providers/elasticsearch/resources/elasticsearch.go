// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/elasticsearch/connection"
)

func intToStr(i int64) string {
	return strconv.FormatInt(i, 10)
}

func (r *mqlElasticsearch) id() (string, error) {
	return "elasticsearch", nil
}

func esConnection(runtime *plugin.Runtime) *connection.ElasticsearchConnection {
	return runtime.Connection.(*connection.ElasticsearchConnection)
}

// epochMillisToTime converts an Elasticsearch epoch-millisecond timestamp to a
// time.Time. A zero or negative value yields the zero time.
func epochMillisToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// toStringSlice converts a decoded JSON string array to []any for llx.
func toStringSlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// refusal classifies a 401 or 403 from the cluster: a 401 is a credential the
// cluster did not accept, a 403 a missing privilege, named by permissions. Any
// other error is returned unchanged.
func refusal(err error, permissions ...string) error {
	var pe *connection.PermissionError
	if !errors.As(err, &pe) {
		return err
	}
	if pe.StatusCode == http.StatusUnauthorized {
		return llx.Unauthenticated(err)
	}
	return llx.Forbidden(err, llx.WithPermissions(permissions...))
}

// refusedList is what a list accessor returns for a failed request. v13 read
// a 401 or 403 as an empty list, which let a check over the list pass on a
// cluster the scanner could not read; with StructuredErrors it is an error
// naming the privilege the scanner lacks (ADR 046).
func refusedList(err error, permissions ...string) ([]any, error) {
	if !connection.IsPermissionError(err) {
		return nil, err
	}
	if !plugin.StructuredErrors() {
		return []any{}, nil
	}
	return nil, refusal(err, permissions...)
}
