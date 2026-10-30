// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// DigitalOcean Functions are backed by Apache OpenWhisk. godo lists
// namespaces and triggers but has no endpoint for the deployed functions
// (actions) themselves — those live behind each namespace's OpenWhisk
// API host. We reach them with the namespace's UUID/Key as HTTP Basic
// credentials, the same way `doctl serverless` does.

// owAction is the summary an OpenWhisk `list actions` call returns. The
// list omits the full exec block, so the runtime kind and web-export
// posture come from annotations rather than dedicated fields.
type owAction struct {
	Namespace   string       `json:"namespace"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Updated     int64        `json:"updated"`
	Annotations []owKeyValue `json:"annotations"`
	Limits      *owLimits    `json:"limits"`
}

type owKeyValue struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

type owLimits struct {
	Timeout     int `json:"timeout"`
	Memory      int `json:"memory"`
	Logs        int `json:"logs"`
	Concurrency int `json:"concurrency"`
}

func owAnnotation(anns []owKeyValue, key string) (any, bool) {
	for _, a := range anns {
		if a.Key == key {
			return a.Value, true
		}
	}
	return nil, false
}

// owTruthy interprets an OpenWhisk annotation value as a boolean. The
// web-export and require-whisk-auth annotations may arrive as a bool, or
// as a string ("true", "raw", or an auth token), so any non-empty,
// non-false value counts as true.
func owTruthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "" && !strings.EqualFold(t, "false") && !strings.EqualFold(t, "no")
	case nil:
		return false
	default:
		return true
	}
}

// openWhiskWebUrl builds the endpoint a web-exported action is published on.
// OpenWhisk serves web actions at /api/v1/web/<namespace>/<package>/<action>,
// and places actions that are not in a package in the "default" package.
// Actions that are not web-exported have no such endpoint and return "".
func openWhiskWebUrl(apiHost, namespace, pkg, action string, webExported bool) string {
	if !webExported || apiHost == "" || namespace == "" {
		return ""
	}
	if pkg == "" {
		pkg = "default"
	}
	return strings.TrimRight(apiHost, "/") + "/api/v1/web/" + namespace + "/" + pkg + "/" + action
}

func owString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// listOpenWhiskActions pages through a namespace's OpenWhisk actions.
func listOpenWhiskActions(ctx context.Context, apiHost, uuid, key string) ([]owAction, error) {
	base := strings.TrimRight(apiHost, "/") + "/api/v1/namespaces/_/actions"
	httpClient := &http.Client{Timeout: 30 * time.Second}

	const perPage = 200
	var all []owAction
	skip := 0
	for {
		url := fmt.Sprintf("%s?limit=%d&skip=%d", base, perPage, skip)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(uuid, key)
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("openwhisk list actions failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var page []owAction
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < perPage {
			break
		}
		skip += perPage
	}
	return all, nil
}

func (r *mqlDigitaloceanFunctionNamespace) accessKeys() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	keys, _, err := client.Functions.ListAccessKeys(context.Background(), r.Namespace.Data)
	if err != nil {
		if isDoNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	all := make([]any, 0, len(keys))
	for _, k := range keys {
		id, err := resourceID("digitalocean.function.accessKey", r.Namespace.Data, k.ID)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.function.accessKey", map[string]*llx.RawData{
			"__id":          llx.StringData(id),
			"namespaceUuid": llx.StringData(r.Uuid.Data),
			"id":            llx.StringData(k.ID),
			"name":          llx.StringData(k.Name),
			"createdAt":     llx.TimeDataPtr(timePtr(k.CreatedAt)),
			"updatedAt":     llx.TimeDataPtr(timePtr(k.UpdatedAt)),
			"lastUsedAt":    llx.TimeDataPtr(timePtr(k.LastUsedAt)),
			"expiresAt":     llx.TimeDataPtr(timePtr(k.ExpiresAt)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanFunctionNamespace) functions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	ctx := context.Background()

	// The namespace list does not include the API key needed to call the
	// OpenWhisk host, so fetch the namespace directly to obtain it. The
	// namespace name is the identifier here: the list endpoint returns an
	// empty uuid, and requesting an empty id resolves to the collection
	// endpoint, which decodes to no namespace at all.
	ns, _, err := client.Functions.GetNamespace(ctx, r.Namespace.Data)
	if err != nil {
		if isDoNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	if ns == nil {
		return []any{}, nil
	}
	if ns.ApiHost == "" || ns.Key == "" {
		// Without an API host and key we can't reach the OpenWhisk host.
		return []any{}, nil
	}

	actions, err := listOpenWhiskActions(ctx, ns.ApiHost, ns.UUID, ns.Key)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(actions))
	for _, a := range actions {
		// The action's namespace field is "<namespace>" or
		// "<namespace>/<package>".
		nsName, pkg := a.Namespace, ""
		if idx := strings.IndexByte(a.Namespace, '/'); idx >= 0 {
			nsName, pkg = a.Namespace[:idx], a.Namespace[idx+1:]
		}

		runtime := ""
		if v, ok := owAnnotation(a.Annotations, "exec"); ok {
			runtime = owString(v)
		}
		webExported := false
		if v, ok := owAnnotation(a.Annotations, "web-export"); ok {
			webExported = owTruthy(v)
		}
		requiresApiKey := false
		if v, ok := owAnnotation(a.Annotations, "require-whisk-auth"); ok {
			requiresApiKey = owTruthy(v)
		}

		var timeoutMs, memoryMb, logSizeMb, concurrency int64
		if a.Limits != nil {
			timeoutMs = int64(a.Limits.Timeout)
			memoryMb = int64(a.Limits.Memory)
			logSizeMb = int64(a.Limits.Logs)
			concurrency = int64(a.Limits.Concurrency)
		}

		var updatedAt *time.Time
		if a.Updated > 0 {
			t := time.UnixMilli(a.Updated)
			updatedAt = &t
		}

		id, err := resourceID("digitalocean.function.action", r.Namespace.Data, pkg, a.Name)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.function.action", map[string]*llx.RawData{
			"__id": llx.StringData(id),
			// The namespace listing leaves uuid empty; the single-namespace
			// read above is where the real one comes from.
			"namespaceUuid":  llx.StringData(ns.UUID),
			"name":           llx.StringData(a.Name),
			"package":        llx.StringData(pkg),
			"version":        llx.StringData(a.Version),
			"runtime":        llx.StringData(runtime),
			"webExported":    llx.BoolData(webExported),
			"requiresApiKey": llx.BoolData(requiresApiKey),
			"webUrl":         llx.StringData(openWhiskWebUrl(ns.ApiHost, nsName, pkg, a.Name, webExported)),
			"timeoutMs":      llx.IntData(timeoutMs),
			"memoryMb":       llx.IntData(memoryMb),
			"logSizeMb":      llx.IntData(logSizeMb),
			"concurrency":    llx.IntData(concurrency),
			"updatedAt":      llx.TimeDataPtr(updatedAt),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}
