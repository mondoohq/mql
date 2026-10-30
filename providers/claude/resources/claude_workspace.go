// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/claude/connection"
)

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func conn(runtime *plugin.Runtime) *connection.ClaudeConnection {
	return runtime.Connection.(*connection.ClaudeConnection)
}

func requireAdmin(runtime *plugin.Runtime) (*connection.AdminClient, error) {
	c := conn(runtime)
	if c.AdminToken() == "" {
		return nil, fmt.Errorf("admin API key required: set --admin-token or ANTHROPIC_ADMIN_API_KEY")
	}
	return connection.NewAdminClient(c.AdminToken(), c.Host()), nil
}

// identifiedResource is any generated resource carrying a public id field,
// which covers every resource a reference resolves to.
type identifiedResource interface {
	GetId() *plugin.TValue[string]
}

// findByID returns the entry of list carrying the given id. Callers get a typed
// zero value and false when no entry matches.
func findByID[T identifiedResource](list []any, id string) (T, bool) {
	var zero T
	for _, item := range list {
		entry, ok := item.(T)
		if ok && entry.GetId().Data == id {
			return entry, true
		}
	}
	return zero, false
}

// claudeChildren reads one of the lists hanging off the shared claude resource
// through its memoized accessor, so resolving references on every row of a
// result set costs a single list call.
func claudeChildren(runtime *plugin.Runtime, get func(*mqlClaude) *plugin.TValue[[]any]) ([]any, error) {
	res, err := CreateResource(runtime, "claude", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := get(res.(*mqlClaude))
	if list.Error != nil {
		return nil, list.Error
	}
	return list.Data, nil
}

// lookupClaudeChild resolves a reference against one of those lists. An empty
// id resolves to nothing without listing at all.
func lookupClaudeChild[T identifiedResource](runtime *plugin.Runtime, id string, get func(*mqlClaude) *plugin.TValue[[]any]) (T, bool, error) {
	var zero T
	if id == "" {
		return zero, false, nil
	}

	list, err := claudeChildren(runtime, get)
	if err != nil {
		return zero, false, err
	}

	entry, ok := findByID[T](list, id)
	return entry, ok, nil
}

// lookupOrganizationChild resolves a reference against one of the lists hanging
// off the shared claude.organization resource, with the same memoization.
func lookupOrganizationChild[T identifiedResource](runtime *plugin.Runtime, id string, get func(*mqlClaudeOrganization) *plugin.TValue[[]any]) (T, bool, error) {
	var zero T
	if id == "" {
		return zero, false, nil
	}

	res, err := CreateResource(runtime, "claude.organization", map[string]*llx.RawData{})
	if err != nil {
		return zero, false, err
	}
	list := get(res.(*mqlClaudeOrganization))
	if list.Error != nil {
		return zero, false, list.Error
	}

	entry, ok := findByID[T](list.Data, id)
	return entry, ok, nil
}

// toInterfaceMap converts an API string map into the interface map llx expects
// for a map[string]string field.
func toInterfaceMap(m map[string]string) map[string]any {
	res := make(map[string]any, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

// toInterfaceSlice converts an API string slice into the interface slice llx
// expects for a []string field.
func toInterfaceSlice(s []string) []any {
	res := make([]any, len(s))
	for i, v := range s {
		res[i] = v
	}
	return res
}

// rawJSONToDict decodes a raw API JSON fragment into the JSON-native values a
// dict field accepts. An absent fragment decodes to nil, which renders as null.
func rawJSONToDict(raw string) (any, error) {
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var res any
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return nil, err
	}
	return res, nil
}

// parseFamily derives the model family from the model id, because the Models
// API does not return one. The family follows the `claude-` prefix, either
// directly (`claude-sonnet-5`) or after a version in the older scheme
// (`claude-3-5-sonnet-20241022`), so it is the first segment that does not
// start with a digit. Deriving the value instead of matching a fixed list of
// families keeps a newly released one from silently reporting as empty.
func parseFamily(id string) string {
	rest, ok := strings.CutPrefix(id, "claude-")
	if !ok {
		return ""
	}
	for seg := range strings.SplitSeq(rest, "-") {
		if seg == "" || (seg[0] >= '0' && seg[0] <= '9') {
			continue
		}
		return seg
	}
	return ""
}

// claude

func (r *mqlClaude) id() (string, error) {
	return "claude", nil
}

func (r *mqlClaude) host() (string, error) {
	return conn(r.MqlRuntime).Host(), nil
}

func (r *mqlClaude) models() ([]any, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Models.ListAutoPaging(context.Background(), anthropic.ModelListParams{})

	var res []any
	for pager.Next() {
		m := pager.Current()

		mqlModel, err := CreateResource(r.MqlRuntime, "claude.model", map[string]*llx.RawData{
			"__id":                       llx.StringData(m.ID),
			"id":                         llx.StringData(m.ID),
			"displayName":                llx.StringData(m.DisplayName),
			"vendor":                     llx.StringData("Anthropic"),
			"family":                     llx.StringData(parseFamily(m.ID)),
			"type":                       llx.StringData("model"),
			"createdAt":                  llx.TimeData(m.CreatedAt),
			"maxInputTokens":             llx.IntData(m.MaxInputTokens),
			"maxTokens":                  llx.IntData(m.MaxTokens),
			"batchSupported":             llx.BoolData(m.Capabilities.Batch.Supported),
			"citationsSupported":         llx.BoolData(m.Capabilities.Citations.Supported),
			"codeExecutionSupported":     llx.BoolData(m.Capabilities.CodeExecution.Supported),
			"imageInputSupported":        llx.BoolData(m.Capabilities.ImageInput.Supported),
			"pdfInputSupported":          llx.BoolData(m.Capabilities.PDFInput.Supported),
			"structuredOutputsSupported": llx.BoolData(m.Capabilities.StructuredOutputs.Supported),
			"thinkingSupported":          llx.BoolData(m.Capabilities.Thinking.Supported),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlModel)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing models: %w", err)
	}

	return res, nil
}

func initClaudeModel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	rawID, ok := args["id"]
	if !ok {
		return args, nil, nil
	}

	id, ok := rawID.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	c := conn(runtime)
	client := c.Client()

	m, err := client.Models.Get(context.Background(), id, anthropic.ModelGetParams{})
	if err != nil {
		return nil, nil, fmt.Errorf("getting model %q: %w", id, err)
	}

	args["__id"] = llx.StringData(m.ID)
	args["id"] = llx.StringData(m.ID)
	args["displayName"] = llx.StringData(m.DisplayName)
	args["vendor"] = llx.StringData("Anthropic")
	args["family"] = llx.StringData(parseFamily(m.ID))
	args["type"] = llx.StringData("model")
	args["createdAt"] = llx.TimeData(m.CreatedAt)
	args["maxInputTokens"] = llx.IntData(m.MaxInputTokens)
	args["maxTokens"] = llx.IntData(m.MaxTokens)
	args["batchSupported"] = llx.BoolData(m.Capabilities.Batch.Supported)
	args["citationsSupported"] = llx.BoolData(m.Capabilities.Citations.Supported)
	args["codeExecutionSupported"] = llx.BoolData(m.Capabilities.CodeExecution.Supported)
	args["imageInputSupported"] = llx.BoolData(m.Capabilities.ImageInput.Supported)
	args["pdfInputSupported"] = llx.BoolData(m.Capabilities.PDFInput.Supported)
	args["structuredOutputsSupported"] = llx.BoolData(m.Capabilities.StructuredOutputs.Supported)
	args["thinkingSupported"] = llx.BoolData(m.Capabilities.Thinking.Supported)

	return args, nil, nil
}

func initClaudeOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	admin, err := requireAdmin(runtime)
	if err != nil {
		return nil, nil, err
	}

	org, err := admin.GetOrganization(context.Background())
	if err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData(org.ID)
	args["id"] = llx.StringData(org.ID)
	args["name"] = llx.StringData(org.Name)

	return args, nil, nil
}
