// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/bicep/connection"
	"go.mondoo.com/mql/types"
)

// stampOnce guards the Internal fields: CreateResource returns the CACHED
// instance for an id already in the runtime cache, and the same template id is
// reached concurrently from bicep.template, bicep.templates, and a nested
// resource's linkedTemplate. It also serves as the lazy-populate gate for a
// resource reconstructed across the gRPC boundary, where the Internal fields
// come back zeroed.
type mqlBicepTemplateInternal struct {
	stampOnce   sync.Once
	armTemplate *connection.ARMTemplate
	cachePath   string
}

func newMqlBicepTemplate(runtime *plugin.Runtime, filePath string, tmpl *connection.ARMTemplate) (*mqlBicepTemplate, error) {
	res, err := CreateResource(runtime, "bicep.template", map[string]*llx.RawData{
		"__id": llx.StringData("bicep.template:" + filePath),
	})
	if err != nil {
		return nil, err
	}
	mqlT := res.(*mqlBicepTemplate)
	mqlT.stampOnce.Do(func() {
		mqlT.armTemplate = tmpl
		mqlT.cachePath = filePath
	})
	return mqlT, nil
}

// id falls back to the connection's path when the Internal struct hasn't
// been populated yet (e.g., the resource came back via StoreData and no
// accessor has run getARMTemplate). If neither source yields a path we
// surface an error rather than returning a "bicep.template:" sentinel —
// a non-unique id would cause every such reconstruction to collide on
// the same cache entry.
func (t *mqlBicepTemplate) id() (string, error) {
	t.ensureStamped()
	path := t.cachePath
	if path == "" {
		if conn, ok := t.MqlRuntime.Connection.(*connection.BicepConnection); ok {
			path = conn.Path()
		}
	}
	if path == "" {
		return "", errors.New("bicep.template: no path available to derive a stable cache id")
	}
	return "bicep.template:" + path, nil
}

// ensureStamped populates the Internal fields exactly once, either from the
// creator's arguments or, when the resource was reconstructed via StoreData
// across gRPC with its Internal fields zeroed, by re-fetching from the
// connection. Running both through the same sync.Once keeps concurrent
// accessors on a cached instance from racing each other.
func (t *mqlBicepTemplate) ensureStamped() {
	t.stampOnce.Do(func() {
		// Guard the assertion: on a non-Bicep runtime (e.g. recording/replay)
		// there's nothing to re-fetch — leave the fields empty rather than
		// panicking, matching the comma-ok cast in id().
		conn, ok := t.MqlRuntime.Connection.(*connection.BicepConnection)
		if !ok {
			return
		}
		if tmpl := conn.ARMTemplate(); tmpl != nil {
			t.armTemplate = tmpl
			t.cachePath = conn.ARMTemplatePath()
		}
	})
}

func (t *mqlBicepTemplate) getARMTemplate() *connection.ARMTemplate {
	t.ensureStamped()
	return t.armTemplate
}

func (t *mqlBicepTemplate) schema() (string, error) {
	tmpl := t.getARMTemplate()
	if tmpl == nil {
		return "", nil
	}
	return tmpl.Schema, nil
}

func (t *mqlBicepTemplate) contentVersion() (string, error) {
	tmpl := t.getARMTemplate()
	if tmpl == nil {
		return "", nil
	}
	return tmpl.ContentVersion, nil
}

// parameters/variables/outputs return an empty slice (not nil) when the
// ARM template is unavailable. The connection layer already distinguishes
// "no ARM template at all" by returning a nil bicep.template resource, so
// an empty list here means "template present, none declared". Entries are
// emitted in a stable, name-sorted order so output and tests are
// deterministic.
func (t *mqlBicepTemplate) parameters() ([]any, error) {
	tmpl := t.getARMTemplate()
	if tmpl == nil {
		return []any{}, nil
	}
	mqlParams := make([]any, 0, len(tmpl.Parameters))
	for _, name := range sortedKeys(tmpl.Parameters) {
		mqlP, err := t.newMqlBicepTemplateParameter(name, tmpl.Parameters[name])
		if err != nil {
			return nil, err
		}
		mqlParams = append(mqlParams, mqlP)
	}
	return mqlParams, nil
}

func (t *mqlBicepTemplate) variables() ([]any, error) {
	tmpl := t.getARMTemplate()
	if tmpl == nil {
		return []any{}, nil
	}
	mqlVars := make([]any, 0, len(tmpl.Variables))
	for _, name := range sortedKeys(tmpl.Variables) {
		mqlV, err := t.newMqlBicepTemplateVariable(name, tmpl.Variables[name])
		if err != nil {
			return nil, err
		}
		mqlVars = append(mqlVars, mqlV)
	}
	return mqlVars, nil
}

func (t *mqlBicepTemplate) outputs() ([]any, error) {
	tmpl := t.getARMTemplate()
	if tmpl == nil {
		return []any{}, nil
	}
	mqlOutputs := make([]any, 0, len(tmpl.Outputs))
	for _, name := range sortedKeys(tmpl.Outputs) {
		mqlO, err := t.newMqlBicepTemplateOutput(name, tmpl.Outputs[name])
		if err != nil {
			return nil, err
		}
		mqlOutputs = append(mqlOutputs, mqlO)
	}
	return mqlOutputs, nil
}

// armParameter mirrors the shape of an ARM template parameter declaration.
type armParameter struct {
	Type          string            `json:"type"`
	DefaultValue  json.RawMessage   `json:"defaultValue"`
	AllowedValues []json.RawMessage `json:"allowedValues"`
	Metadata      json.RawMessage   `json:"metadata"`
}

func (t *mqlBicepTemplate) newMqlBicepTemplateParameter(name string, raw json.RawMessage) (*mqlBicepTemplateParameter, error) {
	var p armParameter
	if err := json.Unmarshal(raw, &p); err != nil {
		log.Warn().Err(err).Str("name", name).Msg("failed to unmarshal ARM template parameter")
	}

	var defaultValue any
	if len(p.DefaultValue) > 0 {
		defaultValue = rawMessageToDict(p.DefaultValue)
	}

	allowedValues := make([]any, 0, len(p.AllowedValues))
	for _, av := range p.AllowedValues {
		allowedValues = append(allowedValues, rawMessageToDict(av))
	}

	var metadata any
	if len(p.Metadata) > 0 {
		metadata = rawMessageToDict(p.Metadata)
	}

	secure := p.Type == "securestring" || p.Type == "secureObject"

	id := t.cachePath + "/parameters/" + name
	res, err := CreateResource(t.MqlRuntime, "bicep.template.parameter", map[string]*llx.RawData{
		"__id":          llx.StringData(id),
		"name":          llx.StringData(name),
		"type":          llx.StringData(p.Type),
		"defaultValue":  llx.DictData(defaultValue),
		"allowedValues": llx.ArrayData(allowedValues, types.Dict),
		"secure":        llx.BoolData(secure),
		"metadata":      llx.DictData(metadata),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBicepTemplateParameter), nil
}

func (t *mqlBicepTemplate) newMqlBicepTemplateVariable(name string, raw json.RawMessage) (*mqlBicepTemplateVariable, error) {
	id := t.cachePath + "/variables/" + name
	res, err := CreateResource(t.MqlRuntime, "bicep.template.variable", map[string]*llx.RawData{
		"__id":  llx.StringData(id),
		"name":  llx.StringData(name),
		"value": llx.DictData(rawMessageToDict(raw)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBicepTemplateVariable), nil
}

// armOutput mirrors the shape of an ARM template output declaration.
type armOutput struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

func (t *mqlBicepTemplate) newMqlBicepTemplateOutput(name string, raw json.RawMessage) (*mqlBicepTemplateOutput, error) {
	var o armOutput
	if err := json.Unmarshal(raw, &o); err != nil {
		log.Warn().Err(err).Str("name", name).Msg("failed to unmarshal ARM template output")
	}

	var value any
	if len(o.Value) > 0 {
		value = rawMessageToDict(o.Value)
	}

	id := t.cachePath + "/outputs/" + name
	res, err := CreateResource(t.MqlRuntime, "bicep.template.output", map[string]*llx.RawData{
		"__id":  llx.StringData(id),
		"name":  llx.StringData(name),
		"type":  llx.StringData(o.Type),
		"value": llx.DictData(value),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBicepTemplateOutput), nil
}

// resources materializes the template's top-level resources. Like its
// parameters/variables/outputs siblings it returns an empty slice (not nil)
// when the template is unavailable or declares none.
func (t *mqlBicepTemplate) resources() ([]any, error) {
	tmpl := t.getARMTemplate()
	if tmpl == nil {
		return []any{}, nil
	}
	list := tmpl.ResourceList()
	mqlResources := make([]any, 0, len(list))
	for i, entry := range list {
		var obj map[string]any
		if err := json.Unmarshal(entry.Raw, &obj); err != nil {
			log.Warn().Err(err).Int("index", i).Msg("failed to unmarshal ARM template resource")
			continue
		}
		// A symbolic-name (languageVersion 2.0) template names each resource,
		// so the key is its identity; the classic array form has only position.
		key := entry.SymbolicName
		if key == "" {
			key = strconv.Itoa(i)
		}
		mqlR, err := newMqlBicepTemplateResource(t.MqlRuntime, t.cachePath, key, obj)
		if err != nil {
			log.Warn().Err(err).Int("index", i).Msg("failed to create ARM template resource")
			continue
		}
		mqlResources = append(mqlResources, mqlR)
	}
	return mqlResources, nil
}

// mqlBicepTemplateResourceInternal caches what the lazy linkedTemplate()
// accessor needs: the inline nested ARM template parsed from a
// `Microsoft.Resources/deployments` resource's `properties.template`, plus the
// synthetic id used to build a non-colliding `bicep.template` for it. Both are
// nil/empty for resources that carry no inline nested template (ordinary
// resources, or deployments that use an external `templateLink`).
// It also caches the resource's own `resources` array so the nested-children
// accessor can materialize them, and the owning template's path so each child
// keeps the same id shape as its parent. stampOnce guards every field:
// CreateResource returns the CACHED instance for an id already in the runtime
// cache, so an unguarded stamp races with a concurrent reader of the same
// instance.
type mqlBicepTemplateResourceInternal struct {
	stampOnce    sync.Once
	linkedTmpl   *connection.ARMTemplate
	linkedTmplID string
	nestedRaw    []any
	templatePath string
}

// newMqlBicepTemplateResource builds one bicep.template.resource. `key`
// identifies the resource within its parent collection: the symbolic name for
// a languageVersion 2.0 template, the positional index for the classic array
// form, and `<parentKey>/<index>` for a nested child.
func newMqlBicepTemplateResource(runtime *plugin.Runtime, templatePath string, key string, obj map[string]any) (*mqlBicepTemplateResource, error) {
	typ, _ := obj["type"].(string)
	apiVersion, _ := obj["apiVersion"].(string)
	name, _ := obj["name"].(string)
	location, _ := obj["location"].(string)
	condition := armCondition(obj["condition"])

	var dependsOn []any
	if deps, ok := obj["dependsOn"].([]any); ok {
		for _, d := range deps {
			dependsOn = append(dependsOn, armDependency(d))
		}
	}

	tags := map[string]any{}
	if raw, ok := obj["tags"].(map[string]any); ok {
		for k, v := range raw {
			if sv, ok := v.(string); ok {
				tags[k] = sv
				continue
			}
			// ARM tag values are strings, but a template may put an expression
			// object or number there; render it rather than dropping the tag.
			tags[k] = armDependency(v)
		}
	}

	// ARM `copy` iteration block: { name, count, mode, batchSize }. count may
	// be an int or an ARM expression string, so it's surfaced as a dict.
	var copyName, copyMode string
	var copyCount any
	var copyBatchSize *int64
	if copy, ok := obj["copy"].(map[string]any); ok {
		copyName, _ = copy["name"].(string)
		copyMode, _ = copy["mode"].(string)
		// count is already a decoded JSON value (a float64 for a literal int
		// or a string for an ARM expression); surface it as-is in the dict.
		copyCount = copy["count"]
		if bs, ok := copy["batchSize"].(float64); ok {
			v := int64(bs)
			copyBatchSize = &v
		}
	}

	// Convert the manifest once, then peel `properties` out of the
	// already-converted dict. JsonToDict walks every nested value, so a
	// separate pass over obj["properties"] was redoing the same work.
	manifest, err := convert.JsonToDict(obj)
	if err != nil {
		log.Warn().Err(err).Str("name", name).Msg("failed to convert ARM template resource manifest")
	}
	var properties any
	if manifest != nil {
		properties = manifest["properties"]
	}

	id := "bicep.template.resource:" + templatePath + ":" + typ + ":" + name + ":" + key

	// Extract an inline nested deployment template, if any. Only a
	// `Microsoft.Resources/deployments` resource whose `properties.template`
	// is an inline ARM template is resolvable offline; an external
	// `templateLink` is not.
	linkedTmpl := extractInlineTemplate(typ, obj)

	res, err := CreateResource(runtime, "bicep.template.resource", map[string]*llx.RawData{
		"__id":          llx.StringData(id),
		"type":          llx.StringData(typ),
		"apiVersion":    llx.StringData(apiVersion),
		"name":          llx.StringData(name),
		"location":      llx.StringData(location),
		"condition":     llx.StringData(condition),
		"copyName":      llx.StringData(copyName),
		"copyCount":     llx.DictData(copyCount),
		"copyMode":      llx.StringData(copyMode),
		"copyBatchSize": llx.IntDataPtr(copyBatchSize),
		"properties":    llx.DictData(properties),
		"tags":          llx.MapData(tags, types.String),
		"dependsOn":     llx.ArrayData(dependsOn, types.String),
		"manifest":      llx.DictData(manifest),
	})
	if err != nil {
		return nil, err
	}
	// A classic ARM resource may carry its own `resources` array of children:
	// Microsoft.Web/sites to config/web, Microsoft.Sql/servers to
	// auditingSettings and firewallRules, Microsoft.Storage/storageAccounts to
	// blobServices. Cache it for the nested accessor to materialize.
	nestedRaw, _ := obj["resources"].([]any)

	mqlRes := res.(*mqlBicepTemplateResource)
	mqlRes.stampOnce.Do(func() {
		mqlRes.linkedTmpl = linkedTmpl
		mqlRes.linkedTmplID = id + "/linkedTemplate"
		mqlRes.nestedRaw = nestedRaw
		mqlRes.templatePath = templatePath
	})
	return mqlRes, nil
}

// armCondition renders an ARM `condition`. The field is boolean-valued and is
// usually written as an expression string, but a literal true/false is legal
// and appears in generated templates. Reporting a present-but-non-string
// condition as "" would read as "unconditional" — the exact opposite of what
// `"condition": false` means.
func armCondition(v any) string {
	switch c := v.(type) {
	case nil:
		return ""
	case string:
		return c
	case bool:
		return strconv.FormatBool(c)
	default:
		return renderARMValue(v)
	}
}

// armDependency renders one `dependsOn` entry. ARM permits an object form
// alongside the usual resourceId expression string, and symbolic-name
// templates use `[reference(...)]` objects; rendering the object to its raw
// JSON text keeps the dependency edge instead of dropping it.
func armDependency(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return renderARMValue(v)
}

// renderARMValue turns a decoded JSON value back into compact JSON text.
func renderARMValue(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		log.Warn().Err(err).Msg("failed to render ARM value as JSON text")
		return ""
	}
	return string(raw)
}

// resources materializes this resource's nested child resources. Each child
// gets a parent-qualified id so children under different parents never collide
// in the cache, and children may declare children of their own.
func (a *mqlBicepTemplateResource) resources() ([]any, error) {
	out := make([]any, 0, len(a.nestedRaw))
	for i, child := range a.nestedRaw {
		obj, ok := child.(map[string]any)
		if !ok {
			log.Warn().Int("index", i).Str("parent", a.Name.Data).Msg("nested ARM resource is not an object")
			continue
		}
		mqlChild, err := newMqlBicepTemplateResource(a.MqlRuntime, a.templatePath, a.childKey(i), obj)
		if err != nil {
			log.Warn().Err(err).Int("index", i).Str("parent", a.Name.Data).Msg("failed to create nested ARM template resource")
			continue
		}
		out = append(out, mqlChild)
	}
	return out, nil
}

// childKey builds the parent-qualified key for the i-th nested child. The
// parent's own id already encodes its type, name, and key, so appending the
// index is enough to stay unique across the whole template.
func (a *mqlBicepTemplateResource) childKey(i int) string {
	return a.__id + "/" + strconv.Itoa(i)
}

// extractInlineTemplate returns the inline nested ARM template carried by a
// `Microsoft.Resources/deployments` resource's `properties.template`, or nil
// for non-deployment resources, external `templateLink` deployments, and
// deployments with no inline template.
func extractInlineTemplate(typ string, obj map[string]any) *connection.ARMTemplate {
	if !strings.EqualFold(typ, "Microsoft.Resources/deployments") {
		return nil
	}
	props, ok := obj["properties"].(map[string]any)
	if !ok {
		return nil
	}
	inline, ok := props["template"].(map[string]any)
	if !ok {
		return nil
	}
	raw, err := json.Marshal(inline)
	if err != nil {
		log.Warn().Err(err).Msg("failed to re-marshal inline nested ARM template")
		return nil
	}
	var tmpl connection.ARMTemplate
	if err := json.Unmarshal(raw, &tmpl); err != nil {
		log.Warn().Err(err).Msg("failed to unmarshal inline nested ARM template")
		return nil
	}
	return &tmpl
}

// linkedTemplate resolves an inline nested deployment template into a
// bicep.template so its parameters/variables/resources/outputs can be
// traversed. It is null for an external templateLink deployment, a
// non-deployment resource, and a deployment with no inline template.
func (a *mqlBicepTemplateResource) linkedTemplate() (*mqlBicepTemplate, error) {
	if a.linkedTmpl == nil {
		a.LinkedTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlBicepTemplate(a.MqlRuntime, a.linkedTmplID, a.linkedTmpl)
}

// sortedKeys returns the keys of a raw-message map in ascending order so
// the materialized parameter/variable/output lists are deterministic.
func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// rawMessageToDict unmarshals a single raw ARM JSON value into a dict-safe
// Go value. Falls back to the raw string when the bytes don't parse as JSON.
func rawMessageToDict(raw json.RawMessage) any {
	var val any
	if err := json.Unmarshal(raw, &val); err != nil {
		return string(raw)
	}
	dict, err := convert.JsonToDict(val)
	if err != nil {
		return val
	}
	return dict
}
