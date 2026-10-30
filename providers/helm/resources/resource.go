// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"gopkg.in/yaml.v3"
)

// yamlDocSeparator matches a YAML document separator: `---` alone on a line
// (optionally with trailing whitespace), at column 0.
var yamlDocSeparator = regexp.MustCompile(`(?m)^---[ \t]*$`)

// splitYAMLDocuments splits a multi-document YAML stream on real document
// separators only. The previous strings.Split(content, "---") split on ANY
// occurrence of "---" — including inside a string value, an indented block
// scalar (e.g. a ConfigMap data payload), or a comment — which silently
// corrupted or dropped valid Kubernetes resources.
func splitYAMLDocuments(content string) []string {
	return yamlDocSeparator.Split(content, -1)
}

type mqlHelmResourceInternal struct {
	cacheTemplateKey string
	// ownerChart/ownerTemplate wire the resource back to the helm.template it
	// was rendered from. Exactly one is set by the caller of parseK8sResources:
	// ownerTemplate when the resource comes from helm.template.resources (the
	// template is already in hand), ownerChart when it comes from the chart-wide
	// helm.chart.resources/hooks path (the template is resolved lazily through
	// the chart so template() returns the fully-populated resource rather than a
	// bare-__id husk). Both stay nil for crds/, which have no backing template.
	ownerChart    *mqlHelmChart
	ownerTemplate *mqlHelmTemplate
}

// parseK8sResources parses rendered YAML content into Kubernetes resource
// objects. isCRD marks resources that came from the chart's crds/ directory
// (helm installs those ahead of templating) rather than from a template.
func parseK8sResources(runtime *plugin.Runtime, templateKey string, content string, isCRD bool) ([]any, error) {
	var mqlResources []any

	// Split on YAML document separators only (not on `---` inside values)
	docs := splitYAMLDocuments(content)
	docIndex := 0
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		var obj map[string]any
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			// A document that fails to parse would silently vanish from the
			// audit (a policy could then pass vacuously); surface it.
			log.Warn().Err(err).Str("templateKey", templateKey).Msg("helm: skipping rendered document that failed to parse")
			continue
		}

		// Skip empty or non-K8s YAML docs
		kind, _ := obj["kind"].(string)
		if kind == "" {
			continue
		}

		apiVersion, _ := obj["apiVersion"].(string)
		name := ""
		namespace := ""
		labels := map[string]any{}
		annotations := map[string]any{}

		if metadata, ok := obj["metadata"].(map[string]any); ok {
			name, _ = metadata["name"].(string)
			namespace, _ = metadata["namespace"].(string)
			if l, ok := metadata["labels"].(map[string]any); ok {
				labels = l
			}
			if a, ok := metadata["annotations"].(map[string]any); ok {
				annotations = a
			}
		}

		labelsStr := scalarStringMap(labels)
		annotationsStr := scalarStringMap(annotations)

		manifest, err := convert.JsonToDict(obj)
		if err != nil {
			log.Warn().Err(err).Str("templateKey", templateKey).Str("kind", kind).Msg("helm: skipping rendered resource that failed to convert")
			continue
		}

		isHook, hookTypes, hookWeight, hookDeletePolicies := parseHookAnnotations(annotations)

		// Use templateKey (chartName/templateName), namespace, kind, name, and docIndex for uniqueness
		id := "helm.resource:" + templateKey + ":" + kind + ":" + namespace + ":" + name + ":" + strconv.Itoa(docIndex)
		// Store the template ID using ":" separator to match the template __id format (helm.template:chartName:templateName)
		templateID := strings.Replace(templateKey, "/", ":", 1)
		res, err := CreateResource(runtime, "helm.resource", map[string]*llx.RawData{
			"__id":               llx.StringData(id),
			"apiVersion":         llx.StringData(apiVersion),
			"kind":               llx.StringData(kind),
			"name":               llx.StringData(name),
			"namespace":          llx.StringData(namespace),
			"labels":             llx.MapData(labelsStr, types.String),
			"annotations":        llx.MapData(annotationsStr, types.String),
			"manifest":           llx.DictData(manifest),
			"isHook":             llx.BoolData(isHook),
			"hookTypes":          llx.ArrayData(hookTypes, types.String),
			"hookWeight":         llx.IntData(hookWeight),
			"hookDeletePolicies": llx.ArrayData(hookDeletePolicies, types.String),
			"isCRD":              llx.BoolData(isCRD),
		})
		if err != nil {
			continue
		}
		mqlResource := res.(*mqlHelmResource)
		mqlResource.cacheTemplateKey = templateID
		mqlResources = append(mqlResources, mqlResource)
		docIndex++
	}

	return mqlResources, nil
}

// parseHookAnnotations reads Helm's hook annotations off a rendered
// resource's metadata.annotations: helm.sh/hook (lifecycle phases),
// helm.sh/hook-weight (ordering), and helm.sh/hook-delete-policy. A
// resource is a hook iff it carries the helm.sh/hook annotation.
func parseHookAnnotations(annotations map[string]any) (isHook bool, hookTypes []any, hookWeight int64, hookDeletePolicies []any) {
	hookTypes = []any{}
	hookDeletePolicies = []any{}

	hookVal, _ := annotations["helm.sh/hook"].(string)
	if strings.TrimSpace(hookVal) == "" {
		return false, hookTypes, 0, hookDeletePolicies
	}
	isHook = true
	hookTypes = splitCSV(hookVal)

	if w, ok := annotations["helm.sh/hook-weight"].(string); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(w)); err == nil {
			hookWeight = int64(n)
		}
	}
	if dp, ok := annotations["helm.sh/hook-delete-policy"].(string); ok {
		hookDeletePolicies = splitCSV(dp)
	}
	return isHook, hookTypes, hookWeight, hookDeletePolicies
}

// scalarStringMap renders a rendered-manifest labels/annotations block as a
// string->string map. Kubernetes label and annotation values are always
// strings, but a rendered template can emit an unquoted scalar (e.g.
// `version: 1.0` unmarshals to a float, `enabled: true` to a bool). Formatting
// those to their string form — rather than dropping them, as the previous
// string-only type assertion did — keeps helm.resource.labels/annotations
// consistent with the same keys visible under helm.resource.manifest.
// Non-scalar values (nested maps/slices) can't be valid label values and are
// skipped.
func scalarStringMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if s, ok := scalarToString(v); ok {
			out[k] = s
		}
	}
	return out
}

// scalarToString formats a YAML scalar (as produced by yaml.v3 into any) to
// the string Kubernetes would store. It reports false for non-scalar or nil
// values so the caller can skip them.
func scalarToString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	default:
		return "", false
	}
}

// splitCSV splits a comma-separated annotation value into trimmed,
// non-empty entries.
func splitCSV(s string) []any {
	parts := strings.Split(s, ",")
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// template links a rendered resource back to the helm.template it came from.
//
// It deliberately does NOT reconstruct the template from its __id via
// NewResource: helm.template has no init, so NewResource with only "__id"
// would fabricate a husk whose name/raw/requiresCluster are unset — and since
// that husk's __id is byte-identical to the real template's, it would poison
// the shared resource cache and make helm.chart.templates return husks too.
// Instead we return the already-materialized template: directly when the
// resource was parsed from a template, or by resolving it through the owning
// chart's templates() (which builds the real, fully-populated instances).
func (r *mqlHelmResource) template() (*mqlHelmTemplate, error) {
	if r.ownerTemplate != nil {
		return r.ownerTemplate, nil
	}
	if r.ownerChart != nil {
		templates, err := r.ownerChart.templates()
		if err != nil {
			log.Warn().Err(err).Str("templateKey", r.cacheTemplateKey).Msg("failed to resolve helm template for resource")
			r.Template.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		// cacheTemplateKey already uses the ":" separator of the template __id.
		want := "helm.template:" + r.cacheTemplateKey
		for _, t := range templates {
			if mqlT, ok := t.(*mqlHelmTemplate); ok && mqlT.__id == want {
				return mqlT, nil
			}
		}
	}
	// No backing template (e.g. a resource from crds/, or a resource created
	// without an owner). Report null rather than a husk.
	r.Template.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}
