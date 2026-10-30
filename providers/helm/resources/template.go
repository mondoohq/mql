// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"helm.sh/helm/v3/pkg/chart"
)

// helmStubFuncs provides no-op stubs for common Helm/Sprig template functions
// so the Go template AST parser succeeds instead of falling back to regex.
var helmStubFuncs = template.FuncMap{
	// Helm built-ins
	"include":  func(string, ...any) string { return "" },
	"toYaml":   func(any) string { return "" },
	"fromYaml": func(string) map[string]any { return nil },
	"toJson":   func(any) string { return "" },
	"fromJson": func(string) map[string]any { return nil },
	"tpl":      func(string, any) string { return "" },
	"required": func(string, any) any { return nil },
	"lookup":   func(string, string, string, string) map[string]any { return nil },
	// Sprig: strings
	"default":    func(any, ...any) any { return nil },
	"empty":      func(any) bool { return false },
	"coalesce":   func(...any) any { return nil },
	"ternary":    func(any, any, bool) any { return nil },
	"nindent":    func(int, string) string { return "" },
	"indent":     func(int, string) string { return "" },
	"trim":       func(string) string { return "" },
	"trimSuffix": func(string, string) string { return "" },
	"trimPrefix": func(string, string) string { return "" },
	"upper":      func(string) string { return "" },
	"lower":      func(string) string { return "" },
	"title":      func(string) string { return "" },
	"quote":      func(string) string { return "" },
	"replace":    func(string, string, string) string { return "" },
	"contains":   func(string, string) bool { return false },
	"hasPrefix":  func(string, string) bool { return false },
	"hasSuffix":  func(string, string) bool { return false },
	"b64enc":     func(string) string { return "" },
	"b64dec":     func(string) string { return "" },
	// Sprig: collections
	"list":      func(...any) []any { return nil },
	"dict":      func(...any) map[string]any { return nil },
	"get":       func(map[string]any, string) any { return nil },
	"set":       func(map[string]any, string, any) map[string]any { return nil },
	"hasKey":    func(map[string]any, string) bool { return false },
	"keys":      func(map[string]any) []string { return nil },
	"values":    func(map[string]any) []any { return nil },
	"merge":     func(...map[string]any) map[string]any { return nil },
	"splitList": func(string, string) []string { return nil },
	"join":      func(string, []string) string { return "" },
	"sortAlpha": func([]string) []string { return nil },
	// Sprig: type conversion and math
	"int":      func(any) int { return 0 },
	"int64":    func(any) int64 { return 0 },
	"float64":  func(any) float64 { return 0 },
	"toString": func(any) string { return "" },
	"atoi":     func(string) int { return 0 },
	// Sprig: misc
	"fail":            func(string) (string, error) { return "", nil },
	"printf":          func(string, ...any) string { return "" },
	"typeOf":          func(any) string { return "" },
	"kindOf":          func(any) string { return "" },
	"deepEqual":       func(any, any) bool { return false },
	"semverCompare":   func(string, string) bool { return false },
	"sha256sum":       func(string) string { return "" },
	"regexMatch":      func(string, string) bool { return false },
	"regexReplaceAll": func(string, string, string) string { return "" },
}

type mqlHelmTemplateInternal struct {
	chartName       string
	rawContent      string
	renderedContent string
	// renderErr carries the chart-level render failure when the chart's
	// engine.Render() call failed. We attach it to every template the
	// chart produced so a query like `helm.templates[0].rendered`
	// surfaces the failure instead of looking like the template
	// rendered to an empty string.
	renderErr error
}

func newMqlHelmTemplate(runtime *plugin.Runtime, chartName string, t *chart.File, renderedContent string, renderErr error) (*mqlHelmTemplate, error) {
	rawContent := string(t.Data)

	res, err := CreateResource(runtime, "helm.template", map[string]*llx.RawData{
		"__id":            llx.StringData("helm.template:" + chartName + ":" + t.Name),
		"name":            llx.StringData(t.Name),
		"raw":             llx.StringData(rawContent),
		"requiresCluster": llx.BoolData(templateUsesLookup(t.Name, rawContent)),
	})
	if err != nil {
		return nil, err
	}
	mqlT := res.(*mqlHelmTemplate)
	mqlT.chartName = chartName
	mqlT.rawContent = rawContent
	mqlT.renderedContent = renderedContent
	mqlT.renderErr = renderErr
	return mqlT, nil
}

func (t *mqlHelmTemplate) rendered() (string, error) {
	// Surface the chart-level render failure so callers can distinguish
	// "this template legitimately renders to an empty string" from
	// "the whole chart failed to render." The renderedContent is still
	// "" in the failure case, but the error tells the policy author
	// what's going on.
	if t.renderErr != nil {
		return "", t.renderErr
	}
	return t.renderedContent, nil
}

func (t *mqlHelmTemplate) resources() ([]any, error) {
	if t.renderErr != nil {
		return nil, t.renderErr
	}
	if t.renderedContent == "" {
		return []any{}, nil
	}
	templateKey := t.chartName + "/" + t.Name.Data
	resources, err := parseK8sResources(t.MqlRuntime, templateKey, t.renderedContent, false)
	if err != nil {
		return nil, err
	}
	// These resources came straight from this template, so link them back to it
	// directly — helm.resource.template then returns this instance without a
	// chart round-trip.
	for _, r := range resources {
		if res, ok := r.(*mqlHelmResource); ok {
			res.ownerTemplate = t
		}
	}
	return resources, nil
}

func (t *mqlHelmTemplate) directives() ([]any, error) {
	return extractDirectives(t.MqlRuntime, t.Name.Data, t.rawContent)
}

// lookupCallRE matches a call to the Helm `lookup` function inside a
// template action, used as the fallback when the AST parser fails.
var lookupCallRE = regexp.MustCompile(`(^|[\s(|])lookup\s`)

// templateUsesLookup reports whether a template calls the `lookup`
// function, which queries a live cluster at render time. Static analysis
// can't satisfy lookup, so resources gated on it may be missing or
// incomplete in the rendered output.
func templateUsesLookup(name, raw string) bool {
	tmpl, err := template.New(name).Funcs(helmStubFuncs).Parse(raw)
	if err != nil {
		return lookupCallRE.MatchString(raw)
	}
	for _, t := range tmpl.Templates() {
		if t.Tree == nil || t.Tree.Root == nil {
			continue
		}
		if nodeUsesLookup(t.Tree.Root) {
			return true
		}
	}
	return false
}

// nodeUsesLookup walks a template AST looking for an identifier named
// "lookup" in any pipeline command.
func nodeUsesLookup(node parse.Node) bool {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return false
		}
		if slices.ContainsFunc(n.Nodes, nodeUsesLookup) {
			return true
		}
	case *parse.ActionNode:
		return pipeUsesLookup(n.Pipe)
	case *parse.IfNode:
		return pipeUsesLookup(n.Pipe) || nodeUsesLookup(n.List) || nodeUsesLookup(n.ElseList)
	case *parse.RangeNode:
		return pipeUsesLookup(n.Pipe) || nodeUsesLookup(n.List) || nodeUsesLookup(n.ElseList)
	case *parse.WithNode:
		return pipeUsesLookup(n.Pipe) || nodeUsesLookup(n.List) || nodeUsesLookup(n.ElseList)
	}
	return false
}

func pipeUsesLookup(pipe *parse.PipeNode) bool {
	if pipe == nil {
		return false
	}
	for _, cmd := range pipe.Cmds {
		for _, arg := range cmd.Args {
			if id, ok := arg.(*parse.IdentifierNode); ok && id.Ident == "lookup" {
				return true
			}
			if p, ok := arg.(*parse.PipeNode); ok && pipeUsesLookup(p) {
				return true
			}
		}
	}
	return false
}

// extractDirectives parses Go template directives from raw template content.
func extractDirectives(runtime *plugin.Runtime, templateName string, rawContent string) ([]any, error) {
	var mqlDirectives []any

	// Use the Go template parser with Helm/Sprig stub functions so the
	// AST parser succeeds on most real-world charts.
	tmpl, err := template.New(templateName).Funcs(helmStubFuncs).Parse(rawContent)
	if err != nil {
		// If parsing still fails, fall back to regex-like extraction
		return extractDirectivesFallback(runtime, templateName, rawContent)
	}

	for _, t := range tmpl.Templates() {
		if t.Tree == nil || t.Tree.Root == nil {
			continue
		}
		walkNodes(runtime, t.Name(), t.Tree.Root, &mqlDirectives)
	}

	return mqlDirectives, nil
}

func walkNodes(runtime *plugin.Runtime, templateName string, node parse.Node, directives *[]any) {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			walkNodes(runtime, templateName, child, directives)
		}
	case *parse.IfNode:
		addDirective(runtime, templateName, "if", n.String(), n.Line, directives)
		walkNodes(runtime, templateName, n.List, directives)
		walkNodes(runtime, templateName, n.ElseList, directives)
	case *parse.RangeNode:
		addDirective(runtime, templateName, "range", n.String(), n.Line, directives)
		walkNodes(runtime, templateName, n.List, directives)
		walkNodes(runtime, templateName, n.ElseList, directives)
	case *parse.WithNode:
		addDirective(runtime, templateName, "with", n.String(), n.Line, directives)
		walkNodes(runtime, templateName, n.List, directives)
		walkNodes(runtime, templateName, n.ElseList, directives)
	case *parse.TemplateNode:
		addDirective(runtime, templateName, "include", n.Name, n.Line, directives)
	case *parse.ActionNode:
		if n.Pipe != nil {
			pipeStr := n.Pipe.String()
			if strings.Contains(pipeStr, "include ") || strings.Contains(pipeStr, "tpl ") {
				directiveType := "include"
				if strings.Contains(pipeStr, "tpl ") {
					directiveType = "tpl"
				}
				addDirective(runtime, templateName, directiveType, pipeStr, n.Line, directives)
			}
		}
	}
}

func addDirective(runtime *plugin.Runtime, templateName string, directiveType string, expression string, line int, directives *[]any) {
	// Include the current count of directives as an index to avoid __id collisions
	// when multiple directives of the same type appear on the same line.
	idx := len(*directives)
	id := "helm.directive:" + templateName + ":" + directiveType + ":" + strconv.Itoa(line) + ":" + strconv.Itoa(idx)
	res, err := CreateResource(runtime, "helm.directive", map[string]*llx.RawData{
		"__id":       llx.StringData(id),
		"type":       llx.StringData(directiveType),
		"expression": llx.StringData(expression),
		"line":       llx.IntData(int64(line)),
	})
	if err != nil {
		log.Warn().Err(err).Str("template", templateName).Str("type", directiveType).Int("line", line).Msg("failed to create helm directive resource")
		return
	}
	*directives = append(*directives, res)
}

// extractDirectivesFallback handles templates that can't be parsed by the standard Go
// template parser (e.g., those using Helm-specific functions like `include`, `toYaml`).
func extractDirectivesFallback(runtime *plugin.Runtime, templateName string, rawContent string) ([]any, error) {
	var mqlDirectives []any

	lines := strings.Split(rawContent, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "{{") {
			continue
		}

		// Extract content between {{ and }}
		for {
			start := strings.Index(trimmed, "{{")
			if start == -1 {
				break
			}
			// findClosingDelim skips `}}` sequences that appear inside
			// string literals (e.g. `{{ dict "k" "}}" }}`); naive
			// strings.Index would terminate at the embedded `}}`,
			// corrupt the expression, and desync the loop.
			end := findClosingDelim(trimmed[start+2:])
			if end == -1 {
				break
			}
			expr := strings.TrimSpace(trimmed[start+2 : start+2+end])
			expr = strings.TrimPrefix(expr, "-")
			expr = strings.TrimSuffix(expr, "-")
			expr = strings.TrimSpace(expr)

			directiveType := classifyDirective(expr)
			if directiveType != "" {
				addDirective(runtime, templateName, directiveType, expr, i+1, &mqlDirectives)
			}

			trimmed = trimmed[start+2+end+2:]
		}
	}

	return mqlDirectives, nil
}

func classifyDirective(expr string) string {
	switch {
	case strings.HasPrefix(expr, "if "):
		return "if"
	case strings.HasPrefix(expr, "else if "):
		return "if"
	case strings.HasPrefix(expr, "range "):
		return "range"
	case strings.HasPrefix(expr, "with "):
		return "with"
	case strings.HasPrefix(expr, "define "):
		return "define"
	case strings.HasPrefix(expr, "block "):
		return "block"
	case strings.HasPrefix(expr, "template "):
		return "include"
	case strings.HasPrefix(expr, "include "):
		return "include"
	case strings.HasPrefix(expr, "tpl "):
		return "tpl"
	default:
		return ""
	}
}

// findClosingDelim returns the offset of the `}}` that closes a `{{`
// directive, skipping any `}}` that appears inside a `"..."` or
// “ `...` “ string literal. The caller passes the slice that begins
// just after `{{`. Returns -1 when no closing delimiter is found.
func findClosingDelim(s string) int {
	const (
		modeNone = iota
		modeDoubleQuote
		modeBacktick
	)
	mode := modeNone
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch mode {
		case modeNone:
			switch ch {
			case '"':
				mode = modeDoubleQuote
			case '`':
				mode = modeBacktick
			case '}':
				if i+1 < len(s) && s[i+1] == '}' {
					return i
				}
			}
		case modeDoubleQuote:
			switch ch {
			case '\\':
				// Skip the escaped character.
				i++
			case '"':
				mode = modeNone
			}
		case modeBacktick:
			// Backtick-quoted strings in Go templates don't support
			// escapes — a closing backtick always ends the literal.
			if ch == '`' {
				mode = modeNone
			}
		}
	}
	return -1
}
