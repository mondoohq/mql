// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package printer

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
	"go.mondoo.com/mql/utils/sortx"
	"golang.org/x/exp/slices"
)

const MsgUnsupported = "unsupported platform"

// MsgTranslated marks a value a downgrade translation produced.
const MsgTranslated = "(translated for this provider version)"

type printCache struct {
	bundle         *llx.CodeBundle
	checksumLookup map[string]uint64
	isInline       bool
}

func newPrintCache(bundle *llx.CodeBundle) *printCache {
	res := &printCache{
		bundle: bundle,
	}

	code := bundle.CodeV2
	lookup := make(map[string]uint64, len(code.Checksums))
	for k, v := range code.Checksums {
		lookup[v] = k
	}
	res.checksumLookup = lookup

	return res
}

func (print *Printer) Datas(bundle *llx.CodeBundle, results map[string]*llx.RawResult) string {
	var res strings.Builder
	i := 0
	for _, v := range results {
		res.WriteString(print.Result(v, bundle))
		if len(results) > 1 && len(results) != i+1 {
			res.WriteString("\n")
		}
		i++
	}
	return res.String()
}

// Results prints a full query with all data points
// NOTE: ensure that results only contains results that match the bundle!
func (print *Printer) Results(bundle *llx.CodeBundle, results map[string]*llx.RawResult) string {
	assessment := llx.Results2Assessment(bundle, results)

	if assessment != nil {
		return print.Assessment(bundle, assessment)
	}

	return print.Datas(bundle, results)
}

// Assessment prints a complete comparable assessment
func (print *Printer) Assessment(bundle *llx.CodeBundle, assessment *llx.Assessment) string {
	var res strings.Builder

	var indent string
	if len(assessment.Results) > 1 {
		if assessment.Success {
			res.WriteString(print.Secondary("[ok] "))
		} else {
			res.WriteString(print.Failed("[failed] "))
		}
		res.WriteString(bundle.Source)
		res.WriteString("\n")
		// once we displayed the overall status, lets indent the subs
		indent = "  "
	}

	cache := newPrintCache(bundle)

	// indent all sub-results
	for i := range assessment.Results {
		cur := print.assessment(assessment.Results[i], indent, cache)
		res.WriteString(indent)
		res.WriteString(cur)
		res.WriteString("\n")
	}

	return res.String()
}

func isBooleanOp(op string) bool {
	return op == "&&" || op == "||"
}

func (print *Printer) assessment(assessment *llx.AssessmentItem, indent string, cache *printCache) string {
	bundle := cache.bundle
	nextIndent := indent + "  "
	checksum := assessment.Checksum

	if assessment.Error != "" {
		var res strings.Builder
		res.WriteString(print.Failed("[failed] "))
		if bundle != nil && bundle.Labels != nil {
			label := bundle.Labels.Labels[checksum]
			res.WriteString(label)
		}
		res.WriteString("\n")
		res.WriteString(nextIndent)
		res.WriteString("error: ")
		res.WriteString(assessment.Error)
		return res.String()
	}

	if assessment.Template != "" {
		if assessment.Success {
			return print.Secondary("[ok] true")
		}

		data := make([]string, len(assessment.Data))
		for i := range assessment.Data {
			data[i] = print.primitive(assessment.Data[i], "", indent, cache)
		}
		res := print.Failed("[failed] ") +
			print.assessmentTemplate(assessment.Template, data)
		return indentBlock(res, indent)
	}

	if isBooleanOp(assessment.Operation) {
		if assessment.Success {
			return print.Secondary("[ok] true")
		}

		// The operands are not reported for a combinator, so there is nothing to
		// print on either side of the operator. This used to render them anyway,
		// which cost every `a || b` statement the guarantee that its right side
		// only runs when the left side does not decide the result.
		var res strings.Builder
		res.WriteString(print.Secondary("[failed] "))
		if bundle != nil && bundle.Labels != nil {
			res.WriteString(bundle.Labels.Labels[checksum])
		}
		return res.String()
	}

	if assessment.Success {
		if assessment.Actual == nil {
			return print.Secondary("[ok] ") + " (missing result)"
		}

		return print.Secondary("[ok]") +
			" value: " +
			print.primitive(assessment.Actual, "", indent, cache)
	}

	var res strings.Builder
	res.WriteString(print.Failed("[failed] "))
	if bundle != nil && bundle.Labels != nil {
		label, ok := bundle.Labels.Labels[checksum]
		if ok {
			res.WriteString(label)
		}
	}
	res.WriteString("\n")

	if assessment.Expected != nil {
		res.WriteString(nextIndent)
		res.WriteString("expected: " + assessment.Operation + " ")
		res.WriteString(print.primitive(assessment.Expected, "", nextIndent, cache))
		res.WriteString("\n")
	}

	if assessment.Actual != nil {
		res.WriteString(nextIndent)
		res.WriteString("actual:   ")
		res.WriteString(print.primitive(assessment.Actual, checksum, nextIndent, cache))
	}

	return res.String()
}

// Result prints the llx raw result into a string
func (print *Printer) Result(result *llx.RawResult, bundle *llx.CodeBundle) string {
	if result == nil {
		return "< no result? >"
	}

	return print.DataWithLabel(result.Data, result.CodeID, bundle, "")
}

func (print *Printer) label(ref string, bundle *llx.CodeBundle) string {
	if bundle == nil {
		return ""
	}

	labels := bundle.Labels
	if labels == nil {
		return fmt.Sprintf("["+print.Primary("%s")+"] ", ref)
	}

	label := labels.Labels[ref]
	if label == "" {
		return ""
	}

	return print.Primary(label) + ": "
}

func (print *Printer) defaultLabel(ref string, bundle *llx.CodeBundle) string {
	if bundle == nil {
		return ""
	}

	labels := bundle.Labels
	if labels == nil {
		return fmt.Sprintf("["+print.Primary("%s")+"] ", ref)
	}

	label := labels.Labels[ref]
	if label == "" {
		return ""
	}

	return print.Primary(label) + "="
}

func isDefaultField(ref string, bundle *llx.CodeBundle, defaultFields []string) bool {
	if bundle == nil {
		return false
	}

	labels := bundle.Labels
	if labels == nil {
		return false
	}

	label := labels.Labels[ref]
	if label == "" {
		return false
	}

	return slices.Contains(defaultFields, label)
}

func (print *Printer) array(typ types.Type, data []any, checksum string, indent string, cache *printCache) string {
	if len(data) == 0 {
		return "[]"
	}

	var res strings.Builder
	if cache.isInline {
		res.WriteString("[")
	} else {
		res.WriteString("[\n")
	}

	ep := cache.checksumLookup[checksum]
	listType := ""
	if ep != 0 {
		code := cache.bundle.CodeV2
		chunk := code.Chunk(ep)
		switch chunk.Id {
		case "$one", "$all", "$none", "$any":
			ref := chunk.Function.Binding
			listChunk := code.Chunk(ref)
			listType = types.Type(listChunk.Type()).Child().Label()
			listType += " "
		}
	}

	if cache.isInline {
		for i := range data {
			res.WriteString(print.data(typ.Child(), data[i], checksum, indent, cache))
			if len(data) != i+1 {
				res.WriteString(", ")
			}
		}
	} else {
		for i := range data {
			fmt.Fprintf(&res,
				indent+"  %d: %s%s\n",
				i,
				listType,
				print.data(typ.Child(), data[i], checksum, indent+"  ", cache),
			)
		}
	}

	res.WriteString(indent + "]")
	return res.String()
}

func (print *Printer) assessmentTemplate(template string, data []string) string {
	res := template
	for i := range data {
		r := "$" + strconv.Itoa(i)
		res = strings.ReplaceAll(res, r, data[i])
	}
	return res
}

func (print *Printer) dataAssessment(codeID string, data map[string]any, bundle *llx.CodeBundle) string {
	var assertion *llx.AssertionMessage
	var ok bool

	assertion, ok = bundle.Assertions[codeID]
	if !ok {
		return ""
	}

	checksums := assertion.Checksums
	if assertion.DecodeBlock {
		if len(assertion.Checksums) < 2 {
			return ""
		}

		v, ok := data[assertion.Checksums[0]]
		if !ok {
			return ""
		}
		raw, ok := v.(*llx.RawData)
		if !ok {
			return ""
		}
		data, ok = raw.Value.(map[string]any)
		if !ok {
			return ""
		}
		checksums = checksums[1:]
	}

	fields := make([]string, len(checksums))
	for i := range checksums {
		v, ok := data[checksums[i]]
		if !ok {
			return ""
		}

		val := v.(*llx.RawData)
		fields[i] = print.Data(val.Type, val.Value, "", bundle, "")
	}

	return print.assessmentTemplate(assertion.Template, fields)
}

func (print *Printer) refMap(data map[string]any, checksum string, indent string, cache *printCache) string {
	if len(data) == 0 {
		return "{}"
	}

	var res strings.Builder

	// we need to separate entries that are unlabelled (eg part of an assertion)
	labeledKeys := []string{}
	keys := sortx.Keys(data)
	for i := range keys {
		if _, ok := cache.bundle.Labels.Labels[keys[i]]; ok {
			labeledKeys = append(labeledKeys, keys[i])
		}
	}

	code := cache.bundle.CodeV2
	ep := cache.checksumLookup[checksum]
	listType := ""
	if ep != 0 {
		chunk := code.Chunk(ep)
		switch chunk.Id {
		case "$one", "$all", "$none", "$any":
			ref := chunk.Function.Binding
			listChunk := code.Chunk(ref)
			listType = types.Type(listChunk.Type()).Child().Label()
		}
	}

	nonDefaultFields := []string{}
	defaultFields := []string{}
	if listType != "" && print.schema != nil {
		resourceInfo := (print.schema).Lookup(listType)
		if resourceInfo != nil {
			defaultFields = strings.Split(resourceInfo.Defaults, " ")
		}
	}

	inlineCache := *cache
	inlineCache.isInline = true
	for _, k := range labeledKeys {
		if k == "_" {
			continue
		}

		if !isDefaultField(k, cache.bundle, defaultFields) {
			// save for later output after we wrote all the default fields
			nonDefaultFields = append(nonDefaultFields, k)
			continue
		}

		v := data[k]
		label := print.defaultLabel(k, cache.bundle)
		val := v.(*llx.RawData)

		if plugin.IsUnsupportedProviderError(val.Error) {
			res.WriteString("  " + label + print.Disabled(MsgUnsupported) + "\n")
			continue
		}
		// A field this build was never going to have reads as not-measured, not
		// as a failure: nothing went wrong here, the content is simply newer
		// than the provider. Dimmed rather than red, and it still says which
		// version would supply it.
		if llx.IsUnavailable(val.Error) {
			res.WriteString("  " + label + print.Disabled(val.Error.Error()) + "\n")
			continue
		}
		if val.Error != nil {
			res.WriteString("  " + label + print.Error(val.Error.Error()) + " ")
			continue
		}

		data := print.data(val.Type, val.Value, k, "", &inlineCache)
		res.WriteString(label + data + print.translatedNote(val) + " ")
	}

	if len(nonDefaultFields) > 0 {
		res.WriteString("{\n")

		// Work out which fields render as an assessment, and which fields those
		// assessments consume. A consumed field can sit earlier in the list than
		// the assessment using it, so this has to be settled before we write
		// anything -- otherwise the output order would depend on it.
		assessments := map[string]string{}
		skipFields := map[string]struct{}{}
		for _, k := range nonDefaultFields {
			ref, ok := cache.checksumLookup[k]
			if !ok {
				continue
			}

			consumed := []string{}
			assessment := code.Entrypoint2Assessment(cache.bundle, ref, func(s string) (*llx.RawResult, bool) {
				found, ok := data[s]
				if !ok {
					return nil, false
				}
				raw, ok := found.(*llx.RawData)
				if !ok {
					return nil, false
				}
				consumed = append(consumed, s)
				return &llx.RawResult{Data: raw, CodeID: s}, true
			})
			// Entrypoint2Assessment also returns items for plain fields. Only
			// actual assertions are worth rendering as an assessment; anything
			// else stays a regular field.
			if assessment == nil || !assessment.IsAssertion {
				continue
			}

			// The operands an assessment compares are already conveyed by it, so
			// they must not also show up as standalone fields. Note that lookup
			// is first called for the assertion itself, and that one only gets
			// suppressed when we go on to render the expanded form below.
			for _, v := range consumed {
				if v == k && assessment.Success {
					continue
				}
				skipFields[v] = struct{}{}
			}

			// A passing assertion needs no expansion: "x == 'a': true" already
			// says everything, and an [ok] block would drop the label and cost
			// three lines to say the same thing.
			if assessment.Success {
				continue
			}

			assessments[k] = print.assessment(assessment, indent+"  ", cache)
		}

		for _, k := range nonDefaultFields {
			if k == "_" {
				continue
			}
			if _, ok := skipFields[k]; ok {
				// Either this field is an assertion we expand here, or it is an
				// operand some other assertion already reported on.
				if a, ok := assessments[k]; ok {
					res.WriteString(indent)
					res.WriteString("  ")
					res.WriteString(a)
					res.WriteByte('\n')
				}
				continue
			}

			v := data[k]
			label := print.label(k, cache.bundle)
			val := v.(*llx.RawData)

			if plugin.IsUnsupportedProviderError(val.Error) {
				res.WriteString(indent + "  " + label + print.Disabled(MsgUnsupported) + "\n")
				continue
			}
			if llx.IsUnavailable(val.Error) {
				res.WriteString(indent + "  " + label + print.Disabled(val.Error.Error()) + "\n")
				continue
			}
			if val.Error != nil {
				res.WriteString(indent + "  " + label + print.Error(val.Error.Error()) + "\n")
				continue
			}

			if truthy, _ := val.IsTruthy(); !truthy {
				assertion := print.dataAssessment(k, data, cache.bundle)
				if assertion != "" {
					assertion = print.Failed("[failed]") + " " + strings.Trim(assertion, "\n\t ")
					assertion = indentBlock(assertion, indent+"  ")
					res.WriteString(indent + "  " + assertion + "\n")
					continue
				}
			}

			data := print.data(val.Type, val.Value, k, indent+"  ", cache)
			res.WriteString(indent + "  " + label + data + "\n")
		}

		res.WriteString(indent + "}")
	}
	return res.String()
}

func (print *Printer) stringMap(typ types.Type, data map[string]any, indent string, cache *printCache) string {
	if len(data) == 0 {
		return "{}"
	}

	var res strings.Builder
	res.WriteString("{\n")

	keys := sortx.Keys(data)
	for _, k := range keys {
		v := data[k]
		val := print.data(typ.Child(), v, k, indent+"  ", cache)
		fmt.Fprintf(&res, indent+"  %s: %s\n", k, val)
	}

	res.WriteString(indent + "}")
	return res.String()
}

func (print *Printer) dict(typ types.Type, raw any, indent string, cache *printCache) string {
	if raw == nil {
		return print.Secondary("null")
	}

	switch data := raw.(type) {
	case bool:
		if data {
			return print.Secondary("true")
		}
		return print.Secondary("false")

	case int64:
		return print.Secondary(fmt.Sprintf("%d", data))

	case float64:
		return print.Secondary(fmt.Sprintf("%f", data))

	case string:
		return print.Secondary(llx.PrettyPrintString(data))

	case time.Time:
		return print.Secondary(data.String())

	case []any:
		if len(data) == 0 {
			return "[]"
		}

		var res strings.Builder
		res.WriteString("[\n")

		for i := range data {
			fmt.Fprintf(&res,
				indent+"  %d: %s\n",
				i,
				print.dict(typ, data[i], indent+"  ", cache),
			)
		}

		res.WriteString(indent + "]")
		return res.String()

	case map[string]any:
		if len(data) == 0 {
			return "{}"
		}

		var res strings.Builder
		res.WriteString("{\n")

		keys := sortx.Keys(data)
		for _, k := range keys {
			s := print.dict(typ, data[k], indent+"  ", cache)
			fmt.Fprintf(&res, indent+"  %s: %s\n", k, s)
		}

		res.WriteString(indent + "}")
		return res.String()

	default:
		return print.Secondary(fmt.Sprintf("%+v", raw))
	}
}

func (print *Printer) intMap(typ types.Type, data map[int]any, indent string, cache *printCache) string {
	var res strings.Builder
	res.WriteString("{\n")

	for i := range data {
		value := data[i]
		fmt.Fprintf(&res, indent+"  %d: "+print.Secondary("%#v")+"\n", i, value)
	}

	res.WriteString(indent + "}")
	return res.String()
}

func (print *Printer) resourceContext(data any, checksum string, indent string, cache *printCache) (string, bool) {
	sc, ok := cache.bundle.ParseSourceContext(data)
	if !ok {
		return "", false
	}

	var res strings.Builder
	if sc.Path == "" {
		if !sc.Range.IsEmpty() {
			res.WriteString("<unknown>:")
			res.WriteString(sc.Range.String())
		}
	} else {
		res.WriteString(sc.Path)
		if !sc.Range.IsEmpty() {
			res.WriteByte(':')
			res.WriteString(sc.Range.String())
		}
	}
	if sc.Content != "" {
		res.WriteByte('\n')
		res.WriteString(indent)
		res.WriteString(indentBlock(sc.Content, indent))
	}

	r := res.String()
	if r == "" {
		return "", false
	}
	return r, true
}

func (print *Printer) autoExpand(blockRef uint64, data any, indent string, cache *printCache) string {
	var res strings.Builder

	if arr, ok := data.([]any); ok {
		if len(arr) == 0 {
			return "[]"
		}

		prefix := indent + "  "
		res.WriteString("[\n")
		for i := range arr {
			num := strconv.Itoa(i)
			autoIndent := prefix + strings.Repeat(" ", len(num)+2)
			c := print.autoExpand(blockRef, arr[i], autoIndent, cache)
			res.WriteString(prefix)
			res.WriteString(num)
			res.WriteString(": ")
			res.WriteString(c)
			res.WriteByte('\n')
		}
		res.WriteString(indent + "]")
		return res.String()
	}

	if data == nil {
		return print.Secondary("null")
	}

	m, ok := data.(map[string]any)
	if !ok {
		return "data is not a map to auto-expand"
	}

	block := cache.bundle.CodeV2.Block(blockRef)
	var name string

	self, ok := m["_"].(*llx.RawData)
	if ok {
		name = self.Type.ResourceName()
	} else if block != nil {
		// We end up here when we deal with array resources. In that case,
		// the block's first element is typed as an individual resource, so we can
		// use that.
		typ := block.Chunks[0].Type()
		name = typ.ResourceName()
	}
	if name == "" {
		name = "<unknown>"
	}

	// Only show the resource name if there are no entrypoints (defaults) to display.
	// When entrypoints exist, their label=value pairs are self-descriptive enough.
	hasEntrypoints := block != nil && len(block.Entrypoints) > 0
	if !hasEntrypoints {
		res.WriteString(name)
	}

	// hasContext := false
	// resourceInfo := print.schema.Lookup(name)
	// if resourceInfo != nil && resourceInfo.Context != "" {
	// 	hasContext = true
	// }

	if block != nil {
		// important to process them in this order
		first := true
		for _, ref := range block.Entrypoints {
			checksum := cache.bundle.CodeV2.Checksums[ref]
			v, ok := m[checksum]
			if !ok {
				continue
			}
			vv, ok := v.(*llx.RawData)
			if !ok {
				continue
			}

			label := cache.bundle.Labels.Labels[checksum]

			// Note (Dom): We don't have precise matching on the resource context
			// just yet. Here we handle it via best-effort, i.e. if it's called
			// context, a block, and it's part of the resource's auto-expand, then we
			// treat it as a kind of resource context.
			if label == "context" && types.Type(vv.Type) == types.Block {
				if data, ok := print.resourceContext(vv.Value, checksum, indent, cache); ok {
					res.WriteByte('\n')
					res.WriteString(indent)
					res.WriteString("in ")
					res.WriteString(data)
					continue
				}
			}

			// Multi-line string values (e.g. a source-context `content` snippet)
			// read best as a raw block indented on the following lines rather than
			// trailing off a `label=` on the current line. The preceding fields
			// (path, range) already identify it, so we drop the label entirely.
			if s, ok := vv.Value.(string); ok && strings.Contains(s, "\n") {
				fieldIndent := indent + "  "
				res.WriteByte('\n')
				res.WriteString(fieldIndent)
				res.WriteString(indentBlock(strings.TrimRight(s, "\n"), fieldIndent))
				first = false
				continue
			}

			val := print.data(vv.Type, vv.Value, checksum, indent, cache)
			if !first || !hasEntrypoints {
				res.WriteByte(' ')
			}
			first = false
			res.WriteString(label)
			res.WriteByte('=')
			res.WriteString(val)
		}
	}

	return res.String()
}

func (print *Printer) Data(typ types.Type, data any, checksum string, bundle *llx.CodeBundle, indent string) string {
	return print.data(typ, data, checksum, indent, newPrintCache(bundle))
}

func (print *Printer) data(typ types.Type, data any, checksum string, indent string, cache *printCache) string {
	if typ.NotSet() {
		return "no data available"
	}

	if blockRef, ok := cache.bundle.AutoExpand[checksum]; ok {
		return print.autoExpand(blockRef, data, indent, cache)
	}

	switch typ.Underlying() {
	case types.Any:
		return indent + fmt.Sprintf("any: %#v", data)
	case types.Ref:
		if d, ok := data.(uint64); ok {
			return "ref" + print.Primary(fmt.Sprintf("<%d,%d>", d>>32, d&0xFFFFFFFF))
		} else {
			return "ref" + print.Primary(fmt.Sprintf("%d", data.(int32)))
		}
	case types.Nil:
		return print.Secondary("null")
	case types.Bool:
		if data == nil {
			return print.Secondary("null")
		}
		if data.(bool) {
			return print.Secondary("true")
		}
		return print.Secondary("false")
	case types.Int:
		if data == nil {
			return print.Secondary("null")
		}
		if data.(int64) == math.MaxInt64 {
			return print.Secondary("Infinity")
		}
		if data.(int64) == math.MinInt64 {
			return print.Secondary("-Infinity")
		}
		return print.Secondary(strconv.FormatInt(data.(int64), 10))
	case types.Float:
		if data == nil {
			return print.Secondary("null")
		}
		if math.IsInf(data.(float64), 1) {
			return print.Secondary("Infinity")
		}
		if math.IsInf(data.(float64), -1) {
			return print.Secondary("-Infinity")
		}
		return print.Secondary(strconv.FormatFloat(data.(float64), 'g', -1, 64))
	case types.String:
		if data == nil {
			return print.Secondary("null")
		}
		return print.Secondary(llx.PrettyPrintString(data.(string)))
	case types.Regex:
		if data == nil {
			return print.Secondary("null")
		}
		return print.Secondary(fmt.Sprintf("/%s/", data))
	case types.Time:
		return print.Secondary(llx.StringifyValue(data, types.Time))

	case types.Dict:
		return print.dict(typ, data, indent, cache)

	case types.Score:
		return llx.ScoreString(data.([]byte))

	case types.Block:
		return print.refMap(data.(map[string]any), checksum, indent, cache)

	case types.Version:
		return print.Secondary(data.(string))

	case types.IP:
		if data == nil {
			return print.Secondary("null")
		}
		return print.Secondary(data.(llx.RawIP).String())

	case types.ArrayLike:
		if data == nil {
			return print.Secondary("null")
		}
		return print.array(typ, data.([]any), checksum, indent, cache)

	case types.MapLike:
		if data == nil {
			return print.Secondary("null")
		}
		if typ.Key() == types.String {
			return print.stringMap(typ, data.(map[string]any), indent, cache)
		}
		if typ.Key() == types.Int {
			return print.intMap(typ, data.(map[int]any), indent, cache)
		}
		return "unable to render map, its type is not supported: " + typ.Label() + ", raw: " + fmt.Sprintf("%#v", data)

	case types.ResourceLike:
		if data == nil {
			return print.Secondary("null")
		}

		r := data.(llx.Resource)
		if id := r.MqlID(); id != "" {
			return id
		}
		return r.MqlName()

	case types.FunctionLike:
		if d, ok := data.(uint64); ok {
			return indent + fmt.Sprintf("=> <%d,0>", d>>32)
		} else {
			return indent + fmt.Sprintf("=> %#v", data)
		}

	case types.Range:
		// A range is a scalar value, so (like int/string) it must not carry the
		// block indent — otherwise it renders right-shifted when printed inline
		// after a `range=` label.
		if d, ok := data.(llx.Range); ok {
			return d.String()
		} else {
			return "<bad range>"
		}

	case types.AssetLike:
		v, ok := data.(*llx.AssetValue)
		if !ok || v == nil {
			return "null"
		}
		// TODO: store and retrieve more information about the referenced asset
		return "asset"

	default:
		return indent + fmt.Sprintf("🤷 %#v", data)
	}
}

// For the printer we want to filter out UnsupportedProvider errors,
// since they are just reporting ignored bits.
func filterErrors(e error) error {
	if e == nil {
		return nil
	}
	if plugin.IsUnsupportedProviderError(e) {
		return nil
	}
	merr, ok := e.(*multierr.Errors)
	if !ok {
		return e
	}

	filtered := merr.Filter(func(e error) bool {
		return plugin.IsUnsupportedProviderError(e)
	})
	if len(filtered.Errors) == 0 {
		return nil
	}
	return filtered
}

// DataWithLabel prints RawData into a string
func (print *Printer) DataWithLabel(r *llx.RawData, checksum string, bundle *llx.CodeBundle, indent string) string {
	b := strings.Builder{}
	errs := filterErrors(r.Error)
	if errs != nil {
		b.WriteString(print.Error(strings.TrimSpace(errs.Error())))
		b.WriteByte('\n')
	}

	b.WriteString(print.label(checksum, bundle))
	b.WriteString(print.Data(r.Type, r.Value, checksum, bundle, indent))
	return b.String()
}

func (print *Printer) CompilerStats(stats mqlc.CompilerStats) string {
	var res strings.Builder
	res.WriteString("Resources and Fields used:\n")

	stats.WalkSorted(func(resource string, field string, info mqlc.FieldStat) {
		if field == "" {
			res.WriteString("- " + print.Yellow(resource) + "\n")
			return
		}

		autoexpand := ""
		if info.AutoExpand {
			autoexpand = print.Disabled(" [auto-expand]")
		}

		res.WriteString("  - " + print.Primary(field) + "  type=" + info.Type.Label() + autoexpand + "\n")
	})

	return res.String()
}

// CodeBundle prints the contents of the MQL query
func (print *Printer) CodeBundle(bundle *llx.CodeBundle) string {
	var res strings.Builder

	res.WriteString(print.CodeV2(bundle.CodeV2, bundle, ""))

	for idx := range bundle.Suggestions {
		info := bundle.Suggestions[idx]
		res.WriteString(print.Yellow("- suggestion: "+info.Field) + "\n")
	}

	return res.String()
}

func (print *Printer) CodeV2(code *llx.CodeV2, bundle *llx.CodeBundle, indent string) string {
	var res strings.Builder
	indent += "   "
	cache := newPrintCache(bundle)

	for i := range code.Blocks {
		block := code.Blocks[i]

		res.WriteString(print.Secondary(fmt.Sprintf("-> block %d\n", i+1)))

		res.WriteString(indent)
		res.WriteString("entrypoints: [")
		for idx, ep := range block.Entrypoints {
			fmt.Fprintf(&res, "<%d,%d>", ep>>32, ep&0xFFFFFFFF)
			if idx != len(block.Entrypoints)-1 {
				res.WriteString(" ")
			}
		}
		if len(block.Datapoints) != 0 {
			res.WriteString("] datapoints: [")
			for idx, ep := range block.Datapoints {
				fmt.Fprintf(&res, "<%d,%d>", ep>>32, ep&0xFFFFFFFF)
				if idx != len(block.Datapoints)-1 {
					res.WriteString(" ")
				}
			}
		}
		res.WriteString("]\n")

		for j := range block.Chunks {
			res.WriteString("   ")
			print.chunkV2(j, block.Chunks[j], block, indent, cache, &res)
		}
	}

	return res.String()
}

func (print *Printer) chunkV2(idx int, chunk *llx.Chunk, block *llx.Block, indent string, cache *printCache, w *strings.Builder) {
	sidx := strconv.Itoa(idx+1) + ": "

	switch chunk.Call {
	case llx.Chunk_FUNCTION:
		w.WriteString(print.Primary(sidx))
	case llx.Chunk_PRIMITIVE:
		w.WriteString(print.Secondary(sidx))
	default:
		w.WriteString(print.Error(sidx))
	}

	if chunk.Id != "" {
		w.WriteString(chunk.Id + " ")
	}

	if chunk.Primitive != nil {
		primitive := chunk.Primitive

		// special case: function arguments are supplied by the caller, so we fill
		// in the context for all resource references since they cannot have default values
		if idx < int(block.Parameters) && len(primitive.Value) == 0 && types.Type(primitive.Type).IsResource() {
			primitive = &llx.Primitive{Type: primitive.Type, Value: []byte("context")}
		}

		// FIXME: this is definitely the wrong ID
		w.WriteString(print.primitive(primitive, "", indent, cache))
	}

	if chunk.Function != nil {
		w.WriteString(print.functionV2(chunk.Function, "", indent, cache))
	}

	w.WriteString("\n")
}

func (print *Printer) functionV2(f *llx.Function, checksum string, indent string, cache *printCache) string {
	argsStr := ""
	if len(f.Args) > 0 {
		argsStr = " (" + strings.TrimSpace(print.primitives(f.Args, checksum, indent, cache)) + ")"
	}

	return "bind: <" + strconv.Itoa(int(f.Binding>>32)) + "," +
		strconv.Itoa(int(f.Binding&0xFFFFFFFF)) +
		"> type:" + types.Type(f.Type).Label() +
		argsStr
}

func (print *Printer) primitives(list []*llx.Primitive, checksum string, indent string, cache *printCache) string {
	if len(list) == 0 {
		return ""
	}
	var res strings.Builder

	if len(list) >= 1 {
		res.WriteString(print.primitive(list[0], checksum, indent, cache))
	}

	for i := 1; i < len(list); i++ {
		res.WriteString(", ")
		res.WriteString(strings.TrimLeft(print.primitive(list[i], checksum, indent, cache), " "))
	}
	return res.String()
}

// Primitive prints the llx primitive to a string
func (print *Printer) Primitive(primitive *llx.Primitive, checksum string, bundle *llx.CodeBundle, indent string) string {
	return print.primitive(primitive, checksum, indent, newPrintCache(bundle))
}

// Primitive prints the llx primitive to a string
func (print *Printer) primitive(primitive *llx.Primitive, checksum string, indent string, cache *printCache) string {
	if primitive == nil {
		return "?"
	}

	if primitive.Value == nil && primitive.Array == nil && primitive.Map == nil {
		return "_"
	}
	raw := primitive.RawData()
	return print.data(raw.Type, raw.Value, checksum, indent, cache)
}

func indentBlock(text string, indent string) string {
	return strings.ReplaceAll(text, "\n", "\n"+indent)
}

// translatedNote marks a value that a downgrade translation produced rather
// than the call the bundle was compiled with (ADR 040 part 6).
//
// The value is correct as far as we know, so this is a note and not an error:
// it is dimmed and appended, never in place of the data. It exists because
// patching decouples what ran from what is reported, and without a visible
// marker a bad translation looks exactly like a bad provider.
func (print *Printer) translatedNote(val *llx.RawData) string {
	if val == nil || !val.Translated {
		return ""
	}
	return " " + print.Disabled(MsgTranslated)
}
