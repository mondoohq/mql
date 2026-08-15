// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/rs/zerolog/log"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
	"go.mondoo.com/mql/types"
)

type mqlTerraformInternal struct {
	// lock guards every field below. The cache is populated exactly once by
	// ensureCache and is immutable afterwards; all readers must hold lock.
	lock sync.Mutex
	// cached reports whether ensureCache has already populated the fields below.
	cached bool

	// The parsed HCL blocks, split by type. allBlocks holds every block;
	// the type-specific slices are views into the same block instances.
	allBlocks        []any
	providerBlocks   []any
	datasourceBlocks []any
	variableBlocks   []any
	outputBlocks     []any
	resources        []*mqlTerraformBlock
	// these are blocks with the type set to "terraform", used for settings
	terraformBlocks []*mqlTerraformBlock

	blocksByName  map[string]*mqlTerraformBlock
	relatedBlocks map[string][]*mqlTerraformBlock
}

func (t *mqlTerraform) files() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)

	// plan and state assets have no HCL parser; there are no files to list.
	parser := conn.Parser()
	if parser == nil {
		return []any{}, nil
	}

	var mqlTerraformFiles []any
	files := parser.Files()
	for path := range files {
		mqlTerraformFile, err := CreateResource(t.MqlRuntime, "terraform.file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, err
		}
		mqlTerraformFiles = append(mqlTerraformFiles, mqlTerraformFile)
	}

	return mqlTerraformFiles, nil
}

func (t *mqlTerraform) tfvars() (any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)
	// .tfvars files hold the raw input values for variables, so they are
	// surfaced verbatim here — we intentionally pass a nil eval context rather
	// than resolving var.*/local.* references. (Variable resolution against
	// these values happens in arguments() via the connection's eval context.)
	return hclAttributesToDict(conn.TfVars(), nil)
}

func (t *mqlTerraform) modules() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)

	manifest := conn.ModulesManifest()
	if manifest == nil {
		return nil, nil
	}

	var mqlModules []any
	for i := range manifest.Records {
		record := manifest.Records[i]

		r, err := CreateResource(t.MqlRuntime, "terraform.module", map[string]*llx.RawData{
			"key":     llx.StringData(record.Key),
			"source":  llx.StringData(record.SourceAddr),
			"version": llx.StringData(record.Version),
			"dir":     llx.StringData(record.Dir),
		})
		if err != nil {
			return nil, err
		}
		mqlModules = append(mqlModules, r)
	}

	return mqlModules, nil
}

func (t *mqlTerraform) blocks() ([]any, error) {
	if err := t.ensureCache(); err != nil {
		return nil, err
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.allBlocks, nil
}

// ensureCache parses the HCL configuration once and populates every cached
// collection on the terraform singleton. It is safe to call concurrently from
// any terraform.* field getter or init function: the first caller does the
// work while holding lock, and every other caller blocks on lock and then
// observes the fully-populated cache. Populating under a single lock (instead
// of bouncing through GetBlocks/GetOrCompute, which is not synchronized) is
// what prevents the intermittently-empty terraform.resources list — several
// terraform.* fields resolve in parallel during a policy scan and previously
// raced on this shared state (mondoohq/mql#8966).
func (t *mqlTerraform) ensureCache() error {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.cached {
		return nil
	}

	var blocks []any
	// plan and state assets have no HCL parser; there are no blocks to list and
	// the cache is left empty (but marked populated so we don't re-parse).
	conn, ok := t.MqlRuntime.Connection.(*connection.Connection)
	if ok && conn != nil {
		if parser := conn.Parser(); parser != nil {
			files := parser.Files()
			for k := range files {
				f := files[k]
				bs, err := listHclBlocks(t.MqlRuntime, f.Body, f)
				if err != nil {
					return err
				}
				blocks = append(blocks, bs...)
			}
		}
	}

	t.allBlocks = blocks
	t.blocksByName = map[string]*mqlTerraformBlock{}
	t.relatedBlocks = map[string][]*mqlTerraformBlock{}
	t.providerBlocks = []any{}
	t.datasourceBlocks = []any{}
	t.variableBlocks = []any{}
	t.outputBlocks = []any{}
	t.resources = []*mqlTerraformBlock{}
	t.terraformBlocks = []*mqlTerraformBlock{}

	for i := range blocks {
		block := blocks[i].(*mqlTerraformBlock)

		// type must be pre-initialized
		switch block.Type.Data {
		case "provider":
			t.providerBlocks = append(t.providerBlocks, block)
		case "data":
			t.datasourceBlocks = append(t.datasourceBlocks, block)
		case "resource":
			t.resources = append(t.resources, block)
		case "variable":
			t.variableBlocks = append(t.variableBlocks, block)
		case "output":
			t.outputBlocks = append(t.outputBlocks, block)
		case "terraform":
			t.terraformBlocks = append(t.terraformBlocks, block)
		default:
			// Note: we don't do anything with these blocks yet.
			// They might be worth looking into.
		}

		// labels must be pre-initialized
		name := block.terraformID()
		t.blocksByName[name] = block
	}

	// We need blocks by name before we can jump into
	// related blocks, because we need to access them
	// via their name
	for i := range blocks {
		block := blocks[i].(*mqlTerraformBlock)
		name := block.terraformID()

		rel, err := listRelatedBlocks(t, block.block.Data.Body)
		if err != nil {
			return err
		}

		// connect from this block to all related blocks...
		t.relatedBlocks[name] = append(t.relatedBlocks[name], rel...)
		// ... and also connect the inverse (related to this block)
		for i := range rel {
			relBlock := rel[i]
			relName := relBlock.terraformID()
			t.relatedBlocks[relName] = append(t.relatedBlocks[relName], block)
		}
	}

	t.cached = true
	return nil
}

func listRelatedBlocks(t *mqlTerraform, rawBody any) ([]*mqlTerraformBlock, error) {
	var res []*mqlTerraformBlock
	switch body := rawBody.(type) {
	case *hclsyntax.Body:
		for _, v := range body.Attributes {
			refs := getReferences(v.Expr, &hcl.EvalContext{
				Functions: hclFunctions(),
			})
			// we need the resource name and its ID at least
			if len(refs) < 2 {
				continue
			}

			refName := strings.Join(refs[0:2], "\x00")
			if t.blocksByName[refName] == nil { // do not add nil blocks
				continue
			}
			res = append(res, t.blocksByName[refName])
		}
	case hcl.Body:
		return nil, errors.New("cannot yet list related blocks for regular hcl Body")
	}
	return res, nil
}

func (t *mqlTerraform) providers() ([]any, error) {
	if err := t.ensureCache(); err != nil {
		return nil, err
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.providerBlocks, nil
}

func (t *mqlTerraform) datasources() ([]any, error) {
	if err := t.ensureCache(); err != nil {
		return nil, err
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.datasourceBlocks, nil
}

func (t *mqlTerraform) variables() ([]any, error) {
	if err := t.ensureCache(); err != nil {
		return nil, err
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.variableBlocks, nil
}

func (t *mqlTerraform) outputs() ([]any, error) {
	if err := t.ensureCache(); err != nil {
		return nil, err
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.outputBlocks, nil
}

func extractHclCodeSnippet(file *hcl.File, fileRange hcl.Range) string {
	if file == nil {
		return ""
	}

	lines := append([]string{""}, strings.Split(string(file.Bytes), "\n")...)

	// determine few surrounding lines
	start := fileRange.Start.Line - 3
	if start <= 0 {
		start = 1
	}
	end := fileRange.End.Line + 3
	if end >= len(lines) {
		end = len(lines) - 1
	}

	// build the snippet
	sb := strings.Builder{}
	for lineNo := start; lineNo <= end; lineNo++ {
		fmt.Fprintf(&sb, "% 6d | ", lineNo)
		sb.WriteString(lines[lineNo])
		sb.WriteString("\n")
	}

	return sb.String()
}

func newMqlHclBlock(runtime *plugin.Runtime, block *hcl.Block, file *hcl.File, iterVars map[string]cty.Value) (plugin.Resource, error) {
	start, end, err := newFilePosRange(runtime, block.TypeRange)
	if err != nil {
		return nil, err
	}

	snippet := extractHclCodeSnippet(file, block.TypeRange)

	args := map[string]*llx.RawData{
		"type":    llx.StringData(block.Type),
		"labels":  llx.ArrayData(llx.TArr2Raw(block.Labels), types.String),
		"start":   llx.ResourceData(start, "terraform.fileposition"),
		"end":     llx.ResourceData(end, "terraform.fileposition"),
		"snippet": llx.StringData(snippet),
	}

	var res plugin.Resource
	if len(iterVars) > 0 {
		// A `dynamic` block expands to one block per for_each element, and every
		// one of them points at the same `content { ... }` source position. The
		// runtime caches resources by id, and a block's id is its file position,
		// so routing these through CreateResource would collapse all elements
		// onto a single shared resource and leave every one showing the last
		// element's iterator. Build them directly instead: they are distinct
		// values that deliberately share a position, which is exactly the case
		// the position-keyed cache cannot represent.
		res, err = createTerraformBlock(runtime, args)
	} else {
		res, err = CreateResource(runtime, "terraform.block", args)
	}
	if err != nil {
		return nil, err
	}
	r := res.(*mqlTerraformBlock)
	r.block = plugin.TValue[*hcl.Block]{State: plugin.StateIsSet, Data: block}
	r.cachedFile = plugin.TValue[*hcl.File]{State: plugin.StateIsSet, Data: file}
	r.iterVars = iterVars
	return r, err
}

type mqlTerraformBlockInternal struct {
	block      plugin.TValue[*hcl.Block]
	cachedFile plugin.TValue[*hcl.File]
	// iterVars binds the `dynamic` iterator (e.g. `ingress.value`) for a block
	// generated by expanding a dynamic block's for_each. It is empty for an
	// ordinary block, and merged into the eval context when resolving this
	// block's attributes.
	iterVars map[string]cty.Value
}

func (t *mqlTerraformBlock) id() (string, error) {
	// NOTE: a hcl block is identified by its filename and position
	fp := t.Start

	if fp.State != plugin.StateIsSet || fp.Data == nil {
		return "", errors.New("terraform block has invalid position data")
	}

	file := fp.Data.Path.Data
	line := fp.Data.Line.Data
	column := fp.Data.Column.Data

	return "terraform.block/" + file + "/" + strconv.FormatInt(line, 10) + "/" + strconv.FormatInt(column, 10), nil
}

func (r *mqlTerraformContext) id() (string, error) {
	if r.Path.Data == "" {
		return "", errors.New("need path to exist for terraform.context ID")
	}

	rng := r.Range.Data.String()
	return r.Path.Data + ":" + rng, nil
}

func (r *mqlTerraformContext) content(path string, rnge llx.Range) (string, error) {
	if path == "" {
		return "", errors.New("no path information for terraform.context")
	}

	conn := r.MqlRuntime.Connection.(*connection.Connection)
	// plan and state assets have no HCL parser; there is no source text to read.
	parser := conn.Parser()
	if parser == nil {
		return "", errors.New("terraform.context content is not available for plan/state assets")
	}
	files := parser.Files()
	if files == nil {
		return "", errors.New("missing terraform files in cache")
	}
	file := files[path]
	if file == nil {
		return "", errors.New("failed to get contents for terraform file '" + path + "'")
	}

	return rnge.ExtractString(string(file.Bytes), llx.DefaultExtractConfig), nil
}

func (g *mqlTerraformBlock) context() (*mqlTerraformContext, error) {
	block := g.block.Data
	if block == nil {
		return nil, errors.New("missing underlying terraform block")
	}

	runtime := g.MqlRuntime

	conn := runtime.Connection.(*connection.Connection)
	// plan and state assets have no HCL parser; there is no source text to read.
	parser := conn.Parser()
	if parser == nil {
		return nil, errors.New("terraform block context is not available for plan/state assets")
	}
	files := parser.Files()
	if files == nil {
		return nil, errors.New("missing terraform files in cache")
	}
	file := files[block.DefRange.Filename]
	if file == nil {
		return nil, errors.New("failed to get contents for terraform file '" + block.DefRange.Filename + "'")
	}

	endLine := block.DefRange.End.Line
	endColumn := block.DefRange.End.Column
	if body, ok := block.Body.(*hclsyntax.Body); ok && body != nil {
		if body.SrcRange.Filename == block.DefRange.Filename {
			endLine = body.SrcRange.End.Line
			endColumn = body.SrcRange.End.Column
		}
	}

	rnge := llx.NewRange().AddLineColumnRange(uint32(block.DefRange.Start.Line), uint32(endLine), uint32(block.DefRange.Start.Column), uint32(endColumn))
	content := rnge.ExtractString(string(file.Bytes), llx.DefaultExtractConfig)

	cobj, err := CreateResource(runtime, "terraform.context", map[string]*llx.RawData{
		"path":    llx.StringData(block.DefRange.Filename),
		"range":   llx.RangeData(rnge),
		"content": llx.StringData(content),
	})
	if err != nil {
		return nil, err
	}

	return cobj.(*mqlTerraformContext), nil
}

func (g *mqlTerraformBlock) terraformID() string {
	labels := g.Labels.Data
	var namearr []string
	for i := range labels {
		if s, ok := labels[i].(string); ok {
			namearr = append(namearr, s)
		}
	}
	return strings.Join(namearr, "\x00")
}

func (t *mqlTerraformBlock) nameLabel() (string, error) {
	labels := t.Labels.Data

	// labels are string
	if len(labels) == 0 {
		return "", nil
	}

	return labels[0].(string), nil
}

// resourceType returns the Terraform resource type (the first label, e.g.
// "aws_instance"). It mirrors terraform.state.resource.type and
// terraform.plan.resourceChange.type so HCL policies can use the same field
// name as plan/state policies instead of nameLabel.
func (t *mqlTerraformBlock) resourceType() (string, error) {
	labels := t.Labels.Data
	if len(labels) == 0 {
		return "", nil
	}
	return labels[0].(string), nil
}

// resourceName returns the Terraform resource name (the second label, e.g.
// "web" in `resource "aws_instance" "web"`). It mirrors
// terraform.state.resource.name and terraform.plan.resourceChange.name,
// replacing the cryptic labels[1] index access in policies.
func (t *mqlTerraformBlock) resourceName() (string, error) {
	labels := t.Labels.Data
	if len(labels) < 2 {
		return "", nil
	}
	return labels[1].(string), nil
}

func initTerraformResources(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	tfraw, err := CreateResource(runtime, "terraform", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	tf := tfraw.(*mqlTerraform)
	if err := tf.ensureCache(); err != nil {
		return nil, nil, err
	}
	tf.lock.Lock()
	resources := make([]*mqlTerraformBlock, len(tf.resources))
	copy(resources, tf.resources)
	tf.lock.Unlock()

	resourceArg := args["resource"]
	nameArg := args["name"]

	matchResource, err := llx.StringOrRegexMatcher(resourceArg)
	if err != nil {
		return nil, nil, err
	}
	matchName, err := llx.StringOrRegexMatcher(nameArg)
	if err != nil {
		return nil, nil, err
	}

	// The unfiltered list must have a stable, non-empty __id. An empty __id
	// makes the resource cache key collide/race with concurrently-resolved
	// terraform.resources("...") selector instances (mondoohq/mql#8966).
	id := "terraform.resources"
	if matchResource != nil || matchName != nil {
		s := checksums.New
		if matchResource != nil {
			s = s.Add(resourceArg.String())
		}
		if matchName != nil {
			s = s.Add(nameArg.String())
		}
		id = s.String()
	}

	var res []any
	for i := range resources {
		r := resources[i]
		// A resource block carries two labels (type, name), but a malformed
		// config (e.g. `resource {}` or `resource "type" {}`) parses fine via
		// the native HCL parser, which does not enforce label arity. Guard the
		// label indices and assertions so a filtered query doesn't panic.
		if matchResource != nil {
			if len(r.Labels.Data) < 1 {
				continue
			}
			s, ok := r.Labels.Data[0].(string)
			if !ok || !matchResource(s) {
				continue
			}
		}
		if matchName != nil {
			if len(r.Labels.Data) < 2 {
				continue
			}
			s, ok := r.Labels.Data[1].(string)
			if !ok || !matchName(s) {
				continue
			}
		}
		res = append(res, r)
	}

	return map[string]*llx.RawData{
		"list": llx.ArrayData(res, types.Resource("terraform.block")),
		"__id": llx.StringData(id),
	}, nil, nil
}

func (t *mqlTerraformResources) list() ([]any, error) {
	return nil, errors.New("resource was not initializeed")
}

func (t *mqlTerraformBlock) attributes() (map[string]any, error) {
	var hclBlock *hcl.Block
	if t.block.State == plugin.StateIsSet {
		hclBlock = t.block.Data
	} else {
		if t.block.Error != nil {
			return nil, t.block.Error
		}
		return nil, errors.New("cannot get hcl block")
	}

	// do not handle diag information here, it also throws errors for blocks nearby
	attributes, _ := hclBlock.Body.JustAttributes()
	return hclAttributesToDict(attributes, t.evalContext())
}

// evalContext returns the HCL evaluation context used to resolve this block's
// argument expressions: the connection's context that resolves var.*/local.*
// references to their effective values. It returns nil for connections that
// carry no such context (plan and state assets, which have no HCL parser), in
// which case references are surfaced as strings.
func (t *mqlTerraformBlock) evalContext() *hcl.EvalContext {
	conn, ok := t.MqlRuntime.Connection.(*connection.Connection)
	if !ok || conn == nil {
		return nil
	}
	base := conn.VariableEvalContext()
	if len(t.iterVars) == 0 {
		return base
	}
	// A block generated from `dynamic` needs its iterator in scope on top of
	// the shared variable context. Bind it in a child so the shared context,
	// which every other block reads, is left untouched.
	child := &hcl.EvalContext{Variables: map[string]cty.Value{}}
	if base != nil {
		child = base.NewChild()
		child.Variables = map[string]cty.Value{}
	}
	for k, v := range t.iterVars {
		child.Variables[k] = v
	}
	return child
}

func (t *mqlTerraformBlock) arguments() (map[string]any, error) {
	var hclBlock *hcl.Block
	if t.block.State == plugin.StateIsSet {
		hclBlock = t.block.Data
	} else {
		if t.block.Error != nil {
			return nil, t.block.Error
		}
		return nil, errors.New("cannot get hcl block")
	}

	// do not handle diag information here, it also throws errors for blocks nearby
	attributes, _ := hclBlock.Body.JustAttributes()
	return hclResolvedAttributesToDict(attributes, t.evalContext())
}

// argumentReferences returns the block's arguments with variable and local
// references left unresolved (e.g. "var.bucket_acl"). Use it to inspect that a
// value is parameterized even though arguments() resolves it to the effective
// value.
func (t *mqlTerraformBlock) argumentReferences() (map[string]any, error) {
	var hclBlock *hcl.Block
	if t.block.State == plugin.StateIsSet {
		hclBlock = t.block.Data
	} else {
		if t.block.Error != nil {
			return nil, t.block.Error
		}
		return nil, errors.New("cannot get hcl block")
	}

	attributes, _ := hclBlock.Body.JustAttributes()
	return hclResolvedAttributesToDict(attributes, nil)
}

// hclBodyToValuesDict folds an HCL block body into a single dict in the same
// shape Terraform plan (`change.after`) and state (`values`) expose: scalar
// arguments become direct values, and each nested block is collected into a
// list-of-maps keyed by its block type (recursively). This lets one MQL body
// run against terraform-hcl, terraform-plan, and terraform-state assets
// instead of three separately-written variants.
func hclBodyToValuesDict(rawBody hcl.Body, ctx *hcl.EvalContext) (map[string]any, error) {
	dict := map[string]any{}

	body, ok := rawBody.(*hclsyntax.Body)
	if !ok {
		// .tf.json and other non-native bodies: best effort, attributes only.
		// Nested-block traversal needs a schema we don't have here.
		attributes, _ := rawBody.JustAttributes()
		return hclResolvedAttributesToDict(attributes, ctx)
	}

	attributes := make(map[string]*hcl.Attribute, len(body.Attributes))
	for name, attr := range body.Attributes {
		attributes[name] = attr.AsHCLAttribute()
	}
	resolved, err := hclResolvedAttributesToDict(attributes, ctx)
	if err != nil {
		return nil, err
	}
	for k, v := range resolved {
		dict[k] = v
	}

	for _, block := range body.Blocks {
		// Expand `dynamic "X"` blocks into the `X` blocks they generate, exactly
		// as listHclBlocks does for blocks(). Terraform plan/state already expose
		// the generated blocks under their real type, so without this the HCL
		// values() folds them under a "dynamic" key (nested under "content") and a
		// policy written as values["X"] silently sees nothing on an HCL asset while
		// matching on the plan/state asset. normalizeHclSyntaxBlock returns the
		// block unchanged when it is not a dynamic block, so static blocks keep
		// their existing shape.
		for _, nb := range normalizeHclSyntaxBlock(block, ctx) {
			child, err := hclBodyToValuesDict(nb.block.Body, withIterVars(ctx, nb.iterVars))
			if err != nil {
				return nil, err
			}
			existing, _ := dict[nb.block.Type].([]any)
			dict[nb.block.Type] = append(existing, child)
		}
	}

	return dict, nil
}

func (t *mqlTerraformBlock) values() (map[string]any, error) {
	if t.block.State != plugin.StateIsSet {
		if t.block.Error != nil {
			return nil, t.block.Error
		}
		return nil, errors.New("cannot get hcl block")
	}
	return hclBodyToValuesDict(t.block.Data.Body, t.evalContext())
}

// hclEvalContextOrDefault returns ctx when it carries resolved variable/local
// values, or a functions-only context (no var.*/local.* resolution, as used by
// argumentReferences and by plan/state assets) when ctx is nil.
func hclEvalContextOrDefault(ctx *hcl.EvalContext) *hcl.EvalContext {
	if ctx != nil {
		return ctx
	}
	return &hcl.EvalContext{Functions: hclFunctions()}
}

func hclResolvedAttributesToDict(attributes map[string]*hcl.Attribute, ctx *hcl.EvalContext) (map[string]any, error) {
	ctx = hclEvalContextOrDefault(ctx)
	dict := map[string]any{}
	for k := range attributes {
		dict[k] = getCtyValue(attributes[k].Expr, ctx)
	}
	return dict, nil
}

func hclAttributesToDict(attributes map[string]*hcl.Attribute, ctx *hcl.EvalContext) (map[string]any, error) {
	ctx = hclEvalContextOrDefault(ctx)
	dict := map[string]any{}
	for k := range attributes {
		val, _ := attributes[k].Expr.Value(nil)
		dict[k] = map[string]any{
			"value": getCtyValue(attributes[k].Expr, ctx),
			"type":  typeexpr.TypeString(val.Type()),
		}
	}

	return dict, nil
}

// hclFunctions returns the HCL function table. It delegates to
// connection.HCLEvalFunctions so expression evaluation here stays in lockstep
// with the variable/local resolution done in the connection layer.
func hclFunctions() map[string]function.Function {
	return connection.HCLEvalFunctions()
}

// appendCtyResult flattens nested []any results from getCtyValue into a single
// slice, matching the existing TupleConsExpr/TemplateExpr behavior. nil
// values are dropped.
func appendCtyResult(out *[]any, v any) {
	switch vv := v.(type) {
	case nil:
		// drop
	case []any:
		*out = append(*out, vv...)
	default:
		*out = append(*out, vv)
	}
}

// ctyValueToGo converts a fully-evaluated cty.Value into the plain Go types
// used in the resource dict (string/bool/float64, []any, map[string]any). It
// mirrors the scalar handling in getCtyValue's LiteralValueExpr case and
// recurses into collections. Null/unknown values become nil.
func ctyValueToGo(val cty.Value) any {
	if val.IsNull() || !val.IsKnown() {
		return nil
	}

	ty := val.Type()
	switch {
	case ty == cty.String:
		return val.AsString()
	case ty == cty.Bool:
		return val.True()
	case ty == cty.Number:
		f, _ := val.AsBigFloat().Float64()
		return f
	case ty.IsListType() || ty.IsSetType() || ty.IsTupleType():
		res := []any{}
		for it := val.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			res = append(res, ctyValueToGo(ev))
		}
		return res
	case ty.IsMapType() || ty.IsObjectType():
		res := map[string]any{}
		for it := val.ElementIterator(); it.Next(); {
			ek, ev := it.Element()
			res[ek.AsString()] = ctyValueToGo(ev)
		}
		return res
	default:
		log.Warn().Msgf("unknown cty type %s", ty.GoString())
		return nil
	}
}

func getCtyValue(expr hcl.Expression, ctx *hcl.EvalContext) any {
	switch t := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		results := []any{}
		for _, expr := range t.Exprs {
			res := getCtyValue(expr, ctx)
			switch v := res.(type) {
			case []any:
				results = append(results, v...)
			default:
				results = append(results, v)
			}
		}
		return results
	case *hclsyntax.ScopeTraversalExpr:
		// When the eval context carries resolved var.*/local.* values, resolve
		// the traversal to its effective value. If it can't be resolved (no
		// such variable/local, data/resource references, …), fall back to
		// surfacing the reference as a dotted string below.
		if ctx != nil && len(ctx.Variables) > 0 {
			if val, diags := t.Value(ctx); !diags.HasErrors() {
				return ctyValueToGo(val)
			}
		}
		traversal := t.Variables()
		res := []string{}
		for i := range traversal {
			tr := traversal[i]
			for j := range tr {
				switch v := tr[j].(type) {
				case hcl.TraverseRoot:
					res = append(res, v.Name)
				case hcl.TraverseAttr:
					res = append(res, v.Name)
				}
			}
		}
		// TODO: are we sure we want to do this?
		return strings.Join(res, ".")
	case *hclsyntax.FunctionCallExpr:
		results := []any{}
		subVal, err := t.Value(ctx)
		if err == nil && subVal.Type() == cty.String {
			if t.Name == "jsonencode" {
				// Decode into `any` so both a JSON object (`jsonencode({...})`)
				// and a JSON array (`jsonencode([...])`) resolve. Unmarshalling
				// into a map[string]any silently failed for a top-level array,
				// leaving the argument empty so a check iterating the encoded
				// list saw nothing and passed vacuously. appendCtyResult keeps
				// the object case list-wrapped while flattening a decoded list
				// into the result so it stays iterable.
				var res any
				if err := json.Unmarshal([]byte(subVal.AsString()), &res); err == nil {
					appendCtyResult(&results, res)
				}
			} else {
				results = append(results, subVal.AsString())
			}
		}
		return results
	case *hclsyntax.ConditionalExpr:
		// When the whole ternary resolves to a concrete value (the condition
		// and chosen branch are statically knowable, e.g. `var.x ? a : b` with
		// var defaults in ctx), return that value. The previous fast path only
		// accepted a string result, so a bool/number ternary — the natural
		// output of `... ? true : false` — fell through to reference-surfacing
		// and returned the branch list `[cond, true, false]` instead of the
		// scalar, defeating a `!= true` scalar-equality check.
		if subVal, diags := t.Value(ctx); !diags.HasErrors() && subVal.IsKnown() && !subVal.IsNull() {
			return ctyValueToGo(subVal)
		}
		// Unbound variables/refs: surface the references in each branch so
		// policies can still inspect what the conditional depends on.
		results := []any{}
		appendCtyResult(&results, getCtyValue(t.Condition, ctx))
		appendCtyResult(&results, getCtyValue(t.TrueResult, ctx))
		appendCtyResult(&results, getCtyValue(t.FalseResult, ctx))
		return results
	case *hclsyntax.ForExpr:
		results := []any{}
		appendCtyResult(&results, getCtyValue(t.CollExpr, ctx))
		if t.KeyExpr != nil {
			appendCtyResult(&results, getCtyValue(t.KeyExpr, ctx))
		}
		appendCtyResult(&results, getCtyValue(t.ValExpr, ctx))
		if t.CondExpr != nil {
			appendCtyResult(&results, getCtyValue(t.CondExpr, ctx))
		}
		return results
	case *hclsyntax.IndexExpr:
		results := []any{}
		appendCtyResult(&results, getCtyValue(t.Collection, ctx))
		appendCtyResult(&results, getCtyValue(t.Key, ctx))
		return results
	case *hclsyntax.BinaryOpExpr:
		results := []any{}
		appendCtyResult(&results, getCtyValue(t.LHS, ctx))
		appendCtyResult(&results, getCtyValue(t.RHS, ctx))
		return results
	case *hclsyntax.UnaryOpExpr:
		// `-1` and `!true` parse as a unary op wrapping a literal. Evaluate the
		// whole expression so the operator is actually applied — a bare descent
		// into t.Val drops the negation and surfaces the positive magnitude
		// (e.g. the `-1` sentinel becoming `1`). Fall back to the operand's
		// references when it can't be evaluated statically (e.g. `-var.x`).
		if val, diags := t.Value(ctx); !diags.HasErrors() {
			return ctyValueToGo(val)
		}
		return getCtyValue(t.Val, ctx)
	case *hclsyntax.SplatExpr:
		results := []any{}
		appendCtyResult(&results, getCtyValue(t.Source, ctx))
		appendCtyResult(&results, getCtyValue(t.Each, ctx))
		return results
	case *hclsyntax.RelativeTraversalExpr:
		// `(source).a.b` — append attribute names from the traversal to the
		// source. Indexes are dropped, mirroring the existing
		// ScopeTraversalExpr handling. When the source resolves to a single
		// string ref (the common case, e.g. parenthesized scope traversal),
		// produce a dotted ref; otherwise flatten into a list so we don't
		// drop refs from a more complex source like an IndexExpr.
		source := getCtyValue(t.Source, ctx)
		pathParts := []string{}
		for _, step := range t.Traversal {
			if attr, ok := step.(hcl.TraverseAttr); ok {
				pathParts = append(pathParts, attr.Name)
			}
		}
		pathSuffix := strings.Join(pathParts, ".")
		switch s := source.(type) {
		case string:
			if pathSuffix != "" {
				return s + "." + pathSuffix
			}
			return s
		case []any:
			results := append([]any{}, s...)
			if pathSuffix != "" {
				results = append(results, pathSuffix)
			}
			return results
		case nil:
			if pathSuffix != "" {
				return pathSuffix
			}
			return nil
		default:
			return source
		}
	case *hclsyntax.TemplateJoinExpr:
		return getCtyValue(t.Tuple, ctx)
	case *hclsyntax.AnonSymbolExpr:
		// Placeholder for the iteration variable inside splat/for bodies —
		// no static value to surface.
		return nil
	case *hclsyntax.LiteralValueExpr:
		switch t.Val.Type() {
		case cty.String:
			return t.Val.AsString()
		case cty.Bool:
			return t.Val.True()
		case cty.Number:
			f, _ := t.Val.AsBigFloat().Float64()
			return f
		default:
			log.Warn().Msgf("unknown literal type %s", t.Val.Type().GoString())
			return nil
		}
	case *hclsyntax.TemplateExpr:
		// walk the parts of the expression to ensure that it has a literal value

		// When the eval context carries resolved var.*/local.* values, a fully
		// interpolated template (e.g. "app-${var.env}-bucket") can collapse to a
		// single string. Attempt that first; otherwise fall back to surfacing the
		// individual parts/references below (the historical behavior when off).
		if ctx != nil && len(ctx.Variables) > 0 {
			if subVal, diags := t.Value(ctx); !diags.HasErrors() && subVal.Type() == cty.String {
				return subVal.AsString()
			}
		}

		if len(t.Parts) == 1 {
			return getCtyValue(t.Parts[0], ctx)
		}

		results := []any{}
		for _, p := range t.Parts {
			res := getCtyValue(p, ctx)
			switch v := res.(type) {
			case []any:
				results = append(results, v...)
			default:
				results = append(results, v)
			}
		}
		return results
	case *hclsyntax.TemplateWrapExpr:
		results := []any{}
		res := getCtyValue(t.Wrapped, ctx)
		switch v := res.(type) {
		case []any:
			results = append(results, v...)
		default:
			results = append(results, v)
		}
		return results
	case *hclsyntax.ObjectConsExpr:
		result := map[string]any{}
		for _, o := range t.Items {
			key := getCtyValue(o.KeyExpr, ctx)
			value := getCtyValue(o.ValueExpr, ctx)
			keyString := GetKeyString(key)
			result[keyString] = value
		}
		return result
	case *hclsyntax.ObjectConsKeyExpr:
		res := getCtyValue(t.Wrapped, ctx)
		return res
	case *hclsyntax.ParenthesesExpr:
		v := getCtyValue(t.Expression, ctx)
		return v
	default:
		log.Warn().Msgf("unknown type %T", t)
		return nil
	}
}

func getReferences(expr hcl.Expression, ctx *hcl.EvalContext) []string {
	switch t := expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		traversal := t.Variables()
		res := []string{}
		for i := range traversal {
			tr := traversal[i]
			for j := range tr {
				switch v := tr[j].(type) {
				case hcl.TraverseRoot:
					res = append(res, v.Name)
				case hcl.TraverseAttr:
					res = append(res, v.Name)
				}
			}
		}
		return res
	default:
		return nil
	}
}

func GetKeyString(key any) string {
	switch v := key.(type) {
	case []string:
		return strings.Join(v, ",")
	case []any:
		var sb strings.Builder
		for i := range v {
			sb.WriteString(keyScalarToString(v[i]))
		}
		return sb.String()
	default:
		return keyScalarToString(key)
	}
}

// keyScalarToString renders an evaluated object key as the string Terraform
// itself would use for a map key. Object keys resolve to whatever type the key
// expression evaluates to: with variable resolution active a `{ (var.x) = ... }`
// key can be a number/bool/null, and a bareword numeric key like `{ 8080 = ... }`
// always evaluates to a number. A bare `key.(string)` assertion on any of those
// panics, and because query blocks run in goroutines that panic crashes the
// entire scan rather than one query. Stringify each scalar kind explicitly and
// treat null/unknown keys as empty.
func keyScalarToString(key any) string {
	switch k := key.(type) {
	case string:
		return k
	case bool:
		return strconv.FormatBool(k)
	case float64:
		return strconv.FormatFloat(k, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(k, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(k)
	}
}

func (g *mqlTerraformBlock) blocks() ([]any, error) {
	var hclBlock *hcl.Block
	if g.block.State == plugin.StateIsSet {
		hclBlock = g.block.Data
	} else {
		if g.block.Error != nil {
			return nil, g.block.Error
		}
		return nil, errors.New("cannot get hcl block")
	}

	var hclFile *hcl.File
	if g.cachedFile.State == plugin.StateIsSet {
		hclFile = g.cachedFile.Data
	}

	if hclFile == nil {
		return nil, errors.New("cannot get hcl file")
	}

	return listHclBlocks(g.MqlRuntime, hclBlock.Body, hclFile)
}

func listHclBlocks(runtime *plugin.Runtime, rawBody any, file *hcl.File) ([]any, error) {
	var mqlHclBlocks []any

	switch body := rawBody.(type) {
	case *hclsyntax.Body:
		ctx := runtimeEvalContext(runtime)
		for i := range body.Blocks {
			for _, hb := range normalizeHclSyntaxBlock(body.Blocks[i], ctx) {
				mqlBlock, err := newMqlHclBlock(runtime, hb.block, file, hb.iterVars)
				if err != nil {
					return nil, err
				}
				mqlHclBlocks = append(mqlHclBlocks, mqlBlock)
			}
		}
	case hcl.Body:
		// Native-syntax .tf files (where `dynamic "x" {}` blocks are written)
		// always parse to *hclsyntax.Body above, so normalizeHclSyntaxBlock only
		// needs to run there. This branch handles JSON-syntax HCL and plan/state
		// bodies, which do not carry native `dynamic` blocks (JSON encodes them
		// differently and PartialContent's typed schema would not surface them),
		// so no normalization is applied here.
		content, _, _ := body.PartialContent(connection.TerraformSchema_1)
		for i := range content.Blocks {
			mqlBlock, err := newMqlHclBlock(runtime, content.Blocks[i], file, nil)
			if err != nil {
				return nil, err
			}
			mqlHclBlocks = append(mqlHclBlocks, mqlBlock)
		}
	default:
		return nil, errors.New("unsupported hcl block type")
	}

	return mqlHclBlocks, nil
}

// expandedBlock is a block ready to surface to MQL, together with any extra
// variables its attribute expressions need in scope. iterVars is empty for an
// ordinary block and carries the `dynamic` iterator binding for a generated one.
type expandedBlock struct {
	block    *hcl.Block
	iterVars map[string]cty.Value
}

// runtimeEvalContext is the variable-resolution context for a runtime, matching
// what mqlTerraformBlock.evalContext returns for an ordinary block. Block
// listing needs it before any block resource exists, to evaluate for_each.
func runtimeEvalContext(runtime *plugin.Runtime) *hcl.EvalContext {
	conn, ok := runtime.Connection.(*connection.Connection)
	if !ok || conn == nil {
		return nil
	}
	return conn.VariableEvalContext()
}

// withIterVars returns ctx extended with a dynamic block's iterator binding,
// leaving ctx itself untouched. It returns ctx unchanged when there is nothing
// to bind.
func withIterVars(ctx *hcl.EvalContext, iterVars map[string]cty.Value) *hcl.EvalContext {
	if len(iterVars) == 0 {
		return ctx
	}
	child := &hcl.EvalContext{Variables: map[string]cty.Value{}}
	if ctx != nil {
		child = ctx.NewChild()
		child.Variables = map[string]cty.Value{}
	}
	for k, v := range iterVars {
		child.Variables[k] = v
	}
	return child
}

// normalizeHclSyntaxBlock expands a `dynamic "X"` block into the `content { ... }`
// sub-blocks it generates, retyped as `X`, so `blocks.where(type == "X")` sees
// them the same as a statically written `X { ... }` block. A dynamic block's
// real fields live one level deeper inside `content`, and the block itself
// parses as type=="dynamic"/nameLabel=="X" — without this normalization every
// block-iterating check is blind to the (extremely common) dynamic form, so a
// violation-detection check passes vacuously and a presence check false-fails.
//
// The content is also emitted once per `for_each` element, with the iterator
// (`X.key` / `X.value`, or the name given by an `iterator` argument) bound to
// that element. Retyping the block alone is not enough: content bodies almost
// always reference the iterator, as in `cidr_blocks = [ingress.value]`, and an
// unresolved reference makes every value-matching predicate miss. A check like
// blocks.where(type == "ingress" && arguments.source == "0.0.0.0/0") then
// selects nothing and its .none()/.all() passes vacuously, so a genuinely open
// rule written in the dynamic form scores compliant.
//
// When for_each cannot be evaluated statically (an unknown var, a data source)
// the block is emitted once with no binding, which is the prior behaviour: the
// structure is still visible even though the values are not. Any non-dynamic
// block is returned unchanged, and a malformed dynamic block with no `content`
// sub-block falls back to itself rather than being dropped.
func normalizeHclSyntaxBlock(block *hclsyntax.Block, ctx *hcl.EvalContext) []expandedBlock {
	if block.Type != "dynamic" || len(block.Labels) != 1 {
		return []expandedBlock{{block: block.AsHCLBlock()}}
	}

	var contents []*hcl.Block
	for _, inner := range block.Body.Blocks {
		if inner.Type != "content" {
			continue
		}
		hb := inner.AsHCLBlock()
		hb.Type = block.Labels[0]
		hb.Labels = nil
		contents = append(contents, hb)
	}
	if len(contents) == 0 {
		return []expandedBlock{{block: block.AsHCLBlock()}}
	}

	bindings := dynamicIteratorBindings(block, ctx)
	if len(bindings) == 0 {
		out := make([]expandedBlock, 0, len(contents))
		for _, c := range contents {
			out = append(out, expandedBlock{block: c})
		}
		return out
	}

	out := make([]expandedBlock, 0, len(contents)*len(bindings))
	for _, c := range contents {
		for _, b := range bindings {
			out = append(out, expandedBlock{block: c, iterVars: b})
		}
	}
	return out
}

// dynamicIteratorBindings evaluates a dynamic block's for_each and returns one
// iterator binding per element. It returns nil when for_each is absent or not
// statically resolvable, in which case the caller emits the content once
// unbound.
func dynamicIteratorBindings(block *hclsyntax.Block, ctx *hcl.EvalContext) []map[string]cty.Value {
	forEach, ok := block.Body.Attributes["for_each"]
	if !ok {
		return nil
	}
	val, diags := forEach.Expr.Value(ctx)
	if diags.HasErrors() || val.IsNull() || !val.IsKnown() || !val.CanIterateElements() {
		return nil
	}

	// The iterator defaults to the block's label and can be renamed with
	// `iterator = other`, which parses as a naked keyword rather than a string.
	name := block.Labels[0]
	if it, ok := block.Body.Attributes["iterator"]; ok {
		if kw := hcl.ExprAsKeyword(it.Expr); kw != "" {
			name = kw
		}
	}

	var out []map[string]cty.Value
	for it := val.ElementIterator(); it.Next(); {
		k, v := it.Element()
		out = append(out, map[string]cty.Value{
			name: cty.ObjectVal(map[string]cty.Value{"key": k, "value": v}),
		})
	}
	return out
}

func (g *mqlTerraformBlock) related() ([]any, error) {
	// The related-block graph is built once by the terraform singleton's
	// ensureCache; look this block up in it.
	o, err := CreateResource(g.MqlRuntime, "terraform", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	terraform := o.(*mqlTerraform)
	if err := terraform.ensureCache(); err != nil {
		return nil, err
	}

	terraform.lock.Lock()
	defer terraform.lock.Unlock()
	related := terraform.relatedBlocks[g.terraformID()]
	res := make([]any, len(related))
	for i := range related {
		res[i] = related[i]
	}
	return res, nil
}

func newFilePosRange(runtime *plugin.Runtime, r hcl.Range) (plugin.Resource, plugin.Resource, error) {
	start, err := CreateResource(runtime, "terraform.fileposition", map[string]*llx.RawData{
		"path":   llx.StringData(r.Filename),
		"line":   llx.IntData(int64(r.Start.Line)),
		"column": llx.IntData(int64(r.Start.Column)),
		"byte":   llx.IntData(int64(r.Start.Byte)),
	})
	if err != nil {
		return nil, nil, err
	}

	end, err := CreateResource(runtime, "terraform.fileposition", map[string]*llx.RawData{
		"path":   llx.StringData(r.Filename),
		"line":   llx.IntData(int64(r.End.Line)),
		"column": llx.IntData(int64(r.End.Column)),
		"byte":   llx.IntData(int64(r.End.Byte)),
	})
	if err != nil {
		return nil, nil, err
	}

	return start, end, nil
}

func (t *mqlTerraformFileposition) id() (string, error) {
	path := t.Path.Data
	line := t.Line.Data
	column := t.Column.Data
	return "file.position/" + path + "/" + strconv.FormatInt(line, 10) + "/" + strconv.FormatInt(column, 10), nil
}

func (t *mqlTerraformFile) id() (string, error) {
	p := t.Path.Data
	return "terraform.file/" + p, nil
}

func (t *mqlTerraformFile) blocks() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)
	p := t.Path.Data

	// plan and state assets have no HCL parser; there are no blocks to list.
	parser := conn.Parser()
	if parser == nil {
		return []any{}, nil
	}

	files := parser.Files()
	file, ok := files[p]
	if !ok || file == nil {
		// The requested path isn't a parsed HCL file (unknown path, .tf.json,
		// or case mismatch); there are no blocks to list rather than a panic.
		return []any{}, nil
	}
	return listHclBlocks(t.MqlRuntime, file.Body, file)
}

func (t *mqlTerraformModule) id() (string, error) {
	// FIXME: Do we need to check .Error first?
	k := t.Key.Data
	v := t.Version.Data
	return "terraform.module/key/" + k + "/version/" + v, nil
}

func (t *mqlTerraformModule) block() (*mqlTerraformBlock, error) {
	key := t.Key.Data
	conn := t.MqlRuntime.Connection.(*connection.Connection)

	// plan and state assets have no HCL parser; there is no backing block.
	parser := conn.Parser()
	if parser == nil {
		t.Block.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	files := parser.Files()

	var mqlHclBlock *mqlTerraformBlock
	for k := range files {
		f := files[k]
		blocks, err := listHclBlocks(t.MqlRuntime, f.Body, f)
		if err != nil {
			return nil, err
		}

		for i := range blocks {
			b := blocks[i].(*mqlTerraformBlock)
			blockType := b.Type.Data
			namedlabel := b.NameLabel.Data

			if blockType == "module" && namedlabel == key {
				mqlHclBlock = b
			}
		}
	}

	if mqlHclBlock == nil {
		t.Block.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	return mqlHclBlock, nil
}

func initTerraformSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	o, err := CreateResource(runtime, "terraform", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	terraform := o.(*mqlTerraform)
	if err := terraform.ensureCache(); err != nil {
		return nil, nil, err
	}

	terraform.lock.Lock()
	blocks := make([]*mqlTerraformBlock, len(terraform.terraformBlocks))
	copy(blocks, terraform.terraformBlocks)
	terraform.lock.Unlock()
	if len(blocks) == 0 {
		// no terraform settings block found, this is ok for terraform and not an error
		// TODO: return modified arguments to load from recording
		return nil, &mqlTerraformSettings{
			Block:             plugin.TValue[*mqlTerraformBlock]{State: plugin.StateIsSet | plugin.StateIsNull},
			RequiredProviders: plugin.TValue[[]any]{State: plugin.StateIsSet, Data: []any{}},
			Backend:           plugin.TValue[any]{State: plugin.StateIsSet, Data: []any{}},
		}, nil
	}

	// The block `terraform {}` can be defined multiple times but we don't support that yet,
	// we will point to the first block and collect all the settings from all blocks to give
	// as much information as possible back
	args["block"] = llx.ResourceData(blocks[0], "terraform.block")
	requiredProviders := []any{}
	args["backend"] = llx.DictData(map[string]any{})

	for _, settingsBlock := range blocks {
		if settingsBlock.block.State == plugin.StateIsSet {
			hb := settingsBlock.block.Data
			requireProviderBlock := getBlockByName(hb, "required_providers")
			if requireProviderBlock != nil {
				attributes, _ := requireProviderBlock.Body.JustAttributes()
				dict, err := hclResolvedAttributesToDict(attributes, nil)
				if err != nil {
					return nil, nil, err
				}
				for name, val := range dict {
					source := ""
					version := ""
					if m, ok := val.(map[string]any); ok {
						if s, ok := m["source"].(string); ok {
							source = s
						}
						if v, ok := m["version"].(string); ok {
							version = v
						}
					} else if v, ok := val.(string); ok {
						// Shorthand syntax: aws = "~> 3.74"
						version = v
					}
					r, err := CreateResource(runtime, "terraform.settings.requiredProvider",
						map[string]*llx.RawData{
							"name":    llx.StringData(name),
							"source":  llx.StringData(source),
							"version": llx.StringData(version),
						},
					)
					if err != nil {
						return nil, nil, err
					}
					requiredProviders = append(requiredProviders, r)
				}
			}

			backendBlock := getBlockByName(hb, "backend")
			if backendBlock != nil {
				attributes, _ := backendBlock.Body.JustAttributes()
				dict, err := hclResolvedAttributesToDict(attributes, nil)
				if err != nil {
					return nil, nil, err
				}
				if len(backendBlock.Labels) != 0 {
					dict["type"] = backendBlock.Labels[0]
				}
				args["backend"] = llx.DictData(dict)
			}
		}
	}

	args["requiredProviders"] = llx.ArrayData(requiredProviders, types.Resource("terraform.settings.requiredProvider"))
	return args, nil, nil
}

func (r *mqlTerraformSettingsRequiredProvider) id() (string, error) {
	return "terraform.settings.requiredProvider/" + r.Name.Data, nil
}

func getBlockByName(hb *hcl.Block, name string) *hcl.Block {
	rawBody := hb.Body
	switch body := rawBody.(type) {
	case *hclsyntax.Body:
		for i := range body.Blocks {
			b := body.Blocks[i].AsHCLBlock()
			if b.Type == name {
				return b
			}
		}
	case hcl.Body:
		// Native-syntax .tf files (where `dynamic "x" {}` blocks are written)
		// always parse to *hclsyntax.Body above, so normalizeHclSyntaxBlock only
		// needs to run there. This branch handles JSON-syntax HCL and plan/state
		// bodies, which do not carry native `dynamic` blocks (JSON encodes them
		// differently and PartialContent's typed schema would not surface them),
		// so no normalization is applied here.
		content, _, _ := body.PartialContent(connection.TerraformSchema_1)
		for i := range content.Blocks {
			b := content.Blocks[i]
			if b.Type == name {
				return b
			}
		}
	}
	return nil
}

// initTerraformBlock provides initialization for terraform.block resource
// to safely handle direct queries without crashing when a block is queried
// without required parameters.
func initTerraformBlock(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Return a direct error instead of a resource with an error
	return args, nil, errors.New("terraform.block cannot be queried directly. Use terraform.blocks(), terraform.resources(), terraform.file(path).blocks(), or other collection methods instead.")
}
