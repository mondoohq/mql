// copyright: 2019, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package lrcore

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"text/scanner"
	"unicode/utf8"

	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
	"go.mondoo.com/mql/types"
)

// Int number type
type Int int64

// Float number type
type Float float64

// Bool for true/false
type Bool bool

// CommentToken captures a comment along with its source position,
// enabling detection of blank-line gaps between comment groups.
type CommentToken struct {
	Pos  lexer.Position
	Text string `@Comment` //nolint:govet // participle grammar tag
}

var CONTEXT_FIELD = "context"

// Capture a Bool type for participle
func (b *Bool) Capture(values []string) error {
	*b = values[0] == "true"
	return nil
}

type Map map[string]string

func (m *Map) Capture(values []string) error {
	if len(values) == 0 {
		return nil
	}

	if *m == nil {
		*m = map[string]string{}
	}
	(*m)[values[0]] = values[2]
	return nil
}

// Alias declares that `Definition` is an alternate name for `Type`.
//
// Source syntax: `alias <Definition> = <Type>` (e.g. `alias os.unix.sshd = sshd`).
//
// The resulting schema contains both keys pointing at the same *ResourceInfo.
// Downstream consumers can detect aliases by comparing the map key in
// Schema.resources against the entry's `id`: when they differ, the entry is
// an alias from the key to `id`. See resources.proto (Schema.resources) for
// the contract.
//
// nolint: govet
type Alias struct {
	Definition SimpleType `@@`
	Type       SimpleType `'=' @@`
}

// Import is a single `import` statement. Three forms are accepted (ADR 042):
//
//	import network                                          // by name
//	import nw1 from "go.mondoo.com/mql/providers/network"    // aliased, by provider ID
//	import "../../network/resources/network.lr"              // legacy, by path
//
// The name form is canonical. The peer is found by name under the providers
// root, so the import no longer has to spell out a filesystem path that only
// ever got reduced back to that name. The aliased form binds a different local
// namespace, for the day two peers share a name; the provider ID it names is
// cross-checked against the peer's own `option provider`.
//
// nolint: govet
type Import struct {
	Path string `"import" ( @String`
	Name string `          | @Ident`
	From string `            [ "from" @(String | Char) ] )`
}

// PackName is the namespace this import binds inside the importing file, i.e.
// the `network` in `[]network.certificate`.
func (i *Import) PackName() string {
	if i.Name != "" {
		return i.Name
	}
	return strings.TrimSuffix(path.Base(i.Path), ".lr")
}

// PeerName is the provider this import resolves to. It differs from PackName
// only in the aliased form, where the local namespace is the alias and the peer
// is the last segment of the declared provider ID.
func (i *Import) PeerName() string {
	if i.From != "" {
		return path.Base(i.From)
	}
	return i.PackName()
}

// LR are MQL resources parsed into an AST
// nolint: govet
type LR struct {
	Comments  []CommentToken `{ @@ }`
	Imports   []*Import      `{ @@ }`
	Options   Map            `{ "option" @(Ident '=' String) }`
	Aliases   []Alias        `{ "alias" @@ }`
	Resources []*Resource    `{ @@ }`
	imports   map[string]map[string]struct{}
	// importedMembers maps a peer provider's resource id to the members it
	// exposes, embeds expanded. It is what lets a `@replaced_by` point at
	// another provider's resource - `asset.version` on any rooted provider -
	// and still be checked rather than taken on trust.
	importedMembers map[string]map[string]struct{}
	packPaths       map[string]string
	// packProviders maps an import's pack name to the provider ID that import
	// declares via `option provider`. This is the peer's *runtime* identity and
	// is what Schema.Dependencies must record; packPaths holds its Go package
	// path, which is a build-time concern and not interchangeable.
	packProviders map[string]string
	aliases       map[string]*Resource
}

// Resource in LR
// nolint: govet
type Resource struct {
	Comments    []CommentToken `{ @@ }`
	IsPrivate   bool           `@"private"?`
	IsExtension bool           `@"extend"?`
	ID          string         `@Ident { @'.' @Ident }`
	Defaults    string         ` ( '@' "defaults" '(' @String ')' )? `
	Context     string         ` ( '@' "context" '(' @String ')' )? `
	Maturity    string         ` ( '@' "maturity" '(' @String ')' )? `
	ReplacedBy  string         ` ( '@' "replaced_by" '(' @String ')' )? `
	IsGlobal    bool           ` ( '@' @"global" )? `
	IsRoot      bool           ` ( '@' @"root" )? `
	ListType    *SimplListType `[ '{' [ @@ ]`
	Body        *ResourceDef   `@@ '}' ]`
	title       string
	desc        string
}

// gets the path for the field of the resource, e.g
// for resource A and field B this would be A.B
func (r Resource) GetFieldPaths() []string {
	if r.Body == nil {
		return []string{}
	}

	res := []string{}

	for _, f := range r.Body.Fields {
		if f.BasicField != nil {
			fullyQualifiedAccessor := fmt.Sprintf("%s.%s", r.ID, f.BasicField.ID)
			res = append(res, fullyQualifiedAccessor)
		}
	}
	return res
}

// nolint: govet
type Type struct {
	MapType    *MapType    `( @@ |`
	ListType   *ListType   ` @@ |`
	SimpleType *SimpleType ` @@ )`
}

// nolint: govet
type SimplListType struct {
	Type SimpleType `'[' ']' @@`
	Args *FieldArgs `[ '(' @@ ')' ]`
}

// nolint: govet
type ListType struct {
	Type Type `'[' ']' @@`
}

// nolint: govet
type MapType struct {
	Key   SimpleType `'map' '[' @@ `
	Value Type       `']' @@`
}

// nolint: govet
type SimpleType struct {
	Type string `@Ident { @'.' @Ident }`
	// Root is the type parameter of an `asset<root>` type: the resource that
	// roots the referenced asset's tree, i.e. what may be chained off the
	// value. It is a forward reference, so the named resource does not have to
	// exist in this schema (or in any schema present at build time). Only
	// `asset` accepts it; see validateTypeParameters. See ADR 031.
	Root string `[ '<' @Ident { @'.' @Ident } '>' ]`
}

// ResourceDef carrying the definition of the resource
// nolint: govet
type ResourceDef struct {
	Fields []*Field `{ @@ }`
}

// ResourceDef carrying the definition of the field
// nolint: govet
type Field struct {
	Comments   []CommentToken `{ @@ }`
	Init       *Init          `( @@ `
	Embeddable *Embeddable    `| @@`
	BasicField *BasicField    `| @@ )?`
}

// Init field definition
// nolint: govet
type Init struct {
	Args []TypedArg `'init' '(' @@ { ',' @@ } ')'`
}

// TypedArg is an argument with a type
// nolint: govet
type TypedArg struct {
	ID       string `@Ident`
	Optional bool   `@'?'?`
	Type     Type   ` @@`
}

// Basic field definition of a resource
// nolint: govet
type BasicField struct {
	ID         string     `@Ident?`
	Args       *FieldArgs `[ '(' @@ ')' ]`
	Maturity   string     ` ( '@' "maturity" '(' @String ')' )? `
	ReplacedBy string     ` ( '@' "replaced_by" '(' @String ')' )? `
	Type       Type       `[ @@ ]`
	isEmbedded bool
}

// Field definition of a embeddable field resource
// nolint: govet
type Embeddable struct {
	Type  string  `"embed" @Ident { @'.' @Ident }`
	Alias *string `("as" @Ident)?`
}

// Args list of arguments
// nolint: govet
type FieldArgs struct {
	List []SimpleType `[ @@ { ',' @@ } ]`
}

// LEXER

type lrLexer struct{}

func (l *lrLexer) Lex(r io.Reader) (lexer.Lexer, error) {
	var scannerObj scanner.Scanner
	lexerObj := lexer.LexWithScanner(r, &scannerObj)
	scannerObj.Mode ^= scanner.SkipComments
	return lexerObj, nil
}

func (l *lrLexer) Symbols() map[string]rune {
	return map[string]rune{
		"EOF":       scanner.EOF,
		"Char":      scanner.Char,
		"Ident":     scanner.Ident,
		"Int":       scanner.Int,
		"Float":     scanner.Float,
		"String":    scanner.String,
		"RawString": scanner.RawString,
		"Comment":   scanner.Comment,
	}
}

func (r *Resource) GetInitFields() []*Init {
	inits := []*Init{}
	for _, f := range r.Body.Fields {
		if f.Init != nil {
			inits = append(inits, f.Init)
		}
	}
	return inits
}

func SanitizeComments(raw []CommentToken) []CommentToken {
	todoStart := -1
	for i := range raw {
		if raw[i].Text != "" {
			raw[i].Text = strings.Trim(raw[i].Text[2:], " \t\n")
		}
		if todoStart == -1 && strings.HasPrefix(raw[i].Text, "TODO") {
			todoStart = i
		}
	}
	if todoStart != -1 {
		raw = raw[0:todoStart]
	}
	return raw
}

// lastCommentGroup returns only the final contiguous group of comments,
// splitting on blank-line gaps (non-consecutive source lines). This prevents
// section-separator comment blocks from bleeding into resource/field titles.
func lastCommentGroup(comments []CommentToken) []CommentToken {
	if len(comments) <= 1 {
		return comments
	}
	lastGap := 0
	for i := 1; i < len(comments); i++ {
		if comments[i].Pos.Line != comments[i-1].Pos.Line+1 {
			lastGap = i
		}
	}
	return comments[lastGap:]
}

func extractTitleAndDescription(raw []CommentToken) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	title := raw[0].Text
	// Skip the mandatory blank `//` separator between title and description
	// (enforced by validateDocCommentStructure), so it doesn't show up as a
	// leading space in the joined description.
	rest := raw[1:]
	if len(rest) > 0 && rest[0].Text == "" {
		rest = rest[1:]
	}
	parts := make([]string, len(rest))
	for i, c := range rest {
		parts[i] = c.Text
	}
	desc := strings.Join(parts, " ")
	return title, desc
}

// MaxTitleLength caps the rune count of a doc-comment title line. Titles
// render in CLI tables, auto-complete prompts, and the website resource
// docs, where a sprawling title looks bad and wrecks layout. Descriptions
// have no length cap.
const MaxTitleLength = 150

// titleStartsWithDeprecated reports whether a title begins with the word
// "deprecated" (case-insensitive), optionally followed by a colon or other
// non-letter punctuation. Deprecation is expressed via `@maturity` on the
// resource/field, so the title should remain a plain noun phrase.
func titleStartsWithDeprecated(title string) bool {
	t := strings.TrimSpace(title)
	return hasDeprecatedWordPrefix(t)
}

// descriptionStartsWithBadDeprecated reports whether a description starts
// with the word "deprecated" (case-insensitive) in a way that conflicts
// with the convention. The only accepted leading phrases are
// "Deprecated in favor of ..." and "Deprecated, please use ..." — every
// other variant ("Deprecated.", "Deprecated:", "Deprecated and ...", etc.)
// is rejected so deprecation notices read consistently.
func descriptionStartsWithBadDeprecated(desc string) bool {
	d := strings.TrimSpace(desc)
	if !hasDeprecatedWordPrefix(d) {
		return false
	}
	rest := d[len("deprecated"):]
	if hasPrefixFold(rest, " in favor of") {
		return false
	}
	if hasPrefixFold(rest, ", please use") {
		return false
	}
	return true
}

// hasDeprecatedWordPrefix reports whether s begins with the standalone
// word "deprecated" (case-insensitive). It returns false for longer words
// like "deprecation", and true when "deprecated" is followed by EOF or any
// non-letter byte.
func hasDeprecatedWordPrefix(s string) bool {
	const word = "deprecated"
	if len(s) < len(word) {
		return false
	}
	if !strings.EqualFold(s[:len(word)], word) {
		return false
	}
	if len(s) == len(word) {
		return true
	}
	return !isLetter(s[len(word)])
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// validateDocCommentStructure enforces the doc-comment shape for resources
// and fields:
//   - 0 lines: nothing to validate.
//   - 1+ lines: line 1 is the title; it must be at most MaxTitleLength runes.
//   - 2+ lines: line 2 MUST be a blank `//` separator (Text == ""), so the
//     title stays a single line and the description starts cleanly. This
//     prevents accidentally truncated titles when a long one-liner wraps
//     onto two source lines.
//
// `context` is included verbatim in the error to identify the offending
// resource or field (e.g. "resource aws.billing.budget" or
// "field aws.billing.budget.budgetType").
func validateDocCommentStructure(comments []CommentToken, context string) error {
	if len(comments) == 0 {
		return nil
	}

	var errs []error

	if n := utf8.RuneCountInString(comments[0].Text); n > MaxTitleLength {
		errs = append(errs, fmt.Errorf(
			"%s: doc-comment title is %d characters (line %d), max is %d - "+
				"titles render in CLI tables, auto-complete, and the website docs, so keep them short; "+
				"move the rest into the description (a blank `//` followed by the longer text)",
			context, n, comments[0].Pos.Line, MaxTitleLength,
		))
	}

	if titleStartsWithDeprecated(comments[0].Text) {
		errs = append(errs, fmt.Errorf(
			"%s: doc-comment title (line %d) starts with \"deprecated\" - "+
				"deprecation is expressed via `@maturity(\"deprecated\")` on the resource/field, not in the title; "+
				"keep the title as a plain noun phrase and mention the deprecation (and the replacement) in the description",
			context, comments[0].Pos.Line,
		))
	}

	if len(comments) >= 2 && comments[1].Text != "" {
		errs = append(errs, fmt.Errorf(
			"%s: doc-comment has %d lines but is missing the required blank `//` separator after the title (line %d) - "+
				"either collapse the comment to a single line, or insert a blank `//` line between the title and the description",
			context, len(comments), comments[0].Pos.Line,
		))
	}

	_, desc := extractTitleAndDescription(comments)
	if descriptionStartsWithBadDeprecated(desc) {
		errs = append(errs, fmt.Errorf(
			"%s: doc-comment description starts with \"deprecated\" but not in an accepted form - "+
				"only \"Deprecated in favor of ...\" and \"Deprecated, please use ...\" are allowed as the leading phrase; "+
				"rewrite the description so it begins with one of those or leads with the field/resource summary instead",
			context,
		))
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// Parse the input leise string to an AST
func Parse(input string) (*LR, error) {
	res := &LR{}

	var lexer lrLexer
	parser := participle.MustBuild(&LR{},
		participle.Lexer(&lexer),
	)

	err := parser.Parse(strings.NewReader(input), res)

	// clean up the parsed results
	var validationErrs []error
	for i := range res.Resources {
		resource := res.Resources[i]
		resource.Comments = SanitizeComments(resource.Comments)
		resource.Comments = lastCommentGroup(resource.Comments)
		if verr := validateDocCommentStructure(resource.Comments, "resource "+resource.ID); verr != nil {
			validationErrs = append(validationErrs, verr)
		}
		resource.title, resource.desc = extractTitleAndDescription(resource.Comments)
		resource.Comments = nil

		// List types have an implicit list field
		if resource.ListType != nil {
			t := resource.ListType.Type.Type
			args := resource.ListType.Args

			// args of nil tell the compiler that this field needs to be pre-populated
			// however for list we don't have this logic, it is always computed
			if args == nil {
				args = &FieldArgs{}
			}

			field := &BasicField{
				ID:   "list",
				Args: args,
				Type: Type{ListType: &ListType{Type: Type{SimpleType: &SimpleType{Type: t}}}},
			}

			resource.Body.Fields = append(resource.Body.Fields, &Field{BasicField: field})
		}

		if resource.Body == nil {
			continue
		}
		if len(resource.Body.Fields) == 0 {
			continue
		}

		// eliminate fields that are comment-only (no ID)
		arr := resource.Body.Fields
		ptr := len(arr)
		for j := 0; j < ptr; j++ {
			if arr[j].BasicField == nil && arr[j].Embeddable == nil && arr[j].Init == nil {
				arr[j], arr[ptr-1] = arr[ptr-1], arr[j]
				ptr--
			}
		}
		if ptr < len(arr) {
			resource.Body.Fields = arr[:ptr]
		}

		for i, f := range resource.Body.Fields {
			if f.Embeddable == nil {
				continue
			}
			var name string
			if f.Embeddable.Alias != nil {
				name = *f.Embeddable.Alias
			} else {
				// use the first part of the type name as a id, i.e. os for os.any
				// this won't work if there're are multiple embedded resources without aliases that share the same package, i.e os.any and os.base
				name = strings.Split(f.Embeddable.Type, ".")[0]
			}

			if name == CONTEXT_FIELD {
				return nil, errors.New("'" + CONTEXT_FIELD + "' field already exists on resource " + resource.ID)
			}

			newField := &Field{
				Comments: f.Comments,
				BasicField: &BasicField{
					ID:         name,
					Type:       Type{SimpleType: &SimpleType{Type: f.Embeddable.Type}},
					Args:       &FieldArgs{},
					isEmbedded: true,
				},
			}
			resource.Body.Fields[i] = newField
		}

		if resource.Context != "" {
			// Synthetic token: Pos is intentionally zero-value since this comment
			// has no source location. Safe for lastCommentGroup (single-element
			// slice short-circuits before Pos is read).
			resource.Body.Fields = append(resource.Body.Fields, &Field{
				Comments: []CommentToken{{Text: "# Contextual info, where this resource is located and defined"}},
				BasicField: &BasicField{
					ID:         CONTEXT_FIELD,
					Args:       &FieldArgs{},
					Type:       Type{SimpleType: &SimpleType{Type: resource.Context}},
					isEmbedded: false,
				},
			})
		}
	}

	validationErrs = append(validationErrs, res.validateTypeParameters()...)
	validationErrs = append(validationErrs, res.validateAliases()...)
	validationErrs = append(validationErrs, res.validateEmbedAmbiguity()...)
	validationErrs = append(validationErrs, res.validateRootMembers()...)

	if len(validationErrs) > 0 {
		return res, errors.Join(append([]error{err}, validationErrs...)...)
	}
	return res, err
}

// validateTypeParameters rejects a `<root>` parameter on any type but `asset`.
// The grammar accepts it anywhere a type appears, because participle has no way
// to make the group conditional on the type name; without this check
// `name<mcp> string` would parse and then silently drop the parameter.
func (lr *LR) validateTypeParameters() []error {
	var errs []error

	var check func(context string, t *Type)
	check = func(context string, t *Type) {
		if t == nil {
			return
		}
		switch {
		case t.SimpleType != nil:
			if t.SimpleType.Root != "" && t.SimpleType.Type != "asset" {
				errs = append(errs, errors.New(context+": only `asset` takes a type parameter, got `"+
					t.SimpleType.Type+"<"+t.SimpleType.Root+">`"))
			}
		case t.ListType != nil:
			// a list of assets is legal: []asset<mcp>
			check(context, &t.ListType.Type)
		case t.MapType != nil:
			if t.MapType.Key.Root != "" {
				errs = append(errs, errors.New(context+": map keys take no type parameter"))
			}
			check(context, &t.MapType.Value)
		}
	}

	for _, resource := range lr.Resources {
		if resource.Body == nil {
			continue
		}
		for _, field := range resource.Body.Fields {
			if field.BasicField == nil {
				continue
			}
			t := field.BasicField.Type
			check("resource "+resource.ID+", field "+field.BasicField.ID, &t)
		}
	}
	return errs
}

// validateAliases rejects an alias name that would silently replace something.
//
// Both the AST's alias map (`resolve.go`) and the schema's resource map
// (`schema.go`) are keyed by the alias name and assigned without a presence
// check, so a repeated name overwrites the earlier entry and a name that
// collides with a declared resource overwrites the resource. Neither says
// anything at build time, and the result is a resource that resolves to
// something other than what the schema reads like. That matters most where
// aliases are generated in bulk, e.g. attaching a provider's surface to its
// asset roots (ADR 031).
func (lr *LR) validateAliases() []error {
	var errs []error

	declared := map[string]bool{}
	for _, r := range lr.Resources {
		if r != nil {
			declared[r.ID] = true
		}
	}

	seen := map[string]bool{}
	for _, a := range lr.Aliases {
		name := a.Definition.Type
		if seen[name] {
			errs = append(errs, errors.New("alias "+name+" is declared more than once; "+
				"the later one silently replaces the earlier"))
			continue
		}
		seen[name] = true

		if declared[name] {
			errs = append(errs, errors.New("alias "+name+" has the same name as a resource; "+
				"the alias silently replaces it"))
		}
	}
	return errs
}

// reservedIdentifiers are the language constructs the compiler answers itself. A
// query is a block on the asset root (ADR 031 point 7) and these are resolved
// without ever consulting it, so a root member carrying one of these names could
// not be read.
//
// This only constrains members of a root; any other resource may use these
// names freely, because nothing binds them implicitly.
var reservedIdentifiers = map[string]struct{}{
	"props": {}, "if": {}, "else": {}, "expect": {}, "switch": {}, "return": {},
	"_": {},
}

// conversionIdentifiers are the type conversions - `version("1.2.3")`,
// `string(x)`. They are NOT reserved against a root member, because the
// compiler already tells them apart by arity: compileTypeConversion returns
// errNotConversion when there are no arguments, and mqlc then "tosses this fish
// back in the sea" and resolves the name as a member of the root. So a device
// with a `version` field answers `mql run arista -c version` with the device's
// version, which is the whole point of having a root - the root is the position
// everything is relative to.
//
// A member that *takes arguments* is the real conflict: the conversion is tried
// first and wins on any call with arguments, leaving that member unreachable.
var conversionIdentifiers = map[string]struct{}{
	"bool": {}, "int": {}, "float": {}, "string": {}, "regex": {},
	"dict": {}, "ip": {}, "semver": {}, "version": {},
}

// validateRootMembers checks the resource named by `option root`, which is what
// every bare identifier resolves against once the root is the namespace.
//
// Two ways a member breaks that: it shadows the language (see
// reservedIdentifiers), or it shadows a *different* global resource. The second
// is what keeps the v14 and v15 namespace precedences agreeing - a member that
// is an alias of the resource of the same name is the normal case and is fine;
// one that means something else under a taken name would change meaning when the
// precedence flips. See ADR 031 point 3.
func (lr *LR) validateRootMembers() []error {
	root, ok := lr.Options["root"]
	if !ok || root == "" {
		return nil
	}

	byID := map[string]*Resource{}
	for _, r := range lr.Resources {
		if r != nil {
			byID[r.ID] = r
		}
	}
	if _, ok := byID[root]; !ok {
		// The root may be declared by a resource this file does not define; the
		// members are then not knowable here.
		return nil
	}

	aliased := map[string]string{}
	for _, a := range lr.Aliases {
		aliased[a.Definition.Type] = a.Type.Type
	}

	var errs []error
	for name, member := range lr.exposedMembers(byID, root, 0) {
		typ := member.typ
		if _, reserved := reservedIdentifiers[name]; reserved {
			errs = append(errs, errors.New("root "+root+" has a member named "+name+
				", which the compiler answers itself; a bare identifier would never reach it"))
			continue
		}
		// A conversion is only a conversion when it is called with arguments, so
		// a plain `version` member reads fine off the root. One that takes
		// arguments does not: the conversion is tried first and wins on any
		// call that has them.
		if _, conversion := conversionIdentifiers[name]; conversion && member.hasArgs {
			errs = append(errs, errors.New("root "+root+" has a member "+name+
				" that takes arguments, but "+name+"(...) is a type conversion; the conversion wins and the member could not be called"))
			continue
		}

		other, exists := byID[name]
		if !exists {
			continue
		}
		// An alias of the resource of the same name is the same thing reached
		// two ways, which is the point of attaching a surface to a root.
		if aliased[root+"."+name] == name {
			continue
		}
		if typ != types.Resource(other.ID) {
			errs = append(errs, errors.New("root "+root+" has a member "+name+" of type "+
				typ.Label()+", but "+name+" is also a resource; a bare `"+name+
				"` would mean different things depending on the namespace"))
		}
	}
	return errs
}

// validateEmbedAmbiguity rejects a resource whose embeds expose the same member
// under conflicting types.
//
// Embedded members are reachable directly on the embedding resource
// (`docker.container.hostname` reads through `os.linux` → `os.unix` → `os.base`),
// so two embeds that both carry a `foo` leave the lookup with two answers. One
// type is fine - the same member reached two ways is still that member - but two
// types is a schema that cannot be compiled against, and it surfaces as a
// confusing type error in whatever query first touches it rather than here.
//
// This is what bounds composing asset roots from mixins (ADR 031): a union root
// may embed several family roots only while their members agree.
func (lr *LR) validateEmbedAmbiguity() []error {
	byID := map[string]*Resource{}
	for _, r := range lr.Resources {
		if r != nil {
			byID[r.ID] = r
		}
	}

	var errs []error
	for _, r := range lr.Resources {
		if r == nil || r.Body == nil {
			continue
		}

		// Parse rewrites every `embed X` into a BasicField carrying isEmbedded,
		// so that - not f.Embeddable - is what an embed looks like by the time
		// validation runs.
		var embeds []string
		for _, f := range r.Body.Fields {
			if f.BasicField != nil && f.BasicField.isEmbedded && f.BasicField.Type.SimpleType != nil {
				embeds = append(embeds, f.BasicField.Type.SimpleType.Type)
			}
		}
		if len(embeds) < 2 {
			continue
		}

		// name -> type, plus which embed contributed it
		types := map[string]types.Type{}
		origin := map[string]string{}
		for _, e := range embeds {
			for name, member := range lr.exposedMembers(byID, e, 0) {
				typ := member.typ
				prev, ok := types[name]
				if ok && prev != typ {
					errs = append(errs, errors.New("resource "+r.ID+" embeds both "+origin[name]+
						" and "+e+", which expose "+name+" with different types ("+
						prev.Label()+" and "+typ.Label()+")"))
					continue
				}
				types[name] = typ
				origin[name] = e
			}
		}
	}
	return errs
}

// exposedMembers returns the members a resource offers by name, following its
// own embeds. An embed of a resource this schema does not define (an imported
// one) contributes nothing, because its members are not knowable here.
// exposedMember is one member a root offers, and whether reading it takes
// arguments. Arity is what decides whether a type conversion of the same name
// shadows it, so it has to travel with the type.
type exposedMember struct {
	typ     types.Type
	hasArgs bool
}

func (lr *LR) exposedMembers(byID map[string]*Resource, id string, depth int) map[string]exposedMember {
	res := map[string]exposedMember{}
	if depth > 10 {
		return res
	}
	r, ok := byID[id]
	if !ok || r.Body == nil {
		return res
	}

	for _, f := range r.Body.Fields {
		if f.BasicField == nil {
			continue
		}
		if f.BasicField.isEmbedded && f.BasicField.Type.SimpleType != nil {
			for name, m := range lr.exposedMembers(byID, f.BasicField.Type.SimpleType.Type, depth+1) {
				res[name] = m
			}
			continue
		}
		res[f.BasicField.ID] = exposedMember{
			typ:     f.BasicField.Type.Type(lr),
			hasArgs: f.BasicField.Args != nil && len(f.BasicField.Args.List) > 0,
		}
	}
	return res
}

// returns duplicate resources where duplicate means that one path leads to more than one field
// causing ambiguity. An example minimal LR that would cause duplicates is:
//
//	A {
//	  B A.B
//	}
//
//	A.B {
//	  value string
//	}
//
// in the case above 'A.B` could be interpreted as accessing the property 'B' of the resource 'A'
// or as accessing the resource 'A.B' directly.
func (lr *LR) GetDuplicates() []string {
	dups := []string{}
	seen := map[string]struct{}{}
	// first populate with the resource names (ids), so we don't have fields that
	// are the same as resource names
	for _, r := range lr.Resources {
		seen[r.ID] = struct{}{}
	}

	for _, r := range lr.Resources {
		fields := r.GetFieldPaths()
		for _, f := range fields {
			if _, ok := seen[f]; ok {
				dups = append(dups, f)
			}
			seen[f] = struct{}{}
		}
	}

	return dups
}
