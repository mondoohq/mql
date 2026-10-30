// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"strconv"
	"strings"
)

// parsedBicepFile holds the result of parsing a .bicep file.
type parsedBicepFile struct {
	targetScope string
	parameters  []parsedParameter
	variables   []parsedVariable
	resources   []parsedResource
	modules     []parsedModule
	outputs     []parsedOutput
	types       []parsedType
	functions   []parsedFunction
	imports     []parsedImport
	metadata    map[string]string
}

type parsedParameter struct {
	name         string
	typ          string
	defaultValue string
	description  string
	secure       bool
	allowed      []string
	minLength    *int64
	maxLength    *int64
	minValue     *int64
	maxValue     *int64
	decorators   []string
	startLine    int
	endLine      int
}

type parsedVariable struct {
	name        string
	expression  string
	description string
	loop        loopInfo
	startLine   int
	endLine     int
}

type parsedResource struct {
	symbolicName string
	typ          string
	apiVersion   string
	name         string
	location     string
	existing     bool
	condition    string
	parent       string
	scope        string
	body         string
	tags         map[string]string
	dependsOn    []string
	decorators   []string
	loop         loopInfo
	nested       []parsedResource
	startLine    int
	endLine      int
}

type parsedModule struct {
	name           string
	source         string
	scope          string
	condition      string
	body           string
	description    string
	isRegistry     bool
	isTemplateSpec bool
	decorators     []string
	loop           loopInfo
	startLine      int
	endLine        int
}

type parsedOutput struct {
	name        string
	typ         string
	expression  string
	description string
	loop        loopInfo
	startLine   int
	endLine     int
}

// loopInfo captures a Bicep `for`-loop on a declaration. Bicep iterates
// resources, modules, outputs, and variables with
// `[for <iterator> in <expression>: <body>]` (or the indexed
// `[for (<iterator>, <indexVar>) in <expression>: <body>]` form). When a
// declaration's value is such a loop, isLoop is true and the iterator,
// optional indexVar, and collection expression are extracted; body holds
// the text after the header colon (the per-iteration object or expression).
type loopInfo struct {
	isLoop     bool
	iterator   string
	indexVar   string
	expression string
	body       string
}

type parsedType struct {
	name        string
	definition  string
	description string
	exported    bool
	decorators  []string

	// kind classifies the definition: "object", "union", "array", "tuple"
	// (folded into "array"), "primitive", or "alias".
	kind string
	// unionMembers holds the literal members of a union type, each kept
	// exactly as written (including quotes). Empty for non-unions.
	unionMembers []string
	// properties holds the name/type pairs of an object type. Empty otherwise.
	properties []parsedTypeProperty
	// discriminator is the key captured from an `@discriminator('<key>')`
	// decorator; empty when no such decorator is present.
	discriminator string
}

// parsedTypeProperty is one `name: type` member of an object-typed declaration.
type parsedTypeProperty struct {
	name string
	typ  string
}

type parsedFunction struct {
	name        string
	parameters  map[string]string
	returnType  string
	expression  string
	description string
	decorators  []string
}

type parsedImport struct {
	source    string
	symbols   []string
	namespace string
	wildcard  bool
}

// decNS is the leading `@` of a decorator plus an optional `sys.` namespace
// qualifier. Bicep exposes every built-in decorator on the `sys` namespace as
// well as bare, and a file must use the qualified form when a user-defined
// symbol shadows the bare name — so both spellings have to match.
const decNS = `@(?:sys\.)?`

var (
	targetScopeRe = regexp.MustCompile(`(?m)^targetScope\s*=\s*'([^']+)'`)
	// paramRe captures only the parameter NAME and the remainder of the
	// header. The type cannot be a bare `(\w+)` — Bicep types include literal
	// unions (`'a' | 'b'`), arrays (`string[]`), nullables (`myType?`) and
	// parenthesized forms — so the type and default are separated afterwards
	// with the delimiter-aware splitDeclAtEquals.
	paramRe    = regexp.MustCompile(`(?m)^param\s+(\w+)\s+(\S.*)$`)
	varRe      = regexp.MustCompile(`(?m)^var\s+(\w+)\s*=\s*(.+)$`)
	resourceRe = regexp.MustCompile(`(?m)^(resource)\s+(\w+)\s+'([^']+)'(\s+existing)?\s*=`)
	moduleRe   = regexp.MustCompile(`(?m)^module\s+(\w+)\s+'([^']+)'\s*=`)
	// outputRe captures the output NAME and the remainder of the header, for
	// the same reason as paramRe — `output ids string[] = names` has no bare
	// word before the `=`.
	outputRe = regexp.MustCompile(`(?m)^output\s+(\w+)\s+(\S.*)$`)
	// paramHeaderRe and outputHeaderRe match only the declaration header,
	// anchored to the start of the statement. The value is then taken as the
	// remaining text, which may span lines when it holds a triple-quoted
	// string.
	paramHeaderRe  = regexp.MustCompile(`\Aparam\s+(\w+)\s+`)
	outputHeaderRe = regexp.MustCompile(`\Aoutput\s+(\w+)\s+`)
	// Every built-in decorator may also be written through the `sys`
	// namespace (`@sys.secure()`), which is what Bicep requires when a
	// user-defined symbol shadows the bare name. `decNS` makes that prefix
	// optional everywhere so a namespace-qualified `@sys.secure()` is not
	// silently read as "not secure".
	// The value may contain an escaped quote (`@description('The VM\\'s name')`),
	// so the capture accepts escape pairs. A bare `[^']*` class stopped at the
	// backslash and then failed to anchor, blanking the whole description.
	descDecRe   = regexp.MustCompile(decNS + `description\('((?:[^'\\]|\\.)*)'\)`)
	secureDecRe = regexp.MustCompile(decNS + `secure\(\)`)
	// allowedDecOpenRe locates the decorator; the argument list is then
	// delimited with the string-aware scanner. A `[^\]]*` class stopped at the
	// first `]`, so an allowed value containing one (`'a]b'`) failed the match
	// entirely and the constraint read as absent rather than partial.
	allowedDecOpenRe = regexp.MustCompile(decNS + `allowed\(`)
	minLengthDecRe   = regexp.MustCompile(decNS + `minLength\(\s*(-?\d+)\s*\)`)
	maxLengthDecRe   = regexp.MustCompile(decNS + `maxLength\(\s*(-?\d+)\s*\)`)
	minValueDecRe    = regexp.MustCompile(decNS + `minValue\(\s*(-?\d+)\s*\)`)
	maxValueDecRe    = regexp.MustCompile(decNS + `maxValue\(\s*(-?\d+)\s*\)`)
	exportDecRe      = regexp.MustCompile(decNS + `export\(\)`)

	// discriminatorDecRe captures the key argument of an
	// `@discriminator('<key>')` decorator on a tagged-union type.
	discriminatorDecRe = regexp.MustCompile(decNS + `discriminator\(\s*'([^']*)'\s*\)`)

	// typeRe matches the header of a `type Name = <definition>` statement.
	// The definition (everything after the first `=`) is captured raw;
	// unions, object types, and references all flow through as text.
	typeRe = regexp.MustCompile(`(?s)^type\s+(\w+)\s*=\s*(.+)$`)

	// funcHeadRe matches just the `func name(` prefix of a function
	// declaration. The parameter list, return type, and body are split out
	// with depth-aware scanning rather than a single regex, so object-typed
	// parameters (`opts { name: string }`, which contain `)`/`,`/`{}`) and
	// array/object return types (`string[]`, `{ a: int }`) parse correctly.
	funcHeadRe = regexp.MustCompile(`(?s)^func\s+(\w+)\s*\(`)

	// metadataRe matches a `metadata <name> = '<literal>'` entry. Only
	// literal single-quoted values are captured; expression-/object-valued
	// metadata is skipped (mirrors the tag-extraction behavior).
	metadataRe = regexp.MustCompile(`(?m)^metadata\s+(\w+)\s*=\s*'([^']*)'\s*$`)

	// usingRe matches the `using '<target>'` statement at the head of a
	// `.bicepparam` file. The target is the referenced template
	// ('./main.bicep', 'none', or a registry/template-spec ref like 'br:...').
	usingRe = regexp.MustCompile(`(?m)^\s*using\s+'([^']*)'`)

	// paramAssignRe matches a `.bicepparam` parameter assignment
	// `param <name> = <value>`. Unlike a `.bicep` `param` declaration there
	// is no type between the name and `=`, so this deliberately does not reuse
	// paramRe. The right-hand side is captured raw (everything after `=`).
	paramAssignRe = regexp.MustCompile(`^param\s+(\w+)\s*=\s*(.+)$`)
)

// parseBicepParam parses a `.bicepparam` parameter file into the `using`
// target and a name->value map. The right-hand-side value text is stored
// EXACTLY as written, NOT quote-stripped: a literal stays quoted
// (`'Standard_LRS'`) and an expression stays bare
// (`resourceGroup().location`, `readEnvironmentVariable('ADMIN_PW')`). This
// preserves the literal-vs-expression distinction audits care about, and
// intentionally differs from `bicep.parameter.defaultValue`, which strips
// quotes.
//
// The tokenizer keys off the leading keyword of each statement, so `using`
// and `param` assignments are dispatched the same brace/string-aware way as
// `.bicep` constructs; multi-line object/array values are reassembled into a
// single collapsed-whitespace value.
func parseBicepParam(content string) (string, map[string]string) {
	// `.bicepparam` files take the same comment syntax as `.bicep`.
	content = stripBlockComments(content)

	var using string
	if m := usingRe.FindStringSubmatch(content); len(m) > 1 {
		using = m[1]
	}

	params := map[string]string{}
	for _, stmt := range tokenizeBicep(content) {
		if stmt.keyword != "param" {
			continue
		}
		stmtLines := strings.Split(stmt.text, "\n")
		// Reassemble multi-line values (object/array RHS) into one line with
		// runs of whitespace collapsed, mirroring parseVariableDecl.
		combined := strings.Join(strings.Fields(strings.Join(stmtLines, " ")), " ")
		m := paramAssignRe.FindStringSubmatch(strings.TrimSpace(combined))
		if len(m) < 3 {
			continue
		}
		params[m[1]] = strings.TrimSpace(m[2])
	}

	return using, params
}

func parseBicep(content string) *parsedBicepFile {
	result := &parsedBicepFile{}

	// Blank out `/*…*/` comments before anything reads the source. Offsets and
	// line numbers are preserved, so this is invisible to every consumer other
	// than removing content that isn't part of the deployment.
	content = stripBlockComments(content)

	// Target scope
	if m := targetScopeRe.FindStringSubmatch(content); len(m) > 1 {
		result.targetScope = m[1]
	}

	// Walk the file once into brace/bracket/string-aware statements, then
	// dispatch each one to the construct-specific parser. Each statement's
	// `text` is a guaranteed-complete construct (its delimiters balance), so
	// the per-construct helpers receive the whole body rather than re-walking
	// the raw line slice.
	for _, stmt := range tokenizeBicep(content) {
		// The Decl helpers still operate on a line slice indexed from the
		// start of the statement. Because `stmt.text` is already a complete
		// construct, splitting it and starting at index 0 yields exactly the
		// lines the helper would have seen in the old line-walking loop.
		stmtLines := strings.Split(stmt.text, "\n")
		firstLine := strings.TrimSpace(stmtLines[0])

		// startLine/endLine bound the statement's source span (1-based); the
		// tokenizer records the start and stmt.text carries every line, so the
		// end is the start plus the additional lines.
		startLine := stmt.startLine
		endLine := stmt.startLine + len(stmtLines) - 1

		switch stmt.keyword {
		case "param":
			// Reassemble multi-line param statements (an object/array default
			// spans lines) into a single line so paramRe's `(.*)$` sees the
			// whole default instead of just the opening `{`/`[`. Inline
			// comments are stripped string-aware so a trailing `// ...` doesn't
			// leak into the default value.
			if p, ok := parseParameter(reassembleParamStatement(stmtLines), stmt.decorators); ok {
				p.startLine, p.endLine = startLine, endLine
				result.parameters = append(result.parameters, p)
			}
		case "var":
			v, _ := parseVariableDecl(stmtLines, 0, stmt.decorators)
			v.startLine, v.endLine = startLine, endLine
			result.variables = append(result.variables, v)
		case "resource":
			if res, _ := parseResourceDecl(stmtLines, 0, stmt.decorators); res != nil {
				res.startLine, res.endLine = startLine, endLine
				result.resources = append(result.resources, *res)
			}
		case "module":
			if mod, _ := parseModuleDecl(stmtLines, 0, stmt.decorators); mod != nil {
				mod.startLine, mod.endLine = startLine, endLine
				result.modules = append(result.modules, *mod)
			}
		case "output":
			// Reassemble multi-line output values (a looped output's
			// `[for ... : ...]` spans lines) into a single collapsed-whitespace
			// line so the value regex and loop detector see the whole RHS. A
			// value holding a triple-quoted string keeps its newlines instead:
			// collapsing them would rewrite the string's contents.
			outLine := firstLine
			if len(stmtLines) > 1 {
				if containsMultilineString(stmt.text) {
					outLine = stmt.text
				} else {
					outLine = strings.Join(strings.Fields(strings.Join(stmtLines, " ")), " ")
				}
			}
			if o, ok := parseOutput(outLine, stmt.decorators); ok {
				o.startLine, o.endLine = startLine, endLine
				result.outputs = append(result.outputs, o)
			}
		case "type":
			if t, ok := parseTypeDecl(stmt.text, stmt.decorators); ok {
				result.types = append(result.types, t)
			}
		case "func":
			if fn, ok := parseFunctionDecl(stmt.text, stmt.decorators); ok {
				result.functions = append(result.functions, fn)
			}
		case "import":
			if imp, ok := parseImportDecl(stmt.text); ok {
				result.imports = append(result.imports, imp)
			}
		case "metadata":
			if name, value, ok := parseMetadataDecl(stmt.text); ok {
				if result.metadata == nil {
					result.metadata = map[string]string{}
				}
				result.metadata[name] = value
			}
		default:
			// targetScope (already captured above) and unknown leading
			// tokens carry no per-construct parsing here; they are retained
			// as statements purely so the tokenizer never drops a line.
		}
	}

	return result
}

// reassembleParamStatement collapses a (possibly multi-line) param statement
// into the single line parseParameter expects. Each source line has its inline
// `// ...` comment stripped string-aware (so a `//` inside a quoted value such
// as a URL is preserved) and is then joined with a single space. Lines are not
// whitespace-collapsed internally, so a string default like 'hello  world'
// keeps its spacing. A shared scanState is carried across lines so a comment
// marker inside a multi-line triple-quoted string is not stripped.
func reassembleParamStatement(lines []string) string {
	st := scanState{}
	parts := make([]string, 0, len(lines))
	multiline := false
	for _, l := range lines {
		before := st.inMulti
		stripped := stripInlineComment(l, &st)
		if !before && st.inMulti {
			multiline = true
		}
		if multiline {
			// Inside (or after opening) a triple-quoted string the line breaks
			// are part of the value. Trimming and space-joining them would
			// rewrite a multi-line default into a single line, and the earlier
			// line-anchored value regex reported only the opening delimiter.
			parts = append(parts, stripped)
			continue
		}
		parts = append(parts, strings.TrimSpace(stripped))
	}
	if multiline {
		return strings.Join(parts, "\n")
	}
	return strings.Join(parts, " ")
}

// stripInlineComment returns s truncated at a trailing `// ...` line comment,
// honoring string literals via the shared scanState so a `//` inside a string
// (e.g. 'http://example.com') is left intact. st is advanced through s so the
// caller can carry string/multi-line state across successive lines.
func stripInlineComment(s string, st *scanState) string {
	i := 0
	for i < len(s) {
		if st.inStr == 0 && !st.inMulti && s[i] == '/' && i+1 < len(s) && s[i+1] == '/' {
			return s[:i]
		}
		i = st.stepAt(s, i)
	}
	return s
}

// parseParameter parses a `param` declaration. ok is false when the line is not
// a well-formed parameter declaration, in which case the caller must skip it:
// appending a zero-value entry both loses the real declaration and gives every
// husk the same `bicep.parameter:<file>:` cache key, so they alias onto one
// instance.
func parseParameter(line string, decorators []string) (parsedParameter, bool) {
	p := parsedParameter{decorators: decorators}

	// The header is matched separately from the value so that a value holding a
	// triple-quoted string can span lines; paramRe's `.` stops at a newline, so
	// using it for the value truncated a multi-line default to the bare opening
	// delimiter and then reported that fragment as the parameter's value.
	loc := paramHeaderRe.FindStringSubmatchIndex(line)
	if loc == nil {
		return parsedParameter{}, false
	}

	p.name = line[loc[2]:loc[3]]
	rest := strings.TrimSpace(line[loc[1]:])
	if rest == "" {
		return parsedParameter{}, false
	}
	if typ, def, hasDefault := splitDeclAtEquals(rest); hasDefault {
		p.typ = typ
		// Strip the delimiters only when the whole default is one string
		// literal. A value that merely begins and ends with a quote, such as
		// `'prod' == env ? 'Premium' : 'Standard'`, is an expression, and removing
		// its outer quotes corrupted it into an unbalanced string.
		if isSingleQuotedLiteral(def) {
			def = def[1 : len(def)-1]
		}
		p.defaultValue = def
	} else {
		p.typ = rest
	}
	if p.typ == "" {
		return parsedParameter{}, false
	}

	decText := strings.Join(decorators, "\n")
	if m := descDecRe.FindStringSubmatch(decText); len(m) > 1 {
		p.description = m[1]
	}
	p.secure = secureDecRe.MatchString(decText)
	p.allowed = extractAllowedValues(decText)
	p.minLength = parseIntDecorator(decText, minLengthDecRe)
	p.maxLength = parseIntDecorator(decText, maxLengthDecRe)
	p.minValue = parseIntDecorator(decText, minValueDecRe)
	p.maxValue = parseIntDecorator(decText, maxValueDecRe)

	return p, true
}

// parseIntDecorator matches a decorator like `@minLength(8)` and returns the
// numeric argument. Returns nil when the decorator is not present or its
// argument is non-numeric, so callers can distinguish an explicit constraint
// of 0 (e.g., `@minValue(0)`) from "no constraint at all".
func parseIntDecorator(decText string, re *regexp.Regexp) *int64 {
	m := re.FindStringSubmatch(decText)
	if len(m) < 2 {
		return nil
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

// allowedValueRe matches individual quoted values like 'foo' or "foo".
var allowedValueRe = regexp.MustCompile(`'([^']*)'`)

// extractAllowedValues returns the values of an `@allowed([...])` decorator.
// The closing parenthesis is found with the string-aware scanner so a `]` or
// `)` inside one of the literals cannot end the list early.
func extractAllowedValues(decText string) []string {
	loc := allowedDecOpenRe.FindStringIndex(decText)
	if loc == nil {
		return nil
	}
	open := loc[1] - 1
	closeIdx := matchingParenIndex(decText, open)
	if closeIdx <= open {
		return nil
	}
	return parseAllowedValues(decText[open+1 : closeIdx])
}

func parseAllowedValues(raw string) []string {
	// Extract all single-quoted values from the raw content.
	// This handles both newline-separated and comma-separated formats:
	//   'Standard_LRS'\n'Standard_GRS'
	//   'win10', 'ws2019'
	matches := allowedValueRe.FindAllStringSubmatch(raw, -1)
	var vals []string
	for _, m := range matches {
		vals = append(vals, m[1])
	}
	return vals
}

// varMultilineHeaderRe matches only the `var <name> =` header, anchored to the
// start of the statement. The value is taken as the remaining text so it can
// span lines, which varRe cannot express (its `.` does not match a newline).
var varMultilineHeaderRe = regexp.MustCompile(`\Avar\s+(\w+)\s*=\s*`)

// parseVariableMultiline parses a `var` declaration whose value contains a
// triple-quoted string, keeping the string's newlines intact.
func parseVariableMultiline(text string, decorators []string) parsedVariable {
	v := parsedVariable{}
	loc := varMultilineHeaderRe.FindStringSubmatchIndex(text)
	if loc == nil {
		// Not a shape we recognize; fall back to the single-line parser so the
		// declaration is not dropped entirely.
		return parseVariable(strings.Join(strings.Fields(text), " "), decorators)
	}
	v.name = text[loc[2]:loc[3]]
	v.expression = strings.TrimSpace(text[loc[1]:])

	decText := strings.Join(decorators, "\n")
	if m := descDecRe.FindStringSubmatch(decText); len(m) > 1 {
		v.description = m[1]
	}
	return v
}

func parseVariable(line string, decorators []string) parsedVariable {
	v := parsedVariable{}
	m := varRe.FindStringSubmatch(line)
	if len(m) >= 3 {
		v.name = m[1]
		expr := strings.TrimSpace(m[2])
		// A looped variable (`var names = [for i in range(0, 3): 'item-${i}']`)
		// builds an array. Intentionally store the per-iteration value
		// expression in `expression` (here `'item-${i}'`), not the raw
		// `[for ...]` text, and record the loop header separately. This keeps
		// `expression` describing the value each iteration produces.
		if loop := detectLoop(expr); loop.isLoop {
			v.loop = loop
			v.expression = loop.body
		} else {
			v.expression = expr
		}
	}
	decText := strings.Join(decorators, "\n")
	if m := descDecRe.FindStringSubmatch(decText); len(m) > 1 {
		v.description = m[1]
	}
	return v
}

// parseVariableDecl handles `var foo = ...` declarations, collecting
// continuation lines when the value opens an object (`{`) or array (`[`)
// that closes on a later line. Without this, a `var pet = { name: 'x' }`
// spread across multiple lines used to truncate at the first newline.
// Depth tracking is string-aware so braces or brackets that live inside
// a Bicep string literal (e.g. `var x = { msg: 'closing brace }' }`)
// don't confuse the counter.
func parseVariableDecl(lines []string, startIdx int, decorators []string) (parsedVariable, int) {
	first := strings.TrimSpace(lines[startIdx])
	st := scanState{}
	st.feed(first)

	if !st.open() {
		return parseVariable(first, decorators), startIdx + 1
	}

	// Value opens a block or a multi-line string; reassemble until it closes.
	joined := []string{first}
	i := startIdx + 1
	for st.open() && i < len(lines) {
		t := strings.TrimSpace(lines[i])
		joined = append(joined, t)
		st.feed(t)
		i++
	}

	// A multi-line string's contents are data, not layout: joining with spaces
	// and collapsing whitespace would rewrite a shell script or certificate
	// body into one line. Keep the newlines in that case, and split the
	// declaration with the delimiter-aware scanner rather than the line regex.
	if raw := strings.Join(joined, "\n"); containsMultilineString(raw) {
		return parseVariableMultiline(raw, decorators), i
	}

	combined := strings.Join(joined, " ")
	// Collapse runs of whitespace inside the reassembled expression so
	// the captured value is a single readable line.
	combined = strings.Join(strings.Fields(combined), " ")
	return parseVariable(combined, decorators), i
}

// declValueAfterEquals returns the text following the top-level `=` of a
// declaration that spans lines[startIdx:] — i.e. everything to the right of
// the `=` in `resource foo 'Type@ver' = <value>` or `module m 'src' = <value>`.
// The whole statement is reassembled and the first `=` that sits outside any
// string, paren, bracket, or brace is taken as the assignment operator (so an
// `=` inside the resource type string or a condition expression is ignored).
// Returns "" when no top-level `=` is found.
func declValueAfterEquals(lines []string, startIdx int) string {
	_, after, _ := splitDeclAtEquals(strings.Join(lines[startIdx:], "\n"))
	return after
}

// splitDeclAtEquals splits a declaration at its assignment `=` — the first one
// that sits outside any string, comment, and bracket, and is not part of a
// `==`/`=>` operator. Returns ok=false when there is no assignment.
//
// The left side is what precedes the assignment, which for a `param` or
// `output` header is the declared type. That type cannot be captured with a
// bare `\w+`: Bicep types include literal unions (`'a' | 'b'`), arrays
// (`string[]`), nullables (`myType?`) and parenthesized forms, so the split has
// to be delimiter-aware rather than lexical.
func splitDeclAtEquals(s string) (before, after string, ok bool) {
	st := scanState{}
	for i := 0; i < len(s); {
		if st.inStr == 0 && !st.inMulti && s[i] == '=' &&
			st.paren == 0 && st.bracket == 0 && st.brace == 0 {
			// Guard against `==`/`=>` which can appear in conditions and
			// lambdas; a real assignment `=` is followed by whitespace or a
			// value char, not another `=` or `>`.
			if i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '>') {
				i = st.stepAt(s, i)
				continue
			}
			return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
		}
		i = st.stepAt(s, i)
	}
	return "", "", false
}

func parseResourceDecl(lines []string, startIdx int, decorators []string) (*parsedResource, int) {
	line := strings.TrimSpace(lines[startIdx])
	m := resourceRe.FindStringSubmatch(line)
	if len(m) < 4 {
		return nil, startIdx + 1
	}

	r := &parsedResource{
		symbolicName: m[2],
		decorators:   decorators,
	}

	// Parse type@apiVersion from the quoted string
	typeAndVersion := m[3]
	if parts := strings.SplitN(typeAndVersion, "@", 2); len(parts) == 2 {
		r.typ = parts[0]
		r.apiVersion = parts[1]
	} else {
		r.typ = typeAndVersion
	}

	r.existing = len(m) > 4 && strings.TrimSpace(m[4]) == "existing"
	r.condition = extractCondition(joinDeclHeader(lines, startIdx))

	// endIdx is where the next statement begins; with the tokenizer feeding a
	// single complete statement it is the end of the slice.
	_, endIdx := extractBlock(lines, startIdx)

	// When deployed via a `for`-loop the body object lives inside
	// `[for <hdr>: { ... }]`. Detect the loop and parse the per-iteration
	// object body the same way a plain resource body is parsed.
	r.loop = detectLoop(declValueAfterEquals(lines, startIdx))
	bodyLines := lines
	bodyStart := startIdx
	if r.loop.isLoop {
		bodyLines = strings.Split(r.loop.body, "\n")
		bodyStart = 0
	}

	body, _ := extractBlock(bodyLines, bodyStart)
	r.body = body

	// Extract common fields from body
	r.name = extractFieldValue(body, "name")
	r.location = extractFieldValue(body, "location")
	r.parent = extractFieldValue(body, "parent")
	r.scope = extractFieldValue(body, "scope")
	r.dependsOn = extractDependsOn(body)
	r.tags = extractTags(body)

	// A resource may declare child resources inside its body. Each nested
	// declaration is parsed with the same logic as a top-level resource and
	// has its `parent` set to this resource's symbolic name.
	r.nested = extractNestedResources(body, r.symbolicName)

	return r, endIdx
}

// extractNestedResources finds `resource <sym> '<type>'( existing)? =`
// declarations that sit at the top level of the parent's body (one brace
// deep, relative to the parent's outer braces) and parses each one
// recursively with the same logic as a top-level resource. The body text
// passed in is the parent's full `{ ... }` block including its outer braces,
// so child declarations live at brace depth 1. The parent's symbolic name is
// recorded on each child's `parent` field.
func extractNestedResources(body, parentSymbolic string) []parsedResource {
	var nested []parsedResource
	st := scanState{}
	for i := 0; i < len(body); {
		// We only consider a `resource` keyword when it begins a statement at
		// brace depth 1 (directly inside the parent body) and outside any
		// string/paren/bracket. depthBefore is captured before stepping.
		if st.inStr == 0 && !st.inMulti && st.brace == 1 && st.paren == 0 && st.bracket == 0 &&
			isStatementStart(body, i) && hasKeywordAt(body, i, "resource") {
			// Reassemble the nested declaration from here until its delimiters
			// balance again, then hand the statement text to the recursive
			// resource parser.
			stmtEnd := scanStatementEnd(body[i:]) + i
			stmt := body[i:stmtEnd]
			stmtLines := strings.Split(stmt, "\n")
			if child, _ := parseResourceDecl(stmtLines, 0, nil); child != nil {
				child.parent = parentSymbolic
				nested = append(nested, *child)
			}
			// Resume scanning after the consumed statement, keeping the depth
			// state consistent by feeding the skipped text.
			for j := i; j < stmtEnd; {
				j = st.stepAt(body, j)
			}
			i = stmtEnd
			continue
		}
		i = st.stepAt(body, i)
	}
	return nested
}

// isStatementStart reports whether position i in s begins a token — i.e. the
// preceding non-ignored byte is a newline, brace, or the start of input. This
// keeps `extractNestedResources` from matching a `resource` substring that is
// part of a larger identifier or appears mid-line (e.g. an expression).
func isStatementStart(s string, i int) bool {
	for j := i - 1; j >= 0; j-- {
		c := s[j]
		if c == ' ' || c == '\t' || c == '\r' {
			continue
		}
		return c == '\n' || c == '{' || c == '}'
	}
	return true
}

// hasKeywordAt reports whether the identifier starting at i in s is exactly
// `kw` (followed by whitespace, not more identifier characters).
func hasKeywordAt(s string, i int, kw string) bool {
	if i+len(kw) > len(s) {
		return false
	}
	if s[i:i+len(kw)] != kw {
		return false
	}
	next := i + len(kw)
	if next >= len(s) {
		return false
	}
	c := s[next]
	return c == ' ' || c == '\t'
}

// scanStatementEnd returns the index just past the end of the statement at the
// start of s. It mirrors the tokenizer: consume the first line, then keep
// pulling continuation lines until the running depth (string-aware) returns to
// zero. This way a `= if (cond) { ... }` header whose parens close before the
// body brace opens doesn't terminate the statement early, and a multi-line
// `= { ... }` body is consumed whole.
func scanStatementEnd(s string) int {
	st := scanState{}
	// Consume the first line.
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return len(s)
	}
	st.feed(s[:nl])
	pos := nl + 1
	if !st.open() {
		return nl
	}
	for pos < len(s) {
		next := strings.IndexByte(s[pos:], '\n')
		var line string
		if next < 0 {
			line = s[pos:]
		} else {
			line = s[pos : pos+next]
		}
		st.feed(line)
		if next < 0 {
			return len(s)
		}
		pos += next + 1
		if !st.open() {
			return pos - 1
		}
	}
	return len(s)
}

func parseModuleDecl(lines []string, startIdx int, decorators []string) (*parsedModule, int) {
	line := strings.TrimSpace(lines[startIdx])
	m := moduleRe.FindStringSubmatch(line)
	if len(m) < 3 {
		return nil, startIdx + 1
	}

	mod := &parsedModule{
		name:           m[1],
		source:         m[2],
		isRegistry:     strings.HasPrefix(m[2], "br:") || strings.HasPrefix(m[2], "br/"),
		isTemplateSpec: strings.HasPrefix(m[2], "ts:") || strings.HasPrefix(m[2], "ts/"),
		decorators:     decorators,
	}

	mod.condition = extractCondition(joinDeclHeader(lines, startIdx))
	_, endIdx := extractBlock(lines, startIdx)

	// As with resources, a looped module wraps its body object in
	// `[for <hdr>: { ... }]`; feed the loop body to the body parser so
	// `name`/`scope`/`params` extraction still works.
	mod.loop = detectLoop(declValueAfterEquals(lines, startIdx))
	bodyLines := lines
	bodyStart := startIdx
	if mod.loop.isLoop {
		bodyLines = strings.Split(mod.loop.body, "\n")
		bodyStart = 0
	}

	body, _ := extractBlock(bodyLines, bodyStart)
	mod.body = body
	mod.scope = extractFieldValue(body, "scope")

	decText := strings.Join(decorators, "\n")
	if dm := descDecRe.FindStringSubmatch(decText); len(dm) > 1 {
		mod.description = dm[1]
	}

	return mod, endIdx
}

// parseOutput parses an `output` declaration. ok is false when the line is not
// a well-formed output declaration — including one with no assignment, which
// Bicep requires — so the caller can skip it rather than append a husk.
func parseOutput(line string, decorators []string) (parsedOutput, bool) {
	o := parsedOutput{}
	loc := outputHeaderRe.FindStringSubmatchIndex(line)
	if loc == nil {
		return parsedOutput{}, false
	}
	rest := strings.TrimSpace(line[loc[1]:])
	if rest == "" {
		return parsedOutput{}, false
	}

	typ, expr, hasValue := splitDeclAtEquals(rest)
	if !hasValue || typ == "" {
		return parsedOutput{}, false
	}

	o.name = line[loc[2]:loc[3]]
	o.typ = typ
	// A looped output (`output ids array = [for sa in sas: sa.id]`)
	// produces an array. Intentionally store the per-iteration value
	// expression in `expression` (here `sa.id`), not the raw `[for ...]`
	// text, and record the loop header separately. This keeps `expression`
	// describing the value each iteration produces.
	if loop := detectLoop(expr); loop.isLoop {
		o.loop = loop
		o.expression = loop.body
	} else {
		o.expression = expr
	}

	decText := strings.Join(decorators, "\n")
	if m := descDecRe.FindStringSubmatch(decText); len(m) > 1 {
		o.description = m[1]
	}
	return o, true
}

// parseTypeDecl handles a `type Name = <definition>` statement. The whole
// statement body is passed in (it may span multiple lines for object types),
// so runs of whitespace in the captured definition are collapsed into single
// spaces for a readable single-line value. The `@export()` decorator marks
// the type as shared/exported, and `@description(...)` is captured.
func parseTypeDecl(text string, decorators []string) (parsedType, bool) {
	trimmed := strings.TrimSpace(text)
	m := typeRe.FindStringSubmatch(trimmed)
	if len(m) < 3 {
		return parsedType{}, false
	}
	t := parsedType{
		name:       m[1],
		definition: strings.Join(strings.Fields(m[2]), " "),
		decorators: decorators,
	}
	decText := strings.Join(decorators, "\n")
	if dm := descDecRe.FindStringSubmatch(decText); len(dm) > 1 {
		t.description = dm[1]
	}
	t.exported = exportDecRe.MatchString(decText)
	if dm := discriminatorDecRe.FindStringSubmatch(decText); len(dm) > 1 {
		t.discriminator = dm[1]
	}

	// Decompose the definition into a kind plus (for objects/unions) its
	// structured members. Classification runs on the RAW (pre-collapse)
	// right-hand side because object properties may be newline-separated with
	// no commas — collapsing whitespace would merge them — and the splitter is
	// already string/bracket-aware so newlines and nested braces are handled.
	t.kind, t.unionMembers, t.properties = classifyTypeDefinition(m[2])
	return t, true
}

// builtinTypeNames is the set of Bicep built-in primitive types a bare type
// identifier may name. A definition that is exactly one of these classifies as
// "primitive"; any other bare identifier classifies as "alias" (it names
// another user-defined type).
var builtinTypeNames = map[string]bool{
	"string":       true,
	"int":          true,
	"bool":         true,
	"object":       true,
	"array":        true,
	"secureString": true,
	"securestring": true,
	"secureObject": true,
	"secureobject": true,
}

// classifyTypeDefinition inspects a type's raw right-hand-side definition and
// returns its kind plus, for object/union types, the structured members:
//
//   - a trimmed `{ ... }` body  -> "object", with each `key: type` pair parsed
//   - a top-level `|`           -> "union", with members split on that `|`
//   - a leading `[`             -> "array" (a `[...]` tuple is folded in)
//   - a `[]` suffix             -> "array"
//   - a bare built-in name      -> "primitive"
//   - any other bare identifier -> "alias"
//
// Splitting (object pairs, union members) is depth-aware via scanState so
// commas/pipes inside nested `{}`/`[]`/`<>`/strings don't split early.
func classifyTypeDefinition(def string) (string, []string, []parsedTypeProperty) {
	trimmed := strings.TrimSpace(def)
	if trimmed == "" {
		return "", nil, nil
	}

	// Union type: members separated by a top-level `|`. Checked before the
	// object case because a discriminated tagged union's first member is itself
	// an object (`{ kind: 'circle', ... } | { kind: 'square', ... }`), so a
	// leading `{` does not imply a plain object type. Members keep their raw
	// form (including the surrounding whitespace collapsed to a single line).
	if members := splitTopLevelPipes(trimmed); len(members) > 1 {
		out := make([]string, 0, len(members))
		for _, m := range members {
			m = strings.Join(strings.Fields(m), " ")
			if m != "" {
				out = append(out, m)
			}
		}
		return "union", out, nil
	}

	// Object type: `{ name: string, tier: sku }`.
	if trimmed[0] == '{' {
		return "object", nil, parseTypeObjectProperties(stripOuter(trimmed, '{', '}'))
	}

	// Array/tuple: a `[...]` tuple or a `<type>[]` suffix.
	if trimmed[0] == '[' || strings.HasSuffix(trimmed, "[]") {
		return "array", nil, nil
	}

	// A bare identifier: a built-in primitive, otherwise an alias for another
	// type. Anything else (a function-shaped or otherwise complex definition)
	// also falls through to "alias".
	if builtinTypeNames[trimmed] {
		return "primitive", nil, nil
	}
	return "alias", nil, nil
}

// parseTypeObjectProperties splits an object type body (the text between the
// outer braces) into its `name: type` members. Entries are split on top-level
// commas and newlines (string/bracket/brace-aware) so a nested object property
// like `nested: { a: int, b: int }` stays intact; a trailing `?` optional
// marker on a key is stripped.
func parseTypeObjectProperties(body string) []parsedTypeProperty {
	var props []parsedTypeProperty
	for _, entry := range splitTopLevelEntries(body) {
		key, value, ok := splitFirstColon(entry)
		if !ok {
			continue
		}
		name := strings.TrimSpace(key)
		name = strings.TrimSuffix(name, "?")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		props = append(props, parsedTypeProperty{
			name: name,
			typ:  strings.TrimSpace(value),
		})
	}
	return props
}

// splitTopLevelPipes splits s on `|` characters that sit outside any string,
// bracket, brace, or paren and outside a triple-quoted string — so a `|` inside
// a nested object/array or a string literal doesn't split the union.
func splitTopLevelPipes(s string) []string {
	var parts []string
	st := scanState{}
	start := 0
	for i := 0; i < len(s); {
		if s[i] == '|' && st.inStr == 0 && !st.inMulti &&
			st.paren == 0 && st.bracket == 0 && st.brace == 0 {
			parts = append(parts, s[start:i])
			i++
			start = i
			continue
		}
		i = st.stepAt(s, i)
	}
	return append(parts, s[start:])
}

// parseFunctionDecl handles a `func name(p1 t1, p2 t2) returnType => expr`
// declaration. The parameter list is split into a name->type map, and the
// body expression after `=>` is captured raw (whitespace collapsed).
func parseFunctionDecl(text string, decorators []string) (parsedFunction, bool) {
	trimmed := strings.TrimSpace(text)
	head := funcHeadRe.FindStringSubmatchIndex(trimmed)
	if head == nil {
		return parsedFunction{}, false
	}
	name := trimmed[head[2]:head[3]]
	// The full match ends on the opening `(` of the parameter list.
	openParen := head[1] - 1
	closeParen := matchingParenIndex(trimmed, openParen)
	if closeParen < 0 {
		return parsedFunction{}, false
	}
	paramList := trimmed[openParen+1 : closeParen]

	// After the parameter list comes `<returnType> => <expression>`. The
	// first `=>` is the function arrow; any later `=>` belongs to a lambda
	// inside the body, so splitting on the first occurrence is correct.
	rest := strings.TrimSpace(trimmed[closeParen+1:])
	before, after, ok := strings.Cut(rest, "=>")
	if !ok {
		return parsedFunction{}, false
	}

	fn := parsedFunction{
		name:       name,
		parameters: parseFunctionParams(paramList),
		returnType: strings.TrimSpace(before),
		expression: strings.Join(strings.Fields(after), " "),
		decorators: decorators,
	}
	decText := strings.Join(decorators, "\n")
	if dm := descDecRe.FindStringSubmatch(decText); len(dm) > 1 {
		fn.description = dm[1]
	}
	return fn, true
}

// parseFunctionParams splits a `p1 t1, p2 t2` parameter list into a
// name->type map. Commas are split at top-level depth only, so an
// object-typed parameter such as `opts { name: string, tier: int }` is kept
// intact. Each entry is `name <type...>`; the first token is the name and the
// remainder (whitespace-collapsed) is the type. Returns nil for an empty list.
func parseFunctionParams(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	params := map[string]string{}
	for _, part := range splitTopLevelCommas(raw) {
		fields := strings.Fields(part)
		if len(fields) < 2 {
			continue
		}
		params[fields[0]] = strings.Join(fields[1:], " ")
	}
	if len(params) == 0 {
		return nil
	}
	return params
}

// matchingParenIndex returns the index of the `)` that closes the `(` at
// position open, using the shared string-aware lexer so parens inside string
// literals or nested brackets/braces don't throw off the count. Returns -1 if
// the paren is unbalanced.
func matchingParenIndex(s string, open int) int {
	st := scanState{}
	i := st.stepAt(s, open) // consume the opening '(' -> paren depth 1
	for i < len(s) {
		if st.paren == 0 {
			return i - 1
		}
		i = st.stepAt(s, i)
	}
	if st.paren == 0 {
		return len(s) - 1
	}
	return -1
}

// splitTopLevelCommas splits s on commas that sit outside any string,
// bracket, brace, or paren — so commas inside an object-typed parameter or a
// nested expression don't split the list.
func splitTopLevelCommas(s string) []string {
	var parts []string
	st := scanState{}
	start := 0
	for i := 0; i < len(s); {
		if s[i] == ',' && st.inStr == 0 && !st.inMulti &&
			st.paren == 0 && st.bracket == 0 && st.brace == 0 {
			parts = append(parts, s[start:i])
			i++
			start = i
			continue
		}
		i = st.stepAt(s, i)
	}
	return append(parts, s[start:])
}

var (
	// importNamedRe matches `import { a, b } from './x.bicep'`.
	importNamedRe = regexp.MustCompile(`(?s)^import\s*\{([^}]*)\}\s*from\s*'([^']+)'`)
	// importWildcardRe matches `import * as ns from './x.bicep'`.
	importWildcardRe = regexp.MustCompile(`^import\s*\*\s*as\s+(\w+)\s+from\s*'([^']+)'`)
	// importProviderRe matches a bare provider import like `import 'az@2.0.0'`.
	importProviderRe = regexp.MustCompile(`^import\s+'([^']+)'`)
)

// loopHeaderRe matches the `[for` opener of a loop value and the iteration
// variable form that follows. Group 1 captures the indexed
// `(item, index)` form's item, group 2 the index var, group 3 the single
// `item` form. Only the header up to the first identifier(s) and the
// trailing `in ` is matched; the `<expression>: <body>` tail is split out
// depth-aware so collection expressions and bodies that contain `:`/`]`
// inside strings, parens, or nested brackets parse correctly.
var loopHeaderRe = regexp.MustCompile(`^\[\s*for\s+(?:\(\s*(\w+)\s*,\s*(\w+)\s*\)|(\w+))\s+in\s+`)

// detectLoop inspects a declaration's value text (everything after the `=`)
// and, when it is a `for`-loop, returns the parsed loop header plus the
// per-iteration body. For a non-loop value it returns loopInfo{} with
// isLoop=false, so callers can fall back to their normal parse.
//
// The collection expression runs from `in` up to the top-level `:` that
// separates the loop header from its body; the body runs from that `:` to
// the matching closing `]`. Both boundaries are found with the shared
// string/bracket-aware scanState so a `:` or `]` inside a string literal,
// a `range(0, 3)` call, or a nested object/array doesn't split early.
func detectLoop(value string) loopInfo {
	trimmed := strings.TrimSpace(value)
	m := loopHeaderRe.FindStringSubmatchIndex(trimmed)
	if m == nil {
		return loopInfo{}
	}

	info := loopInfo{isLoop: true}
	// Submatch groups: [2:3]=indexed item, [4:5]=index var, [6:7]=single item.
	if m[2] >= 0 {
		info.iterator = trimmed[m[2]:m[3]]
		info.indexVar = trimmed[m[4]:m[5]]
	} else if m[6] >= 0 {
		info.iterator = trimmed[m[6]:m[7]]
	}

	// The collection expression starts right after the matched `... in ` prefix.
	exprStart := m[1]

	// Find the top-level `:` separating the loop header from the body, and
	// the matching closing `]`. Seed the scanner with the leading `[`
	// already consumed (bracket depth 1).
	st := scanState{bracket: 1}
	colon := -1
	closeBracket := -1
	for i := exprStart; i < len(trimmed); {
		if st.inStr == 0 && !st.inMulti {
			// The header/body separator is the first `:` at the loop's own
			// bracket depth (1) with no open paren/brace.
			if trimmed[i] == ':' && colon < 0 && st.bracket == 1 && st.paren == 0 && st.brace == 0 {
				colon = i
			}
		}
		prev := i
		i = st.stepAt(trimmed, i)
		if st.bracket == 0 {
			closeBracket = prev
			break
		}
	}

	if colon < 0 {
		// Malformed loop (no header colon found); treat as non-loop so the
		// caller's normal parse still runs.
		return loopInfo{}
	}
	if closeBracket < 0 {
		closeBracket = len(trimmed)
	}

	info.expression = strings.TrimSpace(trimmed[exprStart:colon])
	info.body = strings.TrimSpace(trimmed[colon+1 : closeBracket])
	return info
}

// parseImportDecl handles the three Bicep import forms:
//
//	import { typeA, funcB } from './shared.bicep'
//	import * as shared from './shared.bicep'
//	import 'az@2.0.0'
//
// The `from` target (or the bare provider string) becomes `source`; named
// imports populate `symbols`; a `* as ns` import sets `namespace` and
// `wildcard`.
func parseImportDecl(text string) (parsedImport, bool) {
	trimmed := strings.Join(strings.Fields(text), " ")

	if m := importWildcardRe.FindStringSubmatch(trimmed); len(m) > 2 {
		return parsedImport{
			source:    m[2],
			namespace: m[1],
			wildcard:  true,
		}, true
	}

	if m := importNamedRe.FindStringSubmatch(trimmed); len(m) > 2 {
		var symbols []string
		for s := range strings.SplitSeq(m[1], ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				symbols = append(symbols, s)
			}
		}
		return parsedImport{
			source:  m[2],
			symbols: symbols,
		}, true
	}

	if m := importProviderRe.FindStringSubmatch(trimmed); len(m) > 1 {
		return parsedImport{source: m[1]}, true
	}

	return parsedImport{}, false
}

// parseMetadataDecl handles a `metadata <name> = '<literal>'` entry. Only
// literal single-quoted values are captured; expression-/object-valued
// metadata returns ok=false and is skipped, mirroring tag extraction.
func parseMetadataDecl(text string) (string, string, bool) {
	trimmed := strings.TrimSpace(text)
	m := metadataRe.FindStringSubmatch(trimmed)
	if len(m) < 3 {
		return "", "", false
	}
	return m[1], m[2], true
}

// extractBlock extracts a brace-delimited block starting from startIdx by
// tracking '{'/'}' nesting depth. It walks the source through the shared
// `scanState` lexer so braces that live inside string literals (including
// `${...}` interpolation and triple-quoted multi-line strings) or `//`
// comments do not move the depth counter — a `}` inside a string can't close
// the block early, and a `{` inside one can't extend it.
func extractBlock(lines []string, startIdx int) (string, int) {
	st := scanState{}
	started := false
	var blockLines []string

	for i := startIdx; i < len(lines); i++ {
		line := lines[i]
		for j := 0; j < len(line); {
			j = st.stepAt(line, j)
			if st.brace > 0 {
				started = true
			}
		}
		if started {
			blockLines = append(blockLines, line)
		}
		if started && st.brace == 0 {
			return strings.Join(blockLines, "\n"), i + 1
		}
	}

	return strings.Join(blockLines, "\n"), len(lines)
}

// bodyObjectInner returns the contents of the outermost `{ … }` object in body,
// skipping whatever declaration header precedes it (`resource r 'T@v' = `, or
// the `if (…)` form). Returns "" when body contains no object.
//
// The walk shares scanState, so a brace inside a string literal or a comment is
// not mistaken for the opener. An unterminated object yields everything from
// the opener on, which keeps a truncated file readable rather than empty.
func bodyObjectInner(body string) string {
	st := scanState{}
	open := -1
	for i := 0; i < len(body); {
		before := st.brace
		next := st.stepAt(body, i)
		switch {
		case open == -1 && st.brace == before+1:
			open = i
		case open >= 0 && st.brace == 0:
			return body[open+1 : i]
		}
		if next <= i {
			next = i + 1
		}
		i = next
	}
	if open >= 0 {
		return body[open+1:]
	}
	return ""
}

// topLevelFieldValue returns the raw value text of `fieldName` from the top
// level of a resource/module body — the members at brace depth 1 — or "" when
// the body has no such member.
//
// Matching has to be depth-aware. Bicep does not require a resource's own
// `name`/`location`/`tags`/`dependsOn` to come before its `properties`, and
// nested objects use the very same keys: subnets have names, an inline
// `properties.template` on a `Microsoft.Resources/deployments` has its own tags
// and dependsOn. A scan that took the first match at any indentation returned
// the nested value, so `bicep.resource.name` could report a subnet's name.
func topLevelFieldValue(body string, fieldName string) string {
	inner := bodyObjectInner(body)
	if inner == "" {
		// No object in body — a bare `key: value` fragment. There is no
		// nesting to be confused by, so scan it as-is.
		inner = body
	}

	entries := splitTopLevelEntries(inner)
	for i, entry := range entries {
		key, value, ok := splitFirstColon(entry)
		if !ok || strings.TrimSpace(key) != fieldName {
			continue
		}
		value = strings.TrimSpace(value)
		// Bicep allows the value's opening brace on the following line
		// (`params:\n{ … }`). The newline after the colon sits at depth 0, so
		// the entry splitter hands the object back as the next entry.
		if value == "" && i+1 < len(entries) {
			value = strings.TrimSpace(entries[i+1])
		}
		return value
	}
	return ""
}

func extractFieldValue(body string, fieldName string) string {
	return topLevelFieldValue(body, fieldName)
}

// joinDeclHeader reassembles the declaration header — everything from
// startIdx up to but not including the body's opening `{` — into a
// single line. This lets extractCondition see the whole `if (...)`
// clause even when it spans several source lines, e.g.:
//
//	resource foo 'Type@ver' = if (
//	  expr1 &&
//	  expr2
//	) { ... }
//
// The `{` is only counted as the body opener when paren/bracket depth
// is zero and the cursor isn't inside a string literal.
func joinDeclHeader(lines []string, startIdx int) string {
	var parts []string
	st := scanState{}
	for i := startIdx; i < len(lines); i++ {
		line := lines[i]
		end := st.scanForBodyBrace(line)
		if end >= 0 {
			parts = append(parts, line[:end])
			break
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, " ")
}

func extractCondition(line string) string {
	// condition is expressed as: resource foo 'Type@ver' = if (expr) { ... }
	if _, after, ok := strings.Cut(line, "= if"); ok {
		rest := strings.TrimSpace(after)
		// Extract the condition expression in parens
		// matchingParenIndex shares the string-aware lexer, so a `)` inside a
		// quoted value (`if (tag == 'a)b')`) no longer closes the condition
		// early and truncate the expression.
		if strings.HasPrefix(rest, "(") {
			if closeIdx := matchingParenIndex(rest, 0); closeIdx > 0 {
				return rest[1:closeIdx]
			}
		}
	}
	return ""
}

// extractFieldBlock extracts the brace-delimited block for a top-level field
// like "params: { ... }" from a body string. Returns the raw content between
// the braces, or empty string if the field is not found. The opening `{`
// may be on the same line as the field name or on a subsequent line (both
// are valid Bicep):
//
//	params: { foo: 'x' }
//	params:
//	{
//	  foo: 'x'
//	}
//
// extractFieldBlock returns the contents of a `fieldName: { … }` object
// declared at the top level of body. Like extractFieldValue it matches only at
// brace depth 1, so an inline `properties.template.tags` is not mistaken for
// the resource's own tags.
func extractFieldBlock(body string, fieldName string) string {
	value := topLevelFieldValue(body, fieldName)
	// Require a balanced object: an unterminated `{` is malformed input and
	// reports no block rather than half of one.
	if !strings.HasPrefix(value, "{") || !strings.HasSuffix(value, "}") {
		return ""
	}
	return strings.TrimSpace(stripOuter(value, '{', '}'))
}

// scanState is a tiny lexer state for tracking paren/bracket/brace
// depth across one or more lines of Bicep source while respecting
// string literals (single- and double-quoted, with `\<char>` escapes),
// triple-quoted multi-line strings (`”'…”'`), and `// ...` line
// comments. All of the bracket-balancing helpers in this package
// share it so brackets that live inside a string literal — including
// a `”'…}…”'` block that straddles multiple lines — can't fool
// the depth counter.
type scanState struct {
	paren   int
	bracket int
	brace   int
	inStr   byte // 0, '\'', or '"' — single-line string
	inMulti bool // true while inside a `'''…'''` multi-line string
	inCmt   bool // true while inside a `/*…*/` block comment
}

func (s *scanState) totalDepth() int { return s.paren + s.bracket + s.brace }

// open reports whether the state is mid-construct and a statement scanner must
// keep consuming lines.
//
// Bracket depth alone is not enough. A triple-quoted multi-line string opens no
// paren, bracket, or brace, so a depth-only test ended the statement at the
// first newline and handed the remaining lines of the string back to the
// scanner as top-level statements. Anything in them that looked like a
// declaration was then parsed as one, so a deployment script embedded in a
// variable could fabricate resources, parameters, and outputs that are not part
// of the template.
func (s *scanState) open() bool { return s.totalDepth() > 0 || s.inMulti }

// containsMultilineString reports whether s opens a triple-quoted string
// anywhere outside a comment or another string. Callers use it to decide
// whether a reassembled statement must keep its newlines: collapsing them would
// corrupt the string's contents.
func containsMultilineString(s string) bool {
	st := scanState{}
	for i := 0; i < len(s); {
		before := st.inMulti
		i = st.stepAt(s, i)
		if !before && st.inMulti {
			return true
		}
	}
	return false
}

// stepAt processes one position in `body` and returns the next index
// to resume from. It handles the full set of Bicep token states
// (single-line strings with `\<char>` escapes, triple-quoted
// multi-line strings, `// …` line comments, and bracket nesting) so
// every walker in this file can share the same lexer rules without
// duplicating them.
func (s *scanState) stepAt(body string, i int) int {
	// A `/*…*/` block comment runs across lines and suppresses everything
	// inside it, including delimiters. Checked before the multi-line string
	// case because a comment opened first wins until it closes.
	if s.inCmt {
		if i+1 < len(body) && body[i] == '*' && body[i+1] == '/' {
			s.inCmt = false
			return i + 2
		}
		return i + 1
	}
	if s.inMulti {
		if i+2 < len(body) && body[i] == '\'' && body[i+1] == '\'' && body[i+2] == '\'' {
			s.inMulti = false
			return i + 3
		}
		return i + 1
	}
	ch := body[i]
	if s.inStr != 0 {
		// A single- or double-quoted Bicep string cannot contain a raw
		// newline; that is what the triple-quoted form is for. Clearing the
		// state at the line break keeps one unterminated quote from turning
		// the rest of a resource body into string content, which made the
		// resource's properties read as empty.
		if ch == '\n' {
			s.inStr = 0
			return i + 1
		}
		// Bicep string escapes: `\\`, `\'`, `\n`, `\$`, etc. The next
		// byte is literal regardless of what it is, so just skip it.
		if ch == '\\' && i+1 < len(body) {
			return i + 2
		}
		if ch == s.inStr {
			s.inStr = 0
		}
		return i + 1
	}
	// `// …` line comment — skip to end of line.
	if ch == '/' && i+1 < len(body) && body[i+1] == '/' {
		j := i
		for j < len(body) && body[j] != '\n' {
			j++
		}
		return j
	}
	// `/*` block comment opener. Checked after the `//` case so a block
	// opener that appears inside a line comment is left alone.
	if ch == '/' && i+1 < len(body) && body[i+1] == '*' {
		s.inCmt = true
		return i + 2
	}
	// Triple-quoted multi-line string opener: enter `inMulti` and
	// hand back the index just past the `'''`.
	if ch == '\'' && i+2 < len(body) && body[i+1] == '\'' && body[i+2] == '\'' {
		s.inMulti = true
		return i + 3
	}
	switch ch {
	case '\'', '"':
		s.inStr = ch
	case '(':
		s.paren++
	case ')':
		s.paren--
	case '[':
		s.bracket++
	case ']':
		s.bracket--
	case '{':
		s.brace++
	case '}':
		s.brace--
	}
	return i + 1
}

// feed advances the state through one line of source, updating the
// running depth counters. Characters inside a string literal or after
// a top-level `//` comment marker do not affect depth.
func (s *scanState) feed(line string) {
	// Callers split on newlines, so the line break that would have closed
	// an unterminated single-quoted string is not part of line. Reset for
	// the same reason stepAt resets at an explicit newline. inMulti and
	// inCmt are deliberately preserved: those constructs do span lines.
	s.inStr = 0
	for i := 0; i < len(line); {
		i = s.stepAt(line, i)
	}
}

// stripBlockComments replaces the contents of every `/*…*/` comment with
// spaces, leaving newlines and every other byte in place.
//
// Blanking rather than deleting keeps byte offsets and line numbers identical
// to the original source, so statement start lines, source excerpts, and the
// regex helpers that index into a resource body all stay accurate. Because the
// walk shares scanState, a `/*` inside a string literal (`'/*.json'`) is not
// treated as a comment opener, and a `//` line comment hides a `/*` that
// follows it on the same line.
//
// Doing this once up front is what keeps the ~15 bracket-balancing and
// field-extraction helpers in this file correct without each one having to
// know about comments: by the time they run, a commented-out resource is
// whitespace, and an unbalanced delimiter inside a comment can no longer fool
// the depth counter into consuming the rest of the file.
func stripBlockComments(content string) string {
	if !strings.Contains(content, "/*") {
		return content
	}

	out := []byte(content)
	st := scanState{}
	for i := 0; i < len(content); {
		openBefore := st.inCmt
		next := st.stepAt(content, i)
		if next <= i {
			// Defensive: stepAt always advances, but a non-advancing step
			// here would hang the scan on user-supplied input.
			next = i + 1
		}
		// Blank the span when it opened, continued, or closed a comment.
		if openBefore || st.inCmt {
			for j := i; j < next && j < len(out); j++ {
				if out[j] != '\n' {
					out[j] = ' '
				}
			}
		}
		i = next
	}
	return string(out)
}

// scanForBodyBrace advances the state through one line and returns the
// byte index of the first `{` that lands outside any string and at
// paren/bracket depth 0 — i.e., the opener of a resource/module body.
// Returns -1 if no such brace is on the line. The state still tracks
// every other character so subsequent calls keep their depth context.
func (s *scanState) scanForBodyBrace(line string) int {
	for i := 0; i < len(line); {
		if s.inStr == 0 && !s.inMulti && line[i] == '{' && s.paren == 0 && s.bracket == 0 {
			return i
		}
		i = s.stepAt(line, i)
	}
	return -1
}

// parseBicepObject takes the body of a Bicep object (text between the
// outer braces) and returns it as a key/value map. Nested objects
// become nested maps, arrays become slices, single-/double-quoted
// scalars are unquoted, and anything else (booleans, numbers, function
// calls, expressions) is kept in its raw text form so policy code can
// pattern-match on it.
//
// This is a deliberately small parser, not a full Bicep lexer: it
// honors string literals, `// ...` line comments, and brace/bracket/
// paren nesting when splitting top-level entries, which covers the
// shapes that show up in real-world `properties:` and `params:`
// blocks. Anything it can't parse cleanly falls back to a string —
// audits can still match on the text.
func parseBicepObject(body string) map[string]any {
	return parseBicepObjectDepth(body, 0)
}

func parseBicepObjectDepth(body string, depth int) map[string]any {
	entries := splitTopLevelEntries(body)
	out := make(map[string]any, len(entries))
	for _, entry := range entries {
		key, value, ok := splitFirstColon(entry)
		if !ok {
			continue
		}
		out[unquoteBicepKey(strings.TrimSpace(key))] = parseBicepValueDepth(strings.TrimSpace(value), depth)
	}
	return out
}

// unquoteBicepKey strips the surrounding quotes from a Bicep object key. Keys
// that aren't valid bare identifiers must be quoted in Bicep source, so dotted
// keys such as the API Management `customProperties` entries
// (`'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10'`)
// arrive with their quotes attached. Left in place, the quotes become part of
// the map key and an index lookup written without them
// (`properties["customProperties"]["Microsoft...Tls10"]`) misses and returns
// null. Bare-identifier keys carry no quotes and are returned unchanged.
func unquoteBicepKey(k string) string {
	if len(k) >= 2 && (k[0] == '\'' || k[0] == '"') && k[len(k)-1] == k[0] {
		return k[1 : len(k)-1]
	}
	return k
}

// maxValueDepth bounds recursion in the object/array value parser, mirroring
// maxExprDepth in the expression parser. Real Bicep nests properties a handful
// of levels deep; the cap exists so a deeply nested, possibly adversarial
// template degrades to raw text instead of driving super-linear work that
// wedges the scan.
const maxValueDepth = 200

func parseBicepValue(v string) any {
	return parseBicepValueDepth(v, 0)
}

func parseBicepValueDepth(v string, depth int) any {
	if v == "" {
		return ""
	}
	if depth >= maxValueDepth {
		return v
	}
	switch v[0] {
	case '{':
		// stripOuter returns its input unchanged when there is nothing to
		// strip, which for a lone delimiter makes this a fixed point: the
		// container parser splits the text into the same single entry and
		// hands it straight back. That recursion has no base case and
		// overflows the stack, which is a fatal error the plugin runtime
		// cannot recover from. Only descend when the text actually shrank.
		if inner := stripOuter(v, '{', '}'); len(inner) < len(v) {
			return parseBicepObjectDepth(inner, depth+1)
		}
		return v
	case '[':
		if inner := stripOuter(v, '[', ']'); len(inner) < len(v) {
			return parseBicepArrayDepth(inner, depth+1)
		}
		return v
	case '\'', '"':
		// A triple-quoted multi-line string needs all three delimiters
		// removed; stripping a single quote from each end left stray `''`
		// bookends on every embedded script, certificate, or policy body.
		if len(v) >= 6 && strings.HasPrefix(v, "'''") && strings.HasSuffix(v, "'''") {
			return v[3 : len(v)-3]
		}
		if len(v) >= 2 && v[len(v)-1] == v[0] {
			return v[1 : len(v)-1]
		}
	}
	// Bare `true`/`false` and numeric literals become typed values so policies
	// can compare them naturally (`== true`, `>= 30`) instead of against the
	// stringified form. Anything else (an expression like `resourceGroup().id`,
	// a bare symbol) is returned as-is.
	switch v {
	case "true":
		return true
	case "false":
		return false
	}
	if n, ok := parseBicepNumber(v); ok {
		return n
	}
	return v
}

// parseBicepNumber parses a bare integer or float literal into a float64 (the
// shape MQL uses for numbers inside a dict). Returns false for anything that
// isn't a plain decimal literal so expressions — and the special float forms
// `Inf`/`NaN` that `strconv.ParseFloat` would otherwise accept — stay raw
// strings.
func parseBicepNumber(v string) (float64, bool) {
	if v == "" {
		return 0, false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9', c == '.':
		case (c == '-' || c == '+') && i == 0:
		default:
			return 0, false
		}
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return f, true
	}
	return 0, false
}

// stripLiteralQuotes removes the surrounding single quotes from a Bicep string
// literal (`'eastus'` -> `eastus`), leaving unquoted expressions
// (`resourceGroup().location`) untouched. Mirrors how parameter default values
// are unquoted, so equality checks like `name == "eastus"` work directly.
func stripLiteralQuotes(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseBicepArray(body string) []any {
	return parseBicepArrayDepth(body, 0)
}

func parseBicepArrayDepth(body string, depth int) []any {
	entries := splitTopLevelEntries(body)
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, parseBicepValueDepth(strings.TrimSpace(e), depth))
	}
	return out
}

func splitFirstColon(s string) (string, string, bool) {
	st := scanState{}
	for i := 0; i < len(s); {
		if st.inStr == 0 && !st.inMulti && s[i] == ':' && st.totalDepth() == 0 {
			return s[:i], s[i+1:], true
		}
		i = st.stepAt(s, i)
	}
	return "", "", false
}

func stripOuter(s string, open, close byte) string {
	if len(s) < 2 || s[0] != open {
		return s
	}
	if s[len(s)-1] != close {
		return s[1:]
	}
	return s[1 : len(s)-1]
}

func splitTopLevelEntries(body string) []string {
	var entries []string
	st := scanState{}
	// An entry is the contiguous span body[start:end]. Nothing is copied: a
	// top-level `// …` comment always runs to the newline that terminates the
	// entry, so no entry content ever follows a comment and dropping one is
	// just a matter of leaving `end` where it was.
	start, end := 0, 0
	flush := func() {
		if s := strings.TrimSpace(body[start:end]); s != "" {
			entries = append(entries, s)
		}
	}
	i := 0
	for i < len(body) {
		// A single- or double-quoted string cannot span lines in Bicep, so a
		// newline closes an unterminated one. Without this, one stray quote
		// merged every following entry into the malformed one and the
		// object's remaining keys disappeared.
		if body[i] == '\n' && st.inStr != 0 && !st.inMulti && !st.inCmt {
			st.inStr = 0
		}
		// Special cases only fire when we're not inside any string,
		// and only at top-level depth so nested object/array entries
		// preserve their commas and newlines.
		if st.inStr == 0 && !st.inMulti && st.totalDepth() == 0 {
			// Top-level newline/comma terminates the current entry.
			if body[i] == '\n' || body[i] == ',' {
				flush()
				i++
				start, end = i, i
				continue
			}
			// Drop `// …` line comments without copying them into the
			// running entry — without this they'd leak into the next
			// key or value.
			if body[i] == '/' && i+1 < len(body) && body[i+1] == '/' {
				for i+1 < len(body) && body[i+1] != '\n' {
					i++
				}
				i++
				continue
			}
		}
		next := st.stepAt(body, i)
		// Extend the entry over the bytes we just walked — escape sequences
		// (`\'`, `\\`, …) are preserved verbatim because stepAt walks the
		// escape pair as a single step.
		end = next
		i = next
	}
	flush()
	return entries
}

// extractTags pulls a `tags: { ... }` block out of a resource body and
// returns the literal key/value pairs as a map. Expression-valued tags are
// dropped; the resource's `properties` dict still surfaces the raw text.
//
// Entries are split with the shared string-aware scanner rather than matched
// one per line. A line-anchored pattern required every pair to sit alone on
// its own line, so the inline form `tags: { env: 'prod', owner: 'x' }` matched
// nothing and a correctly tagged resource reported no tags at all.
func extractTags(body string) map[string]string {
	raw := extractFieldBlock(body, "tags")
	if raw == "" {
		return nil
	}
	tags := map[string]string{}
	for _, entry := range splitTopLevelEntries(raw) {
		key, value, ok := splitFirstColon(entry)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		// Only literal values are surfaced here. An expression-valued tag
		// stays reachable through the resource's raw properties dict.
		if !isSingleQuotedLiteral(value) {
			continue
		}
		tags[unquoteBicepKey(strings.TrimSpace(key))] = value[1 : len(value)-1]
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}

// extractDependsOn returns the raw entries of a `dependsOn: [ ... ]` declared
// at the top level of body.
//
// The lookup is depth-aware for the same reason as extractFieldValue: an inline
// `properties.template` carries its own dependsOn, and matching it would report
// the nested template's dependencies as the resource's. splitTopLevelEntries
// handles both newline- and comma-separated entries and shares the string-aware
// lexer, so a `]` inside a string literal (`'[indexed]'`) or an indexed
// expression (`storageAccounts['blobServices']`) never splits the list early.
func extractDependsOn(body string) []string {
	value := topLevelFieldValue(body, "dependsOn")
	// Require a balanced list: an unterminated `[` is malformed input and
	// reports no dependencies rather than a partial list.
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil
	}
	deps := splitTopLevelEntries(stripOuter(value, '[', ']'))
	if len(deps) == 0 {
		return nil
	}
	return deps
}
