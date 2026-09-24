// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"strconv"
	"strings"
)

// rsyslogEntryKind tags the structural role of a parsed directive so the
// resource accessors can filter the unified entry list without re-parsing.
type rsyslogEntryKind int

const (
	rsyslogKindModule rsyslogEntryKind = iota
	rsyslogKindInput
	rsyslogKindAction
	rsyslogKindRule
	// rsyslogKindModuleDefaults carries module-wide settings set through a
	// legacy directive (`$InputTCPServerStreamDriverMode 1`). It is never
	// surfaced as a resource; inputs of that module inherit its parameters.
	rsyslogKindModuleDefaults
	// rsyslogKindGlobal carries `global(...)` parameters or one legacy global
	// directive, keyed by the `global()` parameter name.
	rsyslogKindGlobal
	// rsyslogKindRuleset is a `ruleset(name=...)` declaration or the first
	// `$RuleSet <name>` for a name. The name is in `ruleset`.
	rsyslogKindRuleset
)

// rsyslogEntry is the unified intermediate representation produced by the
// per-file parser. Each typed-resource accessor on rsyslog.conf turns these
// into the matching `[]any` of mql resources.
type rsyslogEntry struct {
	kind       rsyslogEntryKind
	sourceFile string
	sourceLine int

	// module fields
	moduleName string
	parameters map[string]any

	// input/action fields shared
	moduleType       string
	target           string
	protocol         string
	port             int64
	address          string
	ruleset          string
	streamDriverMode string
	tlsEnabled       bool
	template         string
	queue            map[string]any

	// rule fields
	facilities []string
	severities []string
	negate     bool
	// actionOffset is the distance from a rule to the action entry that
	// backs it within the same entry list, or 0 when the rule's target could
	// not be parsed into an action.
	actionOffset int

	// action context
	condition string
	// legacy is set for an action built from a legacy target token rather
	// than an `action(...)` statement.
	legacy bool
	// inheritedStreamDriver and inheritedAuthMode are the legacy
	// `$ActionSendStreamDriver` / `...AuthMode` in effect for a modern omfwd
	// action, which rsyslog applies when the action sets neither.
	inheritedStreamDriver string
	inheritedAuthMode     string
	// fileSettings are the legacy `$File*` settings in effect for a legacy
	// file target, keyed filecreatemode / fileowner / filegroup.
	fileSettings map[string]string

	// effective action settings, filled once every file is parsed
	fileCreateMode       string
	fileOwner            string
	fileGroup            string
	streamDriver         string
	streamDriverAuthMode string

	// id is the resource cache key, assigned once all files are parsed.
	id string
}

// rsyslogLine is a single logical config line tagged with its origin.
// coalesceIncludeBlocks already collapses multi-line modern statements;
// we extend it for typed-parser consumers that need source attribution.
type rsyslogLine struct {
	text       string
	sourceFile string
	sourceLine int
}

// rsyslogBlockKeywords names the modern RainerScript top-level keywords
// whose `keyword(...)` form may span multiple lines and needs coalescing
// before the per-keyword parser runs. The set is intentionally narrow:
// every keyword listed here is parsed as a statement or an include.
var rsyslogBlockKeywords = map[string]bool{
	"module":  true,
	"input":   true,
	"action":  true,
	"global":  true,
	"ruleset": true,
	"include": true,
}

// coalesceRsyslogLines walks a single file's content, strips comments,
// drops blanks, and joins lines that are inside an unterminated
// `keyword(...)` block from the rsyslogBlockKeywords set. The returned
// lines carry the source line number of the *opening* token so audits
// can point at the directive head, not its closing paren.
func coalesceRsyslogLines(sourceFile, content string) []rsyslogLine {
	return coalesceParenBlocks(sourceFile, content, func(line string) bool {
		return hasBlockKeyword(line) || hasEmbeddedAction(line)
	})
}

// rsyslogEmbeddedAction matches an `action(` that follows a filter rather
// than starting the line: `*.* action(`, `if ... then action(`, `& action(`.
var rsyslogEmbeddedAction = regexp.MustCompile(`[\s&{]action\s*\(`)

// hasEmbeddedAction reports whether a line opens an `action(...)` statement
// after a selector, `if ... then`, or `&` prefix. Quoted strings are blanked
// first so a template or property value containing "action(" is ignored.
func hasEmbeddedAction(line string) bool {
	return rsyslogEmbeddedAction.MatchString(blankQuoted(line))
}

// blankQuoted replaces the contents of double- and single-quoted strings with
// spaces, keeping the quotes and the string length.
func blankQuoted(line string) string {
	b := []byte(line)
	var quote byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case quote != 0 && c == '\\' && i+1 < len(b):
			b[i], b[i+1] = ' ', ' '
			i++
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			b[i] = ' '
		case c == '"' || c == '\'':
			quote = c
		}
	}
	return string(b)
}

// coalesceParenBlocks is the shared paren-block coalescer used by both
// `coalesceRsyslogLines` (modern RainerScript module/input/action/global
// blocks) and `coalesceIncludeBlocks` (modern `include(...)` blocks).
// The `isBlockStart` predicate decides which leading tokens open a block;
// every other line passes through one-per-source-line. Lines carry the
// source file and the line number of the opening token so callers can
// point findings at the directive head, not the closing paren.
func coalesceParenBlocks(sourceFile, content string, isBlockStart func(string) bool) []rsyslogLine {
	rawLines := strings.Split(content, "\n")
	var out []rsyslogLine
	var pending strings.Builder
	openParens := 0
	pendingLineNo := 0

	for i, raw := range rawLines {
		ln := i + 1
		line := stripRsyslogComment(raw)
		line = strings.TrimSpace(line)
		if line == "" && openParens == 0 {
			continue
		}

		if openParens == 0 && isBlockStart(line) {
			openParens = countUnquotedParens(line)
			if openParens == 0 {
				out = append(out, rsyslogLine{text: line, sourceFile: sourceFile, sourceLine: ln})
				continue
			}
			pendingLineNo = ln
			pending.WriteString(line)
			continue
		}
		if openParens > 0 {
			if pending.Len() > 0 {
				pending.WriteByte(' ')
			}
			pending.WriteString(line)
			openParens += countUnquotedParens(line)
			if openParens <= 0 {
				out = append(out, rsyslogLine{
					text:       pending.String(),
					sourceFile: sourceFile,
					sourceLine: pendingLineNo,
				})
				pending.Reset()
				openParens = 0
			}
			continue
		}
		out = append(out, rsyslogLine{text: line, sourceFile: sourceFile, sourceLine: ln})
	}

	if pending.Len() > 0 {
		out = append(out, rsyslogLine{
			text:       pending.String(),
			sourceFile: sourceFile,
			sourceLine: pendingLineNo,
		})
	}
	return out
}

// hasBlockKeyword returns true when a line begins with one of the
// RainerScript keywords listed in rsyslogBlockKeywords followed by an
// opening paren. The check is whitespace-tolerant.
func hasBlockKeyword(line string) bool {
	for kw := range rsyslogBlockKeywords {
		if strings.HasPrefix(line, kw) {
			rest := strings.TrimLeft(line[len(kw):], " \t")
			if strings.HasPrefix(rest, "(") {
				return true
			}
		}
	}
	return false
}

// rsyslogModLoad matches the legacy `$ModLoad <module>` form, case-insensitive.
var rsyslogModLoad = regexp.MustCompile(`(?i)^\$ModLoad\s+(\S+)\s*$`)

// rsyslogInputDirectiveLegacy matches the legacy `$Input...Run <value>`
// directives that configure a network listener. The captured group is the
// directive suffix ("TCPServerRun"/"UDPServerRun"/...) so we can tell port
// directives apart from address/protocol directives.
var rsyslogInputDirectiveLegacy = regexp.MustCompile(`(?i)^\$Input(\w+)\s+(.+)$`)

// rsyslogModernStmt matches a modern `keyword(...)` block where the inner
// args have already been coalesced onto a single line.
var rsyslogModernStmt = regexp.MustCompile(`^(module|input|action|global)\s*\((.*)\)\s*$`)

// rsyslogSelector matches one or more legacy "<facility>.<severity>"
// selectors separated by `;`, followed by the target token. Selector
// list members are split inside the rule emitter.
//
// The regex is intentionally permissive on the selector half (anything
// that isn't whitespace until the target) so audits get a typed entry
// even for forms we don't otherwise model — the rule's `facilities`/
// `severities` arrays simply reflect what we could parse. `=` is part of
// the class so severity comparison prefixes (`=info`, `!=info`) don't cut
// the selector short before the target token.
var rsyslogSelector = regexp.MustCompile(`^([!*=A-Za-z0-9_,;.\-]+)\s+(\S.*)$`)

// rsyslogFacilitySeverity matches a single "facility.severity" pair where
// each side may be a list (comma-separated) or `*`. Used inside the
// per-selector loop, after splitting on `;`.
//
// The severity may carry an optional comparison prefix: `=` (exactly this
// severity), `!` (all except this severity), or `!=` (negate-exact). The
// `!?=?` prefix accepts “, `=`, `!`, and `!=` — but not the invalid `=!`
// ordering — so selectors like `mail.info`, `mail.=info`, `mail.!info`, and
// `mail.!=info` all parse. The prefix is preserved verbatim in the captured
// severity token; downstream inspection only special-cases the `.none`
// negation, which is unaffected by these prefixes.
var rsyslogFacilitySeverity = regexp.MustCompile(`^([!*A-Za-z0-9_,\-]+)\.(!?=?[*A-Za-z0-9]+)$`)

// kvRegexp matches a single key="value" / key='value' / key=bareword pair
// inside a coalesced modern statement's argument list. `.` is permitted in
// keys so dotted parameters like `queue.type` and `StreamDriver.Mode` aren't
// silently mis-tokenized as a bare `type`/`Mode` overwriting the outer
// `type=`/`Mode=` value.
var kvRegexp = regexp.MustCompile(`([\w.]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|(\S+))`)

// rsyslogActionStmt matches a coalesced `action(...)` statement, used for the
// action half of a filter line (`*.* action(...)`, `if ... then action(...)`).
var rsyslogActionStmt = regexp.MustCompile(`^action\s*\((.*)\)\s*$`)

// rsyslogIfThen matches a single-line RainerScript conditional,
// `if <expression> then <action>`. The action half may be a legacy target,
// an `action(...)` statement, `stop`, or the opening of a `{` block.
var rsyslogIfThen = regexp.MustCompile(`^if\s+(.+?)\s+then(?:\s+(.*))?$`)

// rsyslogPropertyFilter matches a property-based filter,
// `:property, [!]operation, "value" <action>`.
var rsyslogPropertyFilter = regexp.MustCompile(`^:([A-Za-z0-9_$!.\-]+)\s*,\s*(!?[A-Za-z_\-]+)\s*,\s*"(?:[^"\\]|\\.)*"\s*(.*)$`)

// rsyslogContinuation matches `& <action>`, an additional action that
// runs for the same filter as the statement above it.
var rsyslogContinuation = regexp.MustCompile(`^&\s*(.*)$`)

// rsyslogRulesetStmt matches a coalesced `ruleset(...)` declaration and
// whatever follows it on the same line (usually the opening `{`).
var rsyslogRulesetStmt = regexp.MustCompile(`^ruleset\s*\((.*)\)\s*(.*)$`)

// rsyslogUDPServerRun matches imudp's legacy `$UDPServerRun <port>`.
var rsyslogUDPServerRun = regexp.MustCompile(`(?i)^\$UDPServerRun\s+(\d+)\s*$`)

// rsyslogLegacyDirective splits a legacy `$Directive value` line.
var rsyslogLegacyDirective = regexp.MustCompile(`^\$(\w+)(?:\s+(.*))?$`)

// rsyslogDefaultRuleset is the ruleset that statements outside any
// `ruleset()` block, and inputs without a `ruleset=` binding, belong to.
const rsyslogDefaultRuleset = "RSYSLOG_DefaultRuleset"

// rsyslogSendStreamDriverKeys maps the legacy `$ActionSendStreamDriver*`
// directives onto the omfwd action parameter names they stand for.
var rsyslogSendStreamDriverKeys = map[string]string{
	"actionsendstreamdriver":              "streamdriver",
	"actionsendstreamdrivermode":          "streamdrivermode",
	"actionsendstreamdriverauthmode":      "streamdriverauthmode",
	"actionsendstreamdriverpermittedpeer": "streamdriverpermittedpeers",
	"actionsendstreamdriverremotesni":     "streamdriver.remotesni",
}

// rsyslogInputStreamDriverKeys maps the legacy `$InputTCPServerStreamDriver*`
// directives onto the imtcp module parameter names they stand for.
var rsyslogInputStreamDriverKeys = map[string]string{
	"inputtcpserverstreamdrivermode":          "streamdriver.mode",
	"inputtcpserverstreamdriverauthmode":      "streamdriver.authmode",
	"inputtcpserverstreamdriverpermittedpeer": "permittedpeer",
}

// rsyslogInputBindRulesetKeys maps the legacy `$Input*ServerBindRuleset`
// directives onto the input module whose later listeners they bind.
var rsyslogInputBindRulesetKeys = map[string]string{
	"inputtcpserverbindruleset":  "imtcp",
	"inputptcpserverbindruleset": "imptcp",
	"inputudpserverbindruleset":  "imudp",
	"inputrelpserverbindruleset": "imrelp",
}

// rsyslogLegacyGlobalKeys maps legacy global directives onto the `global()`
// parameter each one sets, so both forms land under one key in
// `rsyslog.conf.globals`.
var rsyslogLegacyGlobalKeys = map[string]string{
	"workdirectory":                      "workdirectory",
	"defaultnetstreamdriver":             "defaultnetstreamdriver",
	"defaultnetstreamdrivercafile":       "defaultnetstreamdrivercafile",
	"defaultnetstreamdrivercrlfile":      "defaultnetstreamdrivercrlfile",
	"defaultnetstreamdrivercertfile":     "defaultnetstreamdrivercertfile",
	"defaultnetstreamdriverkeyfile":      "defaultnetstreamdriverkeyfile",
	"netstreamdrivercaextrafiles":        "netstreamdrivercaextrafiles",
	"defaultopensslengine":               "defaultopensslengine",
	"localhostname":                      "localhostname",
	"preservefqdn":                       "preservefqdn",
	"maxmessagesize":                     "maxmessagesize",
	"dropmsgswithmaliciousdnsptrrecords": "dropmsgswithmaliciousdnsptrrecords",
	"umask":                              "umask",
	"privdroptouser":                     "privdrop.user.name",
	"privdroptouserid":                   "privdrop.user.id",
	"privdroptogroup":                    "privdrop.group.name",
	"privdroptogroupid":                  "privdrop.group.id",
	"controlcharacterescapeprefix":       "parser.controlcharacterescapeprefix",
	"droptrailinglfonreception":          "parser.droptrailinglfonreception",
	"escapecontrolcharactersonreceive":   "parser.escapecontrolcharactersonreceive",
	"escape8bitcharactersonreceive":      "parser.escape8bitcharactersonreceive",
	"escapecontrolcharactertab":          "parser.escapecontrolcharactertab",
	"spacelfonreceive":                   "parser.spacelfonreceive",
}

// rsyslogBlock is one open `{` scope: an `if`/`else` branch, a `ruleset()`
// body, or a brace pair the parser does not interpret.
type rsyslogBlock struct {
	condition string
	ruleset   string
}

// rsyslogParser carries the state rsyslog applies to later statements while
// it reads a configuration top to bottom, following includes where they
// appear:
//
//   - `$ActionQueue*` and `$ActionResumeRetryCount` apply to the next action
//     only. rsyslog resets them once any action is defined.
//   - `$ActionSendStreamDriver*` apply to every later TCP forward until
//     `$ResetConfigVariables`. A modern omfwd action picks up the driver
//     name and auth mode, but not the mode.
//   - `$FileCreateMode`, `$FileOwner`, and `$FileGroup` apply to every later
//     legacy file target until `$ResetConfigVariables`. Modern omfile
//     actions ignore them.
//   - `$RuleSet` and `ruleset() { }` blocks place later statements in a
//     ruleset, and `if ... then { }` blocks give them a condition.
//   - `$Input*ServerBindRuleset` binds later legacy listeners of a module.
type rsyslogParser struct {
	nextQueue        map[string]any
	nextParams       map[string]any
	sendStreamDriver map[string]any
	legacyFile       map[string]string
	legacyRuleset    string
	bindRuleset      map[string]string
	udpServerAddress string
	blocks           []rsyslogBlock
	// pendingBlock is opened by the next `{` line, for a `ruleset(...)` or
	// `if ... then` whose brace sits on the following line.
	pendingBlock  *rsyslogBlock
	lastCondition string

	// include, when set, is called for every include directive with the
	// pattern and the file it appears in; it parses the matched files in
	// place through parseFile.
	include func(pattern, sourceFile string)
	out     []rsyslogEntry
}

func newRsyslogParser() *rsyslogParser {
	p := &rsyslogParser{}
	p.resetConfigVariables()
	p.bindRuleset = map[string]string{}
	return p
}

// resetConfigVariables mirrors `$ResetConfigVariables`.
func (p *rsyslogParser) resetConfigVariables() {
	p.sendStreamDriver = map[string]any{}
	p.legacyFile = map[string]string{}
	p.resetPerAction()
}

// resetPerAction drops the settings that apply to the next action only.
func (p *rsyslogParser) resetPerAction() {
	p.nextQueue = map[string]any{}
	p.nextParams = map[string]any{}
}

// parseRsyslogFile produces a unified list of typed entries from one
// rsyslog config fragment, without following its includes. Source
// attribution (file path + 1-indexed line number) is preserved on every
// entry so callers can build rsyslog.module / .input / .action / .rule
// resources that point back at the originating fragment.
func parseRsyslogFile(sourceFile, content string) []rsyslogEntry {
	p := newRsyslogParser()
	p.parseFile(sourceFile, content)
	return p.out
}

// parseFile parses one file into p.out, handing include directives to
// p.include so the included files are read at the point of their include.
func (p *rsyslogParser) parseFile(sourceFile, content string) {
	for _, l := range coalesceRsyslogLines(sourceFile, content) {
		if p.include != nil {
			if patterns := parseRsyslogIncludes(l.text); len(patterns) > 0 {
				for _, pattern := range patterns {
					p.include(pattern, sourceFile)
				}
				continue
			}
		}
		p.out = append(p.out, p.statement(l)...)
	}
}

// currentRuleset is the ruleset a statement at this point belongs to: the
// innermost `ruleset()` block, else the last `$RuleSet`, else the default.
func (p *rsyslogParser) currentRuleset() string {
	for i := len(p.blocks) - 1; i >= 0; i-- {
		if p.blocks[i].ruleset != "" {
			return p.blocks[i].ruleset
		}
	}
	if p.legacyRuleset != "" {
		return p.legacyRuleset
	}
	return rsyslogDefaultRuleset
}

// withBlockConditions prefixes a statement's own filter with the conditions
// of the `if` blocks enclosing it.
func (p *rsyslogParser) withBlockConditions(own string) string {
	var parts []string
	for _, b := range p.blocks {
		if b.condition != "" {
			parts = append(parts, b.condition)
		}
	}
	if own != "" {
		parts = append(parts, own)
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return "(" + strings.Join(parts, ") and (") + ")"
}

// statement classifies a single (already coalesced) logical line and emits
// zero or more typed entries. Most lines emit exactly one entry; legacy
// multi-selector rules ("*.info;mail.none /path") fan out to one entry per
// selector so each `facility.severity → target` pair is independently
// queryable.
func (p *rsyslogParser) statement(l rsyslogLine) []rsyslogEntry {
	line := l.text

	// Block structure first: a closing brace may carry an `else` branch.
	if strings.HasPrefix(line, "}") {
		return p.closeBlock(l)
	}
	if strings.HasPrefix(line, "{") {
		b := rsyslogBlock{}
		if p.pendingBlock != nil {
			b = *p.pendingBlock
			p.pendingBlock = nil
		}
		return p.openBlock(l, b, strings.TrimSpace(line[1:]))
	}

	// Legacy $ModLoad first — cheapest and most common.
	if m := rsyslogModLoad.FindStringSubmatch(line); m != nil {
		return []rsyslogEntry{{
			kind:       rsyslogKindModule,
			sourceFile: l.sourceFile,
			sourceLine: l.sourceLine,
			moduleName: m[1],
			parameters: map[string]any{},
		}}
	}

	// Legacy $InputXxxRun network listeners. These come in pairs in real
	// configs ($InputTCPServerRun 514, $InputUDPServerBindRuleset name).
	// We surface the *Run directives as inputs; the supporting directives
	// feed the listener's settings.
	if m := rsyslogInputDirectiveLegacy.FindStringSubmatch(line); m != nil {
		if input, ok := legacyInputFromDirective(m[1], strings.TrimSpace(m[2])); ok {
			input.sourceFile = l.sourceFile
			input.sourceLine = l.sourceLine
			input.ruleset = p.bindRuleset[input.moduleType]
			return []rsyslogEntry{input}
		}
	}

	// imudp's legacy listener has no `$Input` prefix.
	if m := rsyslogUDPServerRun.FindStringSubmatch(line); m != nil {
		port, _ := strconv.ParseInt(m[1], 10, 64)
		return []rsyslogEntry{{
			kind:       rsyslogKindInput,
			sourceFile: l.sourceFile,
			sourceLine: l.sourceLine,
			moduleType: "imudp",
			port:       port,
			address:    p.udpServerAddress,
			ruleset:    p.bindRuleset["imudp"],
			parameters: map[string]any{},
		}}
	}

	if m := rsyslogLegacyDirective.FindStringSubmatch(line); m != nil {
		return p.legacyDirective(l, strings.ToLower(m[1]), strings.TrimSpace(m[2]))
	}

	if m := rsyslogRulesetStmt.FindStringSubmatch(line); m != nil {
		return p.rulesetDecl(l, parseKVArgs(m[1]), strings.TrimSpace(m[2]))
	}

	// Modern keyword(...) statements: module / input / action / global.
	if m := rsyslogModernStmt.FindStringSubmatch(line); m != nil {
		keyword := m[1]
		params := parseKVArgs(m[2])
		switch keyword {
		case "module":
			return []rsyslogEntry{moduleFromModern(l, params)}
		case "input":
			return []rsyslogEntry{inputFromModern(l, params)}
		case "action":
			p.lastCondition = p.withBlockConditions("")
			return p.stampAction(actionFromModern(l, params), p.lastCondition, false)
		case "global":
			return []rsyslogEntry{{
				kind:       rsyslogKindGlobal,
				sourceFile: l.sourceFile,
				sourceLine: l.sourceLine,
				parameters: params,
			}}
		}
	}

	// Filters without a selector: the action is surfaced, but there is no
	// facility/severity rule to attach it to.
	if m := rsyslogIfThen.FindStringSubmatch(line); m != nil {
		return p.ifThen(l, strings.TrimSpace(m[1]), strings.TrimSpace(m[2]))
	}
	if m := rsyslogPropertyFilter.FindStringSubmatch(line); m != nil {
		cond := strings.TrimSpace(strings.TrimSuffix(line, m[3]))
		p.lastCondition = p.withBlockConditions(cond)
		return p.actionsFor(l, m[3], p.lastCondition)
	}
	if m := rsyslogContinuation.FindStringSubmatch(line); m != nil {
		return p.actionsFor(l, m[1], p.lastCondition)
	}

	// Legacy selector rule: "<facility>.<severity>[;...] <target>".
	if m := rsyslogSelector.FindStringSubmatch(line); m != nil {
		selectorList := m[1]
		target := strings.TrimSpace(m[2])
		// Ignore lines that match the selector regex but aren't actually
		// selectors — `$Directive value`, `:property, ...`, modern
		// keyword-paren forms, ruleset/if-then bracket lines, etc.
		if selectorList == "" || strings.HasPrefix(selectorList, "$") ||
			strings.HasPrefix(selectorList, ":") || strings.HasPrefix(selectorList, "&") ||
			selectorList == "if" || selectorList == "ruleset" || selectorList == "call" ||
			selectorList == "include" {
			return nil
		}
		rules := selectorRuleEntries(selectorList, target)
		if len(rules) == 0 {
			return nil
		}
		for i := range rules {
			rules[i].sourceFile = l.sourceFile
			rules[i].sourceLine = l.sourceLine
			rules[i].ruleset = p.currentRuleset()
		}
		// The selector is the rule's own filter; enclosing `if` blocks
		// still narrow what reaches it.
		p.lastCondition = p.withBlockConditions("")
		actions := p.actionsFor(l, target, p.lastCondition)
		if len(actions) > 0 {
			// The action follows the rules in the returned list.
			for i := range rules {
				rules[i].actionOffset = len(rules) - i
			}
		}
		return append(rules, actions...)
	}

	return nil
}

// openBlock pushes a `{` scope. Text after the brace on the same line is
// parsed as a statement inside the block.
func (p *rsyslogParser) openBlock(l rsyslogLine, b rsyslogBlock, rest string) []rsyslogEntry {
	p.blocks = append(p.blocks, b)
	if rest == "" {
		return nil
	}
	return p.statement(rsyslogLine{text: rest, sourceFile: l.sourceFile, sourceLine: l.sourceLine})
}

// closeBlock pops the innermost `{` scope. `} else {`, `} else if ... then`,
// and `} else <action>` continue with the opposite branch.
func (p *rsyslogParser) closeBlock(l rsyslogLine) []rsyslogEntry {
	var closed rsyslogBlock
	if n := len(p.blocks); n > 0 {
		closed = p.blocks[n-1]
		p.blocks = p.blocks[:n-1]
	}
	rest := strings.TrimSpace(strings.TrimPrefix(l.text, "}"))
	if !strings.HasPrefix(rest, "else") {
		if rest == "" {
			return nil
		}
		return p.statement(rsyslogLine{text: rest, sourceFile: l.sourceFile, sourceLine: l.sourceLine})
	}

	rest = strings.TrimSpace(strings.TrimPrefix(rest, "else"))
	elseCond := ""
	if closed.condition != "" {
		elseCond = "not (" + closed.condition + ")"
	}
	switch {
	case rsyslogIfThen.MatchString(rest):
		m := rsyslogIfThen.FindStringSubmatch(rest)
		return p.ifThen(l, joinRsyslogConditions(elseCond, strings.TrimSpace(m[1])), strings.TrimSpace(m[2]))
	case strings.HasPrefix(rest, "{"):
		return p.openBlock(l, rsyslogBlock{condition: elseCond}, strings.TrimSpace(rest[1:]))
	case rest == "":
		p.pendingBlock = &rsyslogBlock{condition: elseCond}
		return nil
	default:
		p.lastCondition = p.withBlockConditions(elseCond)
		return p.actionsFor(l, rest, p.lastCondition)
	}
}

// ifThen handles `if <cond> then <rest>`: an action on the same line, a
// block opening on this line or the next, or a one-line `{ ... }` block.
func (p *rsyslogParser) ifThen(l rsyslogLine, cond, rest string) []rsyslogEntry {
	if rest == "" {
		p.pendingBlock = &rsyslogBlock{condition: cond}
		return nil
	}
	if strings.HasPrefix(rest, "{") && !strings.HasSuffix(rest, "}") {
		return p.openBlock(l, rsyslogBlock{condition: cond}, strings.TrimSpace(rest[1:]))
	}
	p.lastCondition = p.withBlockConditions(cond)
	return p.actionsFor(l, rest, p.lastCondition)
}

func joinRsyslogConditions(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return "(" + a + ") and (" + b + ")"
}

// rulesetDecl records a `ruleset(name="...")` declaration and opens its
// block when the brace is on the same line.
func (p *rsyslogParser) rulesetDecl(l rsyslogLine, params map[string]any, rest string) []rsyslogEntry {
	name, _ := params["name"].(string)
	decl := rsyslogEntry{
		kind:       rsyslogKindRuleset,
		sourceFile: l.sourceFile,
		sourceLine: l.sourceLine,
		ruleset:    name,
		parameters: copyParamsWithout(params, "name"),
	}
	b := rsyslogBlock{ruleset: name}
	switch {
	case strings.HasPrefix(rest, "{"):
		return append([]rsyslogEntry{decl}, p.openBlock(l, b, strings.TrimSpace(rest[1:]))...)
	case rest == "":
		p.pendingBlock = &b
	}
	return []rsyslogEntry{decl}
}

// legacyDirective records the `$Directive value` lines that change how later
// statements behave. Directives that only matter at the configuration level
// are left to `rsyslog.conf.params`.
func (p *rsyslogParser) legacyDirective(l rsyslogLine, name, value string) []rsyslogEntry {
	switch {
	case name == "resetconfigvariables":
		p.resetConfigVariables()
	case name == "actionresumeretrycount":
		p.nextParams["action.resumeretrycount"] = value
	case strings.HasPrefix(name, "actionqueue"):
		// `$ActionQueueSize` → `size`, matching the modern `queue.size` key.
		p.nextQueue[strings.TrimPrefix(name, "actionqueue")] = value
	case rsyslogSendStreamDriverKeys[name] != "":
		p.sendStreamDriver[rsyslogSendStreamDriverKeys[name]] = value
	case name == "filecreatemode" || name == "fileowner" || name == "fileownernum" ||
		name == "filegroup" || name == "filegroupnum":
		p.legacyFile[strings.TrimSuffix(name, "num")] = value
	case name == "ruleset":
		p.legacyRuleset = value
		if value == "" || value == rsyslogDefaultRuleset {
			return nil
		}
		return []rsyslogEntry{{
			kind:       rsyslogKindRuleset,
			sourceFile: l.sourceFile,
			sourceLine: l.sourceLine,
			ruleset:    value,
			parameters: map[string]any{},
		}}
	case name == "udpserveraddress":
		p.udpServerAddress = value
	case rsyslogInputBindRulesetKeys[name] != "":
		p.bindRuleset[rsyslogInputBindRulesetKeys[name]] = value
	case rsyslogInputStreamDriverKeys[name] != "":
		return []rsyslogEntry{{
			kind:       rsyslogKindModuleDefaults,
			sourceFile: l.sourceFile,
			sourceLine: l.sourceLine,
			moduleName: "imtcp",
			parameters: map[string]any{rsyslogInputStreamDriverKeys[name]: value},
		}}
	case rsyslogLegacyGlobalKeys[name] != "":
		return []rsyslogEntry{{
			kind:       rsyslogKindGlobal,
			sourceFile: l.sourceFile,
			sourceLine: l.sourceLine,
			parameters: map[string]any{rsyslogLegacyGlobalKeys[name]: value},
		}}
	}
	return nil
}

// actionsFor parses the action half of a filter line. It accepts a modern
// `action(...)` statement, a legacy target token (`/var/log/x`, `@@host:514`,
// `:omusrmsg:*`, `~`, `stop`), or a `{ ... }` block holding one of those on
// the same line. Anything else yields no action rather than a guessed one.
func (p *rsyslogParser) actionsFor(l rsyslogLine, text, condition string) []rsyslogEntry {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") {
		text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text[1:]), "}"))
	}

	switch m := rsyslogActionStmt.FindStringSubmatch(text); {
	case m != nil:
		return p.stampAction(actionFromModern(l, parseKVArgs(m[1])), condition, false)
	case text != "" && !strings.ContainsAny(text, " \t"):
		e := p.legacyAction(text)
		e.sourceFile = l.sourceFile
		e.sourceLine = l.sourceLine
		return p.stampAction(e, condition, true)
	default:
		return nil
	}
}

// stampAction attaches the parser's context to an action: its ruleset and
// condition, and for a modern omfwd action the legacy stream driver name and
// auth mode it inherits. It consumes the next-action settings.
func (p *rsyslogParser) stampAction(e rsyslogEntry, condition string, legacy bool) []rsyslogEntry {
	e.condition = condition
	e.ruleset = p.currentRuleset()
	e.legacy = legacy
	if !legacy && e.moduleType == "omfwd" {
		e.inheritedStreamDriver, _ = p.sendStreamDriver["streamdriver"].(string)
		e.inheritedAuthMode, _ = p.sendStreamDriver["streamdriverauthmode"].(string)
	}
	p.resetPerAction()
	return []rsyslogEntry{e}
}

// legacyAction builds the action behind a legacy target token, applying the
// `$Action*` and `$File*` directive state that precedes it.
func (p *rsyslogParser) legacyAction(token string) rsyslogEntry {
	target, template, _ := strings.Cut(token, ";")
	moduleType, protocol := classifySelectorTarget(target)

	params := map[string]any{}
	for k, v := range p.nextParams {
		params[k] = v
	}
	queue := map[string]any{}
	for k, v := range p.nextQueue {
		queue[k] = v
	}
	tlsEnabled := false
	// rsyslog applies the send stream driver settings to TCP forwards only.
	if moduleType == "omfwd" && protocol == "tcp" {
		for k, v := range p.sendStreamDriver {
			params[k] = v
		}
		tlsEnabled = p.sendStreamDriver["streamdrivermode"] == "1"
	}
	var fileSettings map[string]string
	if moduleType == "omfile" {
		fileSettings = map[string]string{}
		for k, v := range p.legacyFile {
			fileSettings[k] = v
		}
	}

	return rsyslogEntry{
		kind:         rsyslogKindAction,
		moduleType:   moduleType,
		target:       legacyTargetValue(moduleType, target),
		protocol:     protocol,
		tlsEnabled:   tlsEnabled,
		template:     strings.TrimSpace(template),
		queue:        queue,
		parameters:   params,
		fileSettings: fileSettings,
	}
}

// legacyTargetValue strips the syntax that selects the output module from a
// legacy target token, leaving the destination itself:
//
//	@@(o,z9)host:514   -> host:514
//	-/var/log/syslog   -> /var/log/syslog
//	|/dev/xconsole     -> /dev/xconsole
//	:omrelp:host:2514  -> host:2514
//	:omusrmsg:root     -> root
func legacyTargetValue(moduleType, target string) string {
	switch {
	case moduleType == "omfwd":
		t := strings.TrimLeft(target, "@")
		if strings.HasPrefix(t, "(") {
			if i := strings.Index(t, ")"); i >= 0 {
				t = t[i+1:]
			}
		}
		return t
	case moduleType == "ompipe":
		return strings.TrimPrefix(target, "|")
	case strings.HasPrefix(target, ":"):
		if i := strings.Index(target[1:], ":"); i > 0 {
			return target[i+2:]
		}
		return target
	case moduleType == "omfile":
		return strings.TrimPrefix(target, "-")
	default:
		return target
	}
}

// rsyslogOmfileModules names the module that holds omfile's module-wide
// defaults in `module(load=...)`.
var rsyslogOmfileModules = map[string]bool{"builtin:omfile": true, "omfile": true}

// resolveConfigDefaults applies the configuration-wide settings that rsyslog
// resolves regardless of where they appear:
//
//   - imtcp inputs take `StreamDriver.*` and `PermittedPeer` from
//     `module(load="imtcp")` or `$InputTCPServerStreamDriver*` unless the
//     input sets its own.
//   - modern omfile actions take `fileCreateMode`, `fileOwner`, and
//     `fileGroup` from `module(load="builtin:omfile")`.
//   - TCP forwards without a stream driver of their own use the global
//     `DefaultNetstreamDriver`.
func resolveConfigDefaults(entries []rsyslogEntry) {
	moduleParams := map[string]map[string]any{}
	globals := map[string]any{}
	for _, e := range entries {
		switch e.kind {
		case rsyslogKindModule, rsyslogKindModuleDefaults:
			name := strings.ToLower(e.moduleName)
			if moduleParams[name] == nil {
				moduleParams[name] = map[string]any{}
			}
			for k, v := range e.parameters {
				moduleParams[name][k] = v
			}
		case rsyslogKindGlobal:
			for k, v := range e.parameters {
				globals[k] = v
			}
		}
	}
	omfileDefaults := map[string]any{}
	for name := range rsyslogOmfileModules {
		for k, v := range moduleParams[name] {
			omfileDefaults[k] = v
		}
	}
	defaultDriver, _ := globals["defaultnetstreamdriver"].(string)

	for i := range entries {
		e := &entries[i]
		switch e.kind {
		case rsyslogKindInput:
			inheritInputStreamDriver(e, moduleParams[strings.ToLower(e.moduleType)])
		case rsyslogKindAction:
			resolveActionDefaults(e, omfileDefaults, defaultDriver)
		}
	}
}

func inheritInputStreamDriver(e *rsyslogEntry, module map[string]any) {
	if len(module) == 0 {
		return
	}
	if e.parameters == nil {
		e.parameters = map[string]any{}
	}
	for k, v := range module {
		if !strings.HasPrefix(k, "streamdriver.") && k != "permittedpeer" {
			continue
		}
		if _, ok := e.parameters[k]; !ok {
			e.parameters[k] = v
		}
	}
	if e.streamDriverMode == "" {
		e.streamDriverMode = paramString(e.parameters, "streamdriver.mode", "streamdrivermode")
	}
}

// rsyslogDefaultFileCreateMode is omfile's file creation mode when nothing
// sets one.
const rsyslogDefaultFileCreateMode = "0644"

func resolveActionDefaults(e *rsyslogEntry, omfileDefaults map[string]any, defaultDriver string) {
	switch e.moduleType {
	case "omfile":
		settings := map[string]string{}
		if e.legacy {
			settings = e.fileSettings
		} else {
			for _, k := range []string{"filecreatemode", "fileowner", "filegroup"} {
				if v := paramString(e.parameters, k, k+"num"); v != "" {
					settings[k] = v
				} else if v := paramString(omfileDefaults, k, k+"num"); v != "" {
					settings[k] = v
				}
			}
		}
		e.fileCreateMode = settings["filecreatemode"]
		if e.fileCreateMode == "" {
			e.fileCreateMode = rsyslogDefaultFileCreateMode
		}
		e.fileOwner = settings["fileowner"]
		e.fileGroup = settings["filegroup"]
	case "omfwd":
		if e.protocol != "tcp" {
			return
		}
		e.streamDriver = paramString(e.parameters, "streamdriver", "streamdriver.name")
		if e.streamDriver == "" {
			e.streamDriver = e.inheritedStreamDriver
		}
		if e.streamDriver == "" {
			e.streamDriver = defaultDriver
		}
		e.streamDriverAuthMode = paramString(e.parameters, "streamdriverauthmode", "streamdriver.authmode")
		if e.streamDriverAuthMode == "" {
			e.streamDriverAuthMode = e.inheritedAuthMode
		}
	}
}

// rsyslogRemoteOutputs names the output modules that deliver messages to
// another host over the network.
var rsyslogRemoteOutputs = map[string]bool{
	"omfwd":            true,
	"omrelp":           true,
	"omhttp":           true,
	"omkafka":          true,
	"omelasticsearch":  true,
	"omgssapi":         true,
	"omudpspoof":       true,
	"omamqp1":          true,
	"omrabbitmq":       true,
	"omazureeventhubs": true,
	"omclickhouse":     true,
	"omhiredis":        true,
	"ommongodb":        true,
	"ommysql":          true,
	"ompgsql":          true,
	"omlibdbi":         true,
	"omsnmp":           true,
	"ommail":           true,
}

// rsyslogActionPort is the port a network action connects to. omfwd and
// omrelp default to 514; an action that is not a network action reports 0.
func rsyslogActionPort(e rsyslogEntry) int64 {
	if _, ok := e.parameters["port"]; ok {
		return parseIntParam(e.parameters, "port")
	}
	if e.legacy {
		if _, port, ok := splitRsyslogHostPort(e.target); ok {
			n, err := strconv.ParseInt(port, 10, 64)
			if err == nil {
				return n
			}
		}
	}
	if e.moduleType == "omfwd" || e.moduleType == "omrelp" {
		return 514
	}
	return 0
}

// splitRsyslogHostPort splits `host:port` or `[v6addr]:port`. A bare IPv6
// address without brackets has no port.
func splitRsyslogHostPort(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || !strings.HasPrefix(s[end+1:], ":") {
			return s, "", false
		}
		return s[1:end], s[end+2:], true
	}
	if strings.Count(s, ":") != 1 {
		return s, "", false
	}
	host, port, _ = strings.Cut(s, ":")
	return host, port, port != ""
}

// rsyslogResumeRetryCount is the action's configured retry count, or nil
// when the action does not set one (rsyslog then retries 0 times).
func rsyslogResumeRetryCount(e rsyslogEntry) *int64 {
	v, ok := e.parameters["action.resumeretrycount"]
	if !ok {
		return nil
	}
	s, _ := v.(string)
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

// moduleFromModern builds a module entry from a coalesced `module(...)` call.
// The `load` parameter is the module name; every other key/value pair is
// surfaced under `parameters`.
func moduleFromModern(l rsyslogLine, params map[string]any) rsyslogEntry {
	name, _ := params["load"].(string)
	delete(params, "load")
	return rsyslogEntry{
		kind:       rsyslogKindModule,
		sourceFile: l.sourceFile,
		sourceLine: l.sourceLine,
		moduleName: name,
		parameters: params,
	}
}

// inputFromModern builds an input entry from `input(type="..." port="..." ...)`.
// `port` is parsed as a base-10 int; non-numeric or absent values yield 0.
// `streamDriverMode` is preserved as a string to match the source representation
// (rsyslog accepts both `"1"` and `1`).
func inputFromModern(l rsyslogLine, params map[string]any) rsyslogEntry {
	typ, _ := params["type"].(string)
	port := parseIntParam(params, "port")
	address, _ := params["address"].(string)
	if address == "" {
		address, _ = params["host"].(string)
	}
	ruleset, _ := params["ruleset"].(string)
	streamDriverMode := paramString(params, "streamdriver.mode", "streamdrivermode")
	rest := copyParamsWithout(params, "type")
	return rsyslogEntry{
		kind:             rsyslogKindInput,
		sourceFile:       l.sourceFile,
		sourceLine:       l.sourceLine,
		moduleType:       typ,
		port:             port,
		address:          address,
		ruleset:          ruleset,
		streamDriverMode: streamDriverMode,
		parameters:       rest,
	}
}

// actionFromModern builds an action entry from `action(type="..." target="..." ...)`.
// `tlsEnabled` is derived from `StreamDriverMode == "1"`; this catches both the
// per-action and inherited-from-input forms. Queue parameters are collected
// into a separate dict so audits can `.where(queue["type"] == "linkedlist")`.
func actionFromModern(l rsyslogLine, params map[string]any) rsyslogEntry {
	typ, _ := params["type"].(string)
	target := paramString(params, "target", "file", "users") // omfile uses `file=`, omusrmsg `users=`
	protocol := strings.ToLower(paramString(params, "protocol"))
	if protocol == "" && typ == "omfwd" {
		protocol = "udp" // omfwd's default transport
	}
	template, _ := params["template"].(string)
	streamDriverMode := paramString(params, "streamdriver.mode", "streamdrivermode")
	queue := collectPrefix(params, "queue.")
	rest := copyParamsWithout(params, "type")
	return rsyslogEntry{
		kind:       rsyslogKindAction,
		sourceFile: l.sourceFile,
		sourceLine: l.sourceLine,
		moduleType: typ,
		target:     target,
		protocol:   protocol,
		tlsEnabled: streamDriverMode == "1",
		template:   template,
		queue:      queue,
		parameters: rest,
	}
}

// legacyInputFromDirective interprets a `$InputXxxRun <value>` directive.
// rsyslog has a small enumerated set of these — the suffix tells us the
// module type and how to interpret the value:
//
//	TCPServerRun <port>   -> imtcp listening on <port>
//	UDPServerRun <port>   -> imudp listening on <port>
//	RELPServerRun <port>  -> imrelp listening on <port>
//	GSSServerRun <port>   -> imgssapi listening on <port>
//
// Other `$Input*` directives are configuration knobs (Bind, KeepAlive, ...)
// that we don't surface as standalone inputs — they appear in the global
// settings list instead.
func legacyInputFromDirective(suffix, value string) (rsyslogEntry, bool) {
	suffixLower := strings.ToLower(suffix)
	if !strings.HasSuffix(suffixLower, "serverrun") {
		return rsyslogEntry{}, false
	}
	prefix := suffixLower[:len(suffixLower)-len("serverrun")]
	moduleType := ""
	switch prefix {
	case "tcp":
		moduleType = "imtcp"
	case "udp":
		moduleType = "imudp"
	case "relp":
		moduleType = "imrelp"
	case "gss", "gssapi":
		moduleType = "imgssapi"
	default:
		return rsyslogEntry{}, false
	}
	port, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return rsyslogEntry{
		kind:       rsyslogKindInput,
		moduleType: moduleType,
		port:       port,
		parameters: map[string]any{},
	}, true
}

// selectorRuleEntries fans a legacy selector line out into one entry per
// `;`-separated selector. Negation (".none") is hoisted onto a single
// boolean rather than threaded into the severities list. Each rule entry
// carries the selector's facilities, severities, and the shared target.
func selectorRuleEntries(selectorList, target string) []rsyslogEntry {
	var out []rsyslogEntry
	for _, sel := range strings.Split(selectorList, ";") {
		sel = strings.TrimSpace(sel)
		if sel == "" {
			continue
		}
		m := rsyslogFacilitySeverity.FindStringSubmatch(sel)
		if m == nil {
			continue
		}
		facilities := splitCommaList(m[1])
		sevRaw := m[2]
		negate := false
		if strings.EqualFold(sevRaw, "none") {
			negate = true
			sevRaw = "none"
		}
		severities := splitCommaList(sevRaw)
		out = append(out, rsyslogEntry{
			kind:       rsyslogKindRule,
			facilities: facilities,
			severities: severities,
			target:     target,
			negate:     negate,
		})
	}
	return out
}

// classifySelectorTarget maps a legacy selector target token to an
// (output-module, transport-protocol) pair. The recognized forms are:
//
//	/path/to/file       -> omfile, ""
//	-/path/to/file      -> omfile, "" (the "-" disables sync writes)
//	@host[:port]        -> omfwd, "udp"
//	@@host[:port]       -> omfwd, "tcp"
//	:omusrmsg:user[,…]  -> omusrmsg, ""
//	:omhttp:url         -> omhttp, ""
//	~ or stop           -> discard, ""
//	|name               -> ompipe, ""
//	* (single char)     -> omusrmsg, "" (wall-message shorthand)
//
// Anything else falls through to omfile as the safe default — rsyslog
// itself treats unprefixed strings as filesystem paths.
func classifySelectorTarget(target string) (moduleType, protocol string) {
	switch {
	case target == "~" || target == "stop":
		return "discard", ""
	case target == "*":
		return "omusrmsg", ""
	case strings.HasPrefix(target, "@@"):
		return "omfwd", "tcp"
	case strings.HasPrefix(target, "@"):
		return "omfwd", "udp"
	case strings.HasPrefix(target, "|"):
		return "ompipe", ""
	case strings.HasPrefix(target, ":"):
		// Modern third-party output module shorthand: ":modname:args".
		if idx := strings.Index(target[1:], ":"); idx > 0 {
			return target[1 : 1+idx], ""
		}
		return "omfile", ""
	case strings.HasPrefix(target, "/") || strings.HasPrefix(target, "-/"):
		return "omfile", ""
	default:
		return "omfile", ""
	}
}

// parseKVArgs extracts every key=value pair from a modern statement's
// argument list. Keys are case-normalized to lowercase so callers can do
// case-insensitive lookups without re-walking the map. Values keep their
// source representation — string vs unquoted token — but quoted strings
// have surrounding quotes stripped and `\"` / `\'` unescaped.
func parseKVArgs(args string) map[string]any {
	out := map[string]any{}
	for _, m := range kvRegexp.FindAllStringSubmatch(args, -1) {
		key := strings.ToLower(m[1])
		var val string
		switch {
		case m[2] != "":
			val = unescapeQuoted(m[2])
		case m[3] != "":
			val = unescapeQuoted(m[3])
		default:
			val = m[4]
		}
		out[key] = val
	}
	return out
}

// unescapeQuoted reverses the lexer's `\"` / `\'` / `\\` escape sequences
// so values like `Template="hash\#tag"` come back with the literal `#`.
// rsyslog accepts plain backslash + char so this is intentionally narrow
// — anything outside the recognized triples is preserved verbatim.
func unescapeQuoted(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			if next == '"' || next == '\'' || next == '\\' || next == '#' {
				b.WriteByte(next)
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// paramString returns the first non-empty string-valued entry from the
// map among the supplied keys. The keys must already be lowercase since
// parseKVArgs case-normalizes incoming names.
func paramString(params map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := params[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// parseIntParam reads a key from params and tries hard to coerce it to
// int64. rsyslog accepts both numeric and string forms; we accept both
// so callers don't have to care which the source used. Unparseable
// values return 0.
func parseIntParam(params map[string]any, key string) int64 {
	v, ok := params[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// collectPrefix moves every key with the given prefix out of `params`
// and into a new map, stripping the prefix from the destination keys.
// Used to lift `queue.*` parameters into their own dict.
func collectPrefix(params map[string]any, prefix string) map[string]any {
	out := map[string]any{}
	for k, v := range params {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = v
			delete(params, k)
		}
	}
	return out
}

// copyParamsWithout returns a shallow copy of params with the given keys
// removed. The original map is left intact so callers that have already
// pulled values out still see those keys for debugging.
func copyParamsWithout(params map[string]any, keys ...string) map[string]any {
	out := make(map[string]any, len(params))
	skip := map[string]bool{}
	for _, k := range keys {
		skip[k] = true
	}
	for k, v := range params {
		if skip[k] {
			continue
		}
		out[k] = v
	}
	return out
}

// splitCommaList splits a comma-separated list (the form used by rsyslog
// for facility lists like `auth,authpriv` and severity lists). Whitespace
// around each item is trimmed; empty items are dropped.
func splitCommaList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
