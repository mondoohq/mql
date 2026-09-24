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
// before the per-keyword parser runs. The set is intentionally narrow —
// every keyword listed here participates in module/input/action parsing.
var rsyslogBlockKeywords = map[string]bool{
	"module": true,
	"input":  true,
	"action": true,
	"global": true,
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

// rsyslogLegacyDirective splits a legacy `$Directive value` line.
var rsyslogLegacyDirective = regexp.MustCompile(`^\$(\w+)(?:\s+(.*))?$`)

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

// rsyslogFileParser carries the legacy directive state that rsyslog applies
// to later statements in the same file:
//
//   - `$ActionQueue*` and `$ActionResumeRetryCount` apply to the next action
//     only. rsyslog resets them once any action is defined.
//   - `$ActionSendStreamDriver*` apply to every later legacy TCP forward
//     (`@@host`) until `$ResetConfigVariables`.
//
// State does not carry across files. rsyslog reads an included fragment at
// the point of its include, which the flat file list does not preserve, so a
// directive set in one file is not applied to actions in another.
type rsyslogFileParser struct {
	nextQueue        map[string]any
	nextParams       map[string]any
	sendStreamDriver map[string]any
}

func newRsyslogFileParser() *rsyslogFileParser {
	p := &rsyslogFileParser{sendStreamDriver: map[string]any{}}
	p.resetPerAction()
	return p
}

// resetPerAction drops the settings that apply to the next action only.
func (p *rsyslogFileParser) resetPerAction() {
	p.nextQueue = map[string]any{}
	p.nextParams = map[string]any{}
}

// parseRsyslogFile produces a unified list of typed entries from one
// rsyslog config fragment. Source attribution (file path + 1-indexed
// line number) is preserved on every entry so callers can build
// rsyslog.module / .input / .action / .rule resources that point back
// at the originating fragment.
func parseRsyslogFile(sourceFile, content string) []rsyslogEntry {
	p := newRsyslogFileParser()
	var out []rsyslogEntry
	for _, l := range coalesceRsyslogLines(sourceFile, content) {
		out = append(out, p.statement(l)...)
	}
	return out
}

// statement classifies a single (already coalesced) logical line and emits
// zero or more typed entries. Most lines emit exactly one entry; legacy
// multi-selector rules ("*.info;mail.none /path") fan out to one entry per
// selector so each `facility.severity → target` pair is independently
// queryable.
func (p *rsyslogFileParser) statement(l rsyslogLine) []rsyslogEntry {
	line := l.text

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
	// We surface the *Run directives as inputs; supporting directives
	// (BindRuleset, etc.) are not modeled standalone.
	if m := rsyslogInputDirectiveLegacy.FindStringSubmatch(line); m != nil {
		if input, ok := legacyInputFromDirective(m[1], strings.TrimSpace(m[2])); ok {
			input.sourceFile = l.sourceFile
			input.sourceLine = l.sourceLine
			return []rsyslogEntry{input}
		}
	}

	if m := rsyslogLegacyDirective.FindStringSubmatch(line); m != nil {
		return p.legacyDirective(l, strings.ToLower(m[1]), strings.TrimSpace(m[2]))
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
			p.resetPerAction()
			return []rsyslogEntry{actionFromModern(l, params)}
			// `global` is parsed elsewhere; nothing to emit as a typed entry here.
		}
	}

	// Filters without a selector: the action is surfaced, but there is no
	// facility/severity rule to attach it to.
	if m := rsyslogIfThen.FindStringSubmatch(line); m != nil {
		return p.actionsFor(l, m[2])
	}
	if m := rsyslogPropertyFilter.FindStringSubmatch(line); m != nil {
		return p.actionsFor(l, m[3])
	}
	if m := rsyslogContinuation.FindStringSubmatch(line); m != nil {
		return p.actionsFor(l, m[1])
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
		}
		actions := p.actionsFor(l, target)
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

// legacyDirective records the `$Directive value` lines that change how later
// statements behave. Directives that only matter at the configuration level
// are left to `rsyslog.conf.params`.
func (p *rsyslogFileParser) legacyDirective(l rsyslogLine, name, value string) []rsyslogEntry {
	switch {
	case name == "resetconfigvariables":
		p.sendStreamDriver = map[string]any{}
		p.resetPerAction()
	case name == "actionresumeretrycount":
		p.nextParams["action.resumeretrycount"] = value
	case strings.HasPrefix(name, "actionqueue"):
		// `$ActionQueueSize` → `size`, matching the modern `queue.size` key.
		p.nextQueue[strings.TrimPrefix(name, "actionqueue")] = value
	case rsyslogSendStreamDriverKeys[name] != "":
		p.sendStreamDriver[rsyslogSendStreamDriverKeys[name]] = value
	case rsyslogInputStreamDriverKeys[name] != "":
		return []rsyslogEntry{{
			kind:       rsyslogKindModuleDefaults,
			sourceFile: l.sourceFile,
			sourceLine: l.sourceLine,
			moduleName: "imtcp",
			parameters: map[string]any{rsyslogInputStreamDriverKeys[name]: value},
		}}
	}
	return nil
}

// actionsFor parses the action half of a filter line. It accepts a modern
// `action(...)` statement, a legacy target token (`/var/log/x`, `@@host:514`,
// `:omusrmsg:*`, `~`, `stop`), or a `{ ... }` block holding one of those on
// the same line. Anything else yields no action rather than a guessed one.
func (p *rsyslogFileParser) actionsFor(l rsyslogLine, text string) []rsyslogEntry {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") {
		text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text[1:]), "}"))
	}

	var e rsyslogEntry
	switch m := rsyslogActionStmt.FindStringSubmatch(text); {
	case m != nil:
		e = actionFromModern(l, parseKVArgs(m[1]))
	case text != "" && !strings.ContainsAny(text, " \t"):
		e = p.legacyAction(text)
		e.sourceFile = l.sourceFile
		e.sourceLine = l.sourceLine
	default:
		return nil
	}
	p.resetPerAction()
	return []rsyslogEntry{e}
}

// legacyAction builds the action behind a legacy target token, applying the
// `$Action*` directive state that precedes it.
func (p *rsyslogFileParser) legacyAction(token string) rsyslogEntry {
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

	return rsyslogEntry{
		kind:       rsyslogKindAction,
		moduleType: moduleType,
		target:     legacyTargetValue(moduleType, target),
		protocol:   protocol,
		tlsEnabled: tlsEnabled,
		template:   strings.TrimSpace(template),
		queue:      queue,
		parameters: params,
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

// applyModuleDefaults copies module-wide stream driver settings onto the
// inputs of that module that don't set their own. An imtcp listener takes
// its TLS mode from `module(load="imtcp" StreamDriver.Mode="1")` or the
// legacy `$InputTCPServerStreamDriverMode 1` unless the input overrides it.
// Module settings are configuration-wide in rsyslog, so this runs across
// every parsed file rather than per file.
func applyModuleDefaults(entries []rsyslogEntry) {
	defaults := map[string]map[string]any{}
	for _, e := range entries {
		if e.kind != rsyslogKindModule && e.kind != rsyslogKindModuleDefaults {
			continue
		}
		name := strings.ToLower(e.moduleName)
		for k, v := range e.parameters {
			if !strings.HasPrefix(k, "streamdriver.") && k != "permittedpeer" {
				continue
			}
			if defaults[name] == nil {
				defaults[name] = map[string]any{}
			}
			defaults[name][k] = v
		}
	}
	if len(defaults) == 0 {
		return
	}

	for i := range entries {
		e := &entries[i]
		if e.kind != rsyslogKindInput {
			continue
		}
		d := defaults[strings.ToLower(e.moduleType)]
		if len(d) == 0 {
			continue
		}
		if e.parameters == nil {
			e.parameters = map[string]any{}
		}
		for k, v := range d {
			if _, ok := e.parameters[k]; !ok {
				e.parameters[k] = v
			}
		}
		if e.streamDriverMode == "" {
			e.streamDriverMode = paramString(e.parameters, "streamdriver.mode", "streamdrivermode")
		}
	}
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
	target, _ := params["target"].(string)
	if target == "" {
		target, _ = params["file"].(string) // omfile uses `file=`
	}
	protocol, _ := params["protocol"].(string)
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
