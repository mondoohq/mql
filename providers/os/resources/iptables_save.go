// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SavedRule is a structured representation of a single `-A CHAIN ...` line
// from iptables-save output. Fields are populated from the parsed flags;
// fields that the rule does not set retain their zero value.
type SavedRule struct {
	// Chain is the chain this rule belongs to (INPUT, OUTPUT, user-defined, …).
	Chain string
	// Packets / Bytes come from the `[pkts:bytes]` counter prefix
	// emitted by `iptables-save -c`. Both are 0 when the prefix is missing.
	Packets int64
	Bytes   int64
	// Target is the `-j` (or `-g`) argument.
	Target string
	// Protocol is the `-p` argument, or "all" when unset (matching `-L` output).
	Protocol string
	// In / Out come from `-i` / `-o`. Empty when unset; the resource layer
	// substitutes "*" for parity with `-L`.
	In  string
	Out string
	// Source / Destination come from `-s` / `-d`. Empty when unset; the
	// resource layer substitutes the default any-address for parity with `-L`.
	Source      string
	Destination string

	// Structured options that previously had to be parsed out of the
	// trailing "options" blob of `-L` output.

	// Dport holds the parsed integer when `--dport` is a single port.
	// HasDport is true when `--dport` was matched (even if it is a range).
	Dport      int
	HasDport   bool
	DportRange string
	Dports     []string

	Sport      int
	HasSport   bool
	SportRange string
	Sports     []string

	Ctstate    []string
	TCPFlags   []string
	Comment    string
	MatchSet   string
	RejectWith string

	// Options is a best-effort `-L`-style rendering of the trailing match
	// text, used to keep the legacy `iptables.entry.options` field populated.
	Options string

	// Raw is the original `-A CHAIN ...` line, with the optional
	// `[pkts:bytes]` counter prefix stripped.
	Raw string
}

// SavedChain holds a chain's default policy plus the rules parsed for it.
type SavedChain struct {
	Name    string
	Policy  string // ACCEPT/DROP/REJECT, or "" for user-defined chains
	Builtin bool
	Rules   []SavedRule
}

// SavedTable holds the chains for a single iptables table.
type SavedTable struct {
	Name   string
	Chains []*SavedChain
}

// SavedDump is the full parsed output of one iptables-save invocation.
type SavedDump struct {
	Tables []*SavedTable
}

// reCounterPrefix matches the `[pkts:bytes]` counter prefix that
// `iptables-save -c` emits before each `-A` rule.
var reCounterPrefix = regexp.MustCompile(`^\[(\d+):(\d+)\]\s+`)

// rePolicy matches a `:CHAIN POLICY [pkts:bytes]` line.
var rePolicy = regexp.MustCompile(`^:(\S+)\s+(\S+)(?:\s+\[(\d+):(\d+)\])?\s*$`)

// reTable matches a `*tablename` line at the top of each table block.
var reTable = regexp.MustCompile(`^\*(\S+)\s*$`)

// ParseIptablesSave parses the output of `iptables-save -c` (or `-c`-less
// output, in which case packet/byte counters are 0). It tolerates blank
// lines and `#`-prefixed comments.
func ParseIptablesSave(output string) (*SavedDump, error) {
	dump := &SavedDump{}
	var current *SavedTable
	chains := map[string]*SavedChain{}

	for lineNo, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || trim == "COMMIT" {
			continue
		}

		if m := reTable.FindStringSubmatch(trim); m != nil {
			current = &SavedTable{Name: m[1]}
			chains = map[string]*SavedChain{}
			dump.Tables = append(dump.Tables, current)
			continue
		}

		if current == nil {
			return nil, fmt.Errorf("iptables-save line %d: data before any *table header: %q", lineNo+1, trim)
		}

		if m := rePolicy.FindStringSubmatch(trim); m != nil {
			name := m[1]
			policy := m[2]
			// If a rule already auto-created this chain (rule appeared
			// before its `:CHAIN` declaration), update it in place.
			ch, exists := chains[name]
			if !exists {
				ch = &SavedChain{Name: name}
				current.Chains = append(current.Chains, ch)
				chains[name] = ch
			}
			if policy == "-" {
				ch.Builtin = false
			} else {
				ch.Policy = policy
				ch.Builtin = true
			}
			continue
		}

		if strings.HasPrefix(trim, "-A ") || strings.HasPrefix(trim, "[") {
			rule, err := parseRuleLine(trim)
			if err != nil {
				return nil, fmt.Errorf("iptables-save line %d: %w", lineNo+1, err)
			}
			ch, ok := chains[rule.Chain]
			if !ok {
				// Some iptables-save outputs put rules before their chain
				// declarations; create the chain on the fly.
				ch = &SavedChain{Name: rule.Chain}
				current.Chains = append(current.Chains, ch)
				chains[rule.Chain] = ch
			}
			ch.Rules = append(ch.Rules, rule)
			continue
		}
	}

	return dump, nil
}

// parseRuleLine extracts the structured rule from a single
// `[pkts:bytes] -A CHAIN ...` line. The leading counter prefix is optional.
func parseRuleLine(line string) (SavedRule, error) {
	rule := SavedRule{Protocol: "all"}

	if m := reCounterPrefix.FindStringSubmatch(line); m != nil {
		pkts, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return rule, fmt.Errorf("packet counter: %w", err)
		}
		bytes, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			return rule, fmt.Errorf("byte counter: %w", err)
		}
		rule.Packets = pkts
		rule.Bytes = bytes
		line = line[len(m[0]):]
	}

	rule.Raw = line

	tokens, err := tokenize(line)
	if err != nil {
		return rule, err
	}
	if len(tokens) < 2 || tokens[0] != "-A" {
		return rule, errors.New("rule does not start with `-A CHAIN`")
	}
	rule.Chain = tokens[1]
	tokens = tokens[2:]

	var optionParts []string

	// neg renders a negated match the way `iptables -L` prints it: a
	// leading "!" on the value (`! -i lo` becomes "!lo").
	neg := func(negated bool, v string) string {
		if negated {
			return "!" + v
		}
		return v
	}
	negAll := func(negated bool, vals []string) []string {
		if !negated {
			return vals
		}
		for i := range vals {
			vals[i] = "!" + vals[i]
		}
		return vals
	}

	flushNegation := func(negated bool, parts ...string) {
		if negated {
			optionParts = append(optionParts, "!")
		}
		optionParts = append(optionParts, parts...)
	}

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		negated := false
		if tok == "!" {
			negated = true
			i++
			if i >= len(tokens) {
				break
			}
			tok = tokens[i]
		}

		switch tok {
		case "-p", "--protocol":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Protocol = v
				if negated {
					rule.Protocol = "!" + v
				}
			}
		case "-s", "--source":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Source = neg(negated, v)
			}
		case "-d", "--destination":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Destination = neg(negated, v)
			}
		case "-i", "--in-interface":
			if v, ok := nextArg(tokens, &i); ok {
				rule.In = neg(negated, v)
			}
		case "-o", "--out-interface":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Out = neg(negated, v)
			}
		case "-j", "--jump":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Target = v
			}
		case "-g", "--goto":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Target = v
			}
		case "-m", "--match":
			// `-m foo` introduces match options that follow.
			_, _ = nextArg(tokens, &i)
		case "--dport", "--destination-port":
			if v, ok := nextArg(tokens, &i); ok {
				rule.HasDport = true
				// A negated port is not a single port: `dport` stays
				// null and `dportRange` carries "!<port>".
				if negated || strings.Contains(v, ":") {
					rule.DportRange = neg(negated, v)
				} else if n, err := strconv.Atoi(v); err == nil {
					rule.Dport = n
				} else {
					rule.DportRange = v
				}
				flushNegation(negated, "dpt:"+v)
			}
		case "--sport", "--source-port":
			if v, ok := nextArg(tokens, &i); ok {
				rule.HasSport = true
				// A negated port is not a single port: `sport` stays
				// null and `sportRange` carries "!<port>".
				if negated || strings.Contains(v, ":") {
					rule.SportRange = neg(negated, v)
				} else if n, err := strconv.Atoi(v); err == nil {
					rule.Sport = n
				} else {
					rule.SportRange = v
				}
				flushNegation(negated, "spt:"+v)
			}
		case "--dports":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Dports = negAll(negated, splitCSV(v))
				flushNegation(negated, "dpts:"+v)
			}
		case "--sports":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Sports = negAll(negated, splitCSV(v))
				flushNegation(negated, "spts:"+v)
			}
		case "--state", "--ctstate":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Ctstate = negAll(negated, splitCSV(v))
				flushNegation(negated, "state", v)
			}
		case "--tcp-flags":
			mask, ok1 := nextArg(tokens, &i)
			comp, ok2 := nextArg(tokens, &i)
			if ok1 && ok2 {
				rule.TCPFlags = []string{neg(negated, mask), comp}
				flushNegation(negated, "flags:"+mask+"/"+comp)
			}
		case "--comment":
			if v, ok := nextArg(tokens, &i); ok {
				rule.Comment = v
				// Comments are surfaced separately via .comment but also
				// reflected in options for legacy compatibility.
				optionParts = append(optionParts, "/* "+v+" */")
			}
		case "--match-set":
			set, ok1 := nextArg(tokens, &i)
			dir, ok2 := nextArg(tokens, &i)
			if ok1 {
				rule.MatchSet = neg(negated, set)
				if ok2 {
					flushNegation(negated, "match-set", set, dir)
				} else {
					flushNegation(negated, "match-set", set)
				}
			}
		case "--reject-with":
			if v, ok := nextArg(tokens, &i); ok {
				rule.RejectWith = v
				optionParts = append(optionParts, "reject-with "+v)
			}
		default:
			// Unrecognized option: include it in `options` so the legacy
			// blob remains informative for things we don't (yet) parse.
			if name, ok := strings.CutPrefix(tok, "--"); ok {
				if v, hasArg := peekArg(tokens, i); hasArg {
					optionParts = append(optionParts, name+":"+v)
					i++
				} else {
					optionParts = append(optionParts, name)
				}
			}
		}
	}

	rule.Options = strings.Join(optionParts, " ")
	return rule, nil
}

// tokenize splits an iptables-save rule line into tokens, respecting
// double-quoted strings for `--comment` arguments (which can contain spaces).
// Backslash escapes inside quotes are honored for `\"` and `\\`.
func tokenize(line string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	escape := false

	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}

	for _, r := range line {
		switch {
		case escape:
			cur.WriteRune(r)
			escape = false
		case r == '\\':
			if inQuote {
				escape = true
			} else {
				cur.WriteRune(r)
			}
		case r == '"':
			inQuote = !inQuote
		case inQuote:
			cur.WriteRune(r)
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	if inQuote {
		return nil, errors.New("unterminated quoted string")
	}
	flush()
	return tokens, nil
}

// nextArg advances the cursor and returns the next token, or false at end.
func nextArg(tokens []string, i *int) (string, bool) {
	if *i+1 >= len(tokens) {
		return "", false
	}
	*i++
	return tokens[*i], true
}

// peekArg returns the token at i+1 if it exists and doesn't look like a flag.
func peekArg(tokens []string, i int) (string, bool) {
	if i+1 >= len(tokens) {
		return "", false
	}
	next := tokens[i+1]
	if strings.HasPrefix(next, "-") {
		return "", false
	}
	return next, true
}

// splitCSV splits a comma-separated value list, trimming whitespace.
// Empty inputs return nil rather than `[]string{""}`.
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
