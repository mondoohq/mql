// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// aclRules is one permission set: either an access-control user's base rules or
// a single selector. Redis permits a command when the base rules allow it or
// when any one selector allows it, so the two are kept apart instead of being
// merged into one flat rule list.
type aclRules struct {
	keyPatterns     []any
	channelPatterns []any
	commandRules    []any
}

func newACLRules() aclRules {
	return aclRules{keyPatterns: []any{}, channelPatterns: []any{}, commandRules: []any{}}
}

// aclUser is the parsed form of one access-control user.
type aclUser struct {
	name          string
	enabled       bool
	nopass        bool
	passwordCount int64
	base          aclRules
	selectors     []aclRules
}

// apply applies one key, channel, or command rule token to the permission set.
// It reports whether the token was recognized, so a caller parsing a whole user
// can fall through to the user-level flags for the ones that are not.
func (a *aclRules) apply(tok string) bool {
	switch {
	case tok == "allkeys", tok == "~*":
		// allkeys supersedes any narrower pattern rather than adding to it.
		a.keyPatterns = []any{"*"}
	case tok == "resetkeys":
		a.keyPatterns = []any{}
	case strings.HasPrefix(tok, "~"):
		a.keyPatterns = append(a.keyPatterns, aclUnquote(tok[1:]))
	case strings.HasPrefix(tok, "%"):
		// Read/write-qualified key pattern (Redis 7.0+), for example "%RW~foo:*".
		i := strings.IndexByte(tok, '~')
		if i < 0 {
			return false
		}
		a.keyPatterns = append(a.keyPatterns, aclUnquote(tok[i+1:]))
	case tok == "allchannels", tok == "&*":
		a.channelPatterns = []any{"*"}
	case tok == "resetchannels":
		a.channelPatterns = []any{}
	case strings.HasPrefix(tok, "&"):
		a.channelPatterns = append(a.channelPatterns, aclUnquote(tok[1:]))
	case tok == "allcommands":
		a.commandRules = append(a.commandRules, "+@all")
	case tok == "nocommands":
		a.commandRules = append(a.commandRules, "-@all")
	case strings.HasPrefix(tok, "+"), strings.HasPrefix(tok, "-"):
		a.commandRules = append(a.commandRules, tok)
	default:
		return false
	}
	return true
}

func (a *aclRules) applyAll(tokens []string) {
	for _, tok := range tokens {
		a.apply(tok)
	}
}

// aclUnquote strips a matching pair of surrounding quotes from a pattern.
func aclUnquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// aclTokens splits an ACL rule string into tokens. Whitespace separates tokens,
// except inside quotes and except inside a parenthesized selector, which is
// returned whole with its nesting intact so its rules are never mistaken for
// the surrounding rule set. A "(" only opens a group at the start of a token,
// so a parenthesis inside a key pattern such as "~foo(bar)*" stays literal.
// Unbalanced quotes or parentheses yield the trailing text as one token rather
// than an error, so a malformed line degrades instead of panicking.
func aclTokens(s string) []string {
	tokens := []string{}
	var cur strings.Builder
	var quote rune
	depth := 0
	started := false

	flush := func() {
		if started {
			tokens = append(tokens, cur.String())
			cur.Reset()
			started = false
		}
	}

	for _, r := range s {
		switch {
		case quote != 0:
			cur.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
			started = true
			cur.WriteRune(r)
		case r == '(' && (!started || depth > 0):
			depth++
			started = true
			cur.WriteRune(r)
		case r == ')' && depth > 0:
			cur.WriteRune(r)
			depth--
			if depth == 0 {
				flush()
			}
		case depth == 0 && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			flush()
		default:
			started = true
			cur.WriteRune(r)
		}
	}
	flush()
	return tokens
}

// parseACLLine parses a single ACL LIST line in ACL-file format:
//
//	user <name> on|off [nopass|#<hash>...] [~<key>|allkeys|%RW~<key>] [&<chan>|allchannels] [+cmd|-cmd|+@cat|-@cat]... [(<selector rules>)]...
//
// It is the fallback for servers or credentials that will not answer
// ACL GETUSER; the structured reply is preferred when it is available.
func parseACLLine(line string) aclUser {
	u := aclUser{base: newACLRules()}
	toks := aclTokens(line)
	if len(toks) < 2 || toks[0] != "user" {
		return u
	}
	u.name = aclUnquote(toks[1])

	for _, tok := range toks[2:] {
		if strings.HasPrefix(tok, "(") {
			u.selectors = append(u.selectors, parseACLSelector(tok))
			continue
		}
		switch {
		case tok == "on":
			u.enabled = true
		case tok == "off":
			u.enabled = false
		case tok == "nopass":
			u.nopass = true
		case tok == "clearselectors":
			u.selectors = nil
		case tok == "reset":
			u = aclUser{name: u.name, base: newACLRules()}
		case strings.HasPrefix(tok, "#"), strings.HasPrefix(tok, ">"):
			u.passwordCount++
		default:
			// Unrecognized flags (sanitize-payload and the like) are ignored.
			u.base.apply(tok)
		}
	}
	return u
}

// parseACLSelector parses one parenthesized selector, for example
// "(+set ~staging:* &news.*)". An unterminated selector is parsed from the text
// that is there.
func parseACLSelector(tok string) aclRules {
	body := strings.TrimSuffix(strings.TrimPrefix(tok, "("), ")")
	rules := newACLRules()
	rules.applyAll(aclTokens(body))
	return rules
}

// aclUserFromGetUser builds a user from an ACL GETUSER reply, which reports the
// rules structurally and keeps every selector separate from the base rules. It
// reports false when the reply is not in a shape it recognizes, so the caller
// can fall back to parsing the ACL LIST line.
func aclUserFromGetUser(name string, reply any) (aclUser, bool) {
	fields, ok := aclReplyMap(reply)
	if !ok {
		return aclUser{}, false
	}

	u := aclUser{name: name, base: aclRulesFromReply(fields)}
	for _, flag := range aclReplyStrings(fields["flags"]) {
		switch flag {
		case "on":
			u.enabled = true
		case "off":
			u.enabled = false
		case "nopass":
			u.nopass = true
		}
	}
	u.passwordCount = int64(len(aclReplyStrings(fields["passwords"])))

	// Selectors were added in Redis 7.0; older servers omit the field entirely.
	items, _ := fields["selectors"].([]any)
	for _, item := range items {
		selFields, ok := aclReplyMap(item)
		if !ok {
			continue
		}
		u.selectors = append(u.selectors, aclRulesFromReply(selFields))
	}
	return u, true
}

// aclRulesFromReply builds one permission set from the commands, keys, and
// channels entries of an ACL GETUSER reply or of one of its selectors.
func aclRulesFromReply(fields map[string]any) aclRules {
	rules := newACLRules()
	rules.applyAll(aclReplyRuleTokens(fields["commands"], ""))
	rules.applyAll(aclReplyRuleTokens(fields["keys"], "~"))
	rules.applyAll(aclReplyRuleTokens(fields["channels"], "&"))
	return rules
}

// aclReplyRuleTokens turns one ACL GETUSER entry into rule tokens. Redis 7.0
// and later return each entry as a single rule string ("~a:* ~b:*"); before 7.0
// keys and channels came back as an array of bare patterns ("a:*"), which
// prefix restores to rule form.
func aclReplyRuleTokens(v any, prefix string) []string {
	switch val := v.(type) {
	case string:
		return aclTokens(val)
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			s, ok := item.(string)
			if !ok || s == "" {
				continue
			}
			if prefix != "" && !strings.HasPrefix(s, prefix) && !strings.HasPrefix(s, "%") {
				s = prefix + s
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}

// aclReplyMap normalizes one ACL GETUSER reply, or one of its selector entries,
// into a field map. Under RESP3 it arrives as a map; under RESP2 as a flat
// array of alternating field names and values.
func aclReplyMap(v any) (map[string]any, bool) {
	switch val := v.(type) {
	case map[string]any:
		return val, true
	case map[any]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			if s, ok := k.(string); ok {
				out[s] = item
			}
		}
		return out, true
	case []any:
		out := make(map[string]any, len(val)/2)
		for i := 0; i+1 < len(val); i += 2 {
			if s, ok := val[i].(string); ok {
				out[s] = val[i+1]
			}
		}
		return out, true
	}
	return nil, false
}

// aclReplyStrings reads an array-of-strings entry, skipping anything else.
func aclReplyStrings(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (r *mqlRedisdbInstance) users() ([]any, error) {
	conn := redisdbConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	ctx := conn.Context()

	lines, err := client.ACLList(ctx).Result()
	if err != nil {
		// Reading the ACL roster needs the +acl privilege; treat a denial as no
		// visible users rather than failing the whole asset.
		if isNoPerm(err) {
			return []any{}, nil
		}
		return nil, err
	}

	serverID := conn.ServerID()
	list := []any{}
	for _, line := range lines {
		u := parseACLLine(line)
		if u.name == "" {
			continue
		}

		// ACL GETUSER reports the rules structurally, so selectors stay separate
		// from the base rules and no rule text has to be taken apart by hand.
		// The driver has no typed command for it, so it goes through the generic
		// command interface; when the server or the credential will not answer,
		// the parsed ACL LIST line stands in.
		if reply, err := client.Do(ctx, "acl", "getuser", u.name).Result(); err == nil {
			if parsed, ok := aclUserFromGetUser(u.name, reply); ok {
				u = parsed
			}
		}

		res, err := CreateResource(r.MqlRuntime, "redisdb.acl.user", map[string]*llx.RawData{
			"__id":            llx.StringData(serverID + "/user/" + u.name),
			"name":            llx.StringData(u.name),
			"isDefault":       llx.BoolData(u.name == "default"),
			"enabled":         llx.BoolData(u.enabled),
			"nopass":          llx.BoolData(u.nopass),
			"passwordCount":   llx.IntData(u.passwordCount),
			"keyPatterns":     llx.ArrayData(u.base.keyPatterns, types.String),
			"channelPatterns": llx.ArrayData(u.base.channelPatterns, types.String),
			"commandRules":    llx.ArrayData(u.base.commandRules, types.String),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlRedisdbAclUser).selectorCache = u.selectors
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlRedisdbAclUser) selectors() ([]any, error) {
	list := make([]any, 0, len(r.selectorCache))
	for i, sel := range r.selectorCache {
		res, err := CreateResource(r.MqlRuntime, "redisdb.acl.selector", map[string]*llx.RawData{
			"__id":            llx.StringData(r.__id + "/selector/" + strconv.Itoa(i)),
			"commandRules":    llx.ArrayData(sel.commandRules, types.String),
			"keyPatterns":     llx.ArrayData(sel.keyPatterns, types.String),
			"channelPatterns": llx.ArrayData(sel.channelPatterns, types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
