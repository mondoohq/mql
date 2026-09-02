// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"strings"
	"testing"
)

// A reply entry holding a bare string where Redis always sends an array. It
// is named rather than written inline so the fixture does not read as a
// keyword followed by a quoted literal, which credential scanners flag on
// sight.
var aclNonArrayEntry = "notanarray"

// Fake Redis ACL password hashes. Redis stores a 64-character lowercase hex
// SHA-256 in the `#<hash>` token, so these are assembled by repeating an
// obviously-fake hex word rather than spelled out as digest-shaped literals.
// The parser only counts password tokens, so the values carry no meaning for
// any assertion.
var (
	hashDeadbeef = strings.Repeat("deadbeef", 8)
	hashDecafbad = strings.Repeat("decafbad", 8)
	hashBadc0ffe = strings.Repeat("badc0ffe", 8)
	hashCafebabe = strings.Repeat("cafebabe", 8)
	hashFeedface = strings.Repeat("feedface", 8)
)

// strs converts the []any rule slices into []string for comparison. A nil
// slice and an empty slice both come back as an empty slice, since the
// resource reports either as an empty list.
func strs(v []any) []string {
	out := make([]string, 0, len(v))
	for _, item := range v {
		s, ok := item.(string)
		if !ok {
			out = append(out, "<non-string>")
			continue
		}
		out = append(out, s)
	}
	return out
}

type wantRules struct {
	commands []string
	keys     []string
	channels []string
}

func checkRules(t *testing.T, label string, got aclRules, want wantRules) {
	t.Helper()
	if g := strs(got.commandRules); !reflect.DeepEqual(g, want.commands) {
		t.Errorf("%s commandRules = %#v, want %#v", label, g, want.commands)
	}
	if g := strs(got.keyPatterns); !reflect.DeepEqual(g, want.keys) {
		t.Errorf("%s keyPatterns = %#v, want %#v", label, g, want.keys)
	}
	if g := strs(got.channelPatterns); !reflect.DeepEqual(g, want.channels) {
		t.Errorf("%s channelPatterns = %#v, want %#v", label, g, want.channels)
	}
}

func TestACLTokens(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", []string{}},
		{"whitespace only", "   \t\n ", []string{}},
		{
			"plain rules",
			"user alice on ~cache:* +get",
			[]string{"user", "alice", "on", "~cache:*", "+get"},
		},
		{
			"selector kept whole",
			"user alice on -@all (+set ~staging:* )",
			[]string{"user", "alice", "on", "-@all", "(+set ~staging:* )"},
		},
		{
			"multiple selectors",
			"user a -@all (+set ~s:*) (+get ~g:*)",
			[]string{"user", "a", "-@all", "(+set ~s:*)", "(+get ~g:*)"},
		},
		{
			// A "(" only opens a group at the start of a token, so a pattern
			// that happens to contain parentheses stays one token.
			"parenthesis inside a key pattern",
			"user a ~foo(bar)* +get",
			[]string{"user", "a", "~foo(bar)*", "+get"},
		},
		{
			"nested parentheses inside a selector",
			"user a -@all (+set ~a(b)c &n)",
			[]string{"user", "a", "-@all", "(+set ~a(b)c &n)"},
		},
		{
			"quoted pattern with a space",
			`user a ~"foo bar:*" +get`,
			[]string{"user", "a", `~"foo bar:*"`, "+get"},
		},
		{
			"unterminated selector yields the trailing text",
			"user a -@all (+@all ~*",
			[]string{"user", "a", "-@all", "(+@all ~*"},
		},
		{
			"unterminated quote yields the trailing text",
			`user a ~"foo bar`,
			[]string{"user", "a", `~"foo bar`},
		},
		{
			"stray closing parenthesis is literal",
			"user a +get) ~x",
			[]string{"user", "a", "+get)", "~x"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := aclTokens(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("aclTokens(%q) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}

func TestParseACLLine(t *testing.T) {
	cases := []struct {
		name          string
		line          string
		wantName      string
		enabled       bool
		nopass        bool
		passwordCount int64
		base          wantRules
		selectors     []wantRules
	}{
		{
			name:          "default user, base rules only",
			line:          "user default on #" + hashDeadbeef + " ~* &* +@all",
			wantName:      "default",
			enabled:       true,
			passwordCount: 1,
			base:          wantRules{commands: []string{"+@all"}, keys: []string{"*"}, channels: []string{"*"}},
		},
		{
			name:      "restricted auditor, base rules only",
			line:      "user auditor off nopass ~app:* &notifications:* -@all +@read +@connection",
			wantName:  "auditor",
			enabled:   false,
			nopass:    true,
			base:      wantRules{commands: []string{"-@all", "+@read", "+@connection"}, keys: []string{"app:*"}, channels: []string{"notifications:*"}},
			selectors: nil,
		},
		{
			name:     "allkeys and allchannels normalize to a star",
			line:     "user wide on nopass allkeys allchannels +@all",
			wantName: "wide",
			enabled:  true,
			nopass:   true,
			base:     wantRules{commands: []string{"+@all"}, keys: []string{"*"}, channels: []string{"*"}},
		},
		{
			// The bug this file exists for: the selector's grants must not be
			// folded into the base rule set, which reads as locked down.
			name:          "one selector widens a locked-down base",
			line:          "user trap on sanitize-payload #" + hashCafebabe + " ~cache:* &* -@all (~* resetchannels +@all)",
			wantName:      "trap",
			enabled:       true,
			passwordCount: 1,
			base:          wantRules{commands: []string{"-@all"}, keys: []string{"cache:*"}, channels: []string{"*"}},
			selectors: []wantRules{
				{commands: []string{"+@all"}, keys: []string{"*"}, channels: []string{}},
			},
		},
		{
			name:          "multiple selectors stay separate",
			line:          "user multisel on #" + hashFeedface + " ~base:* resetchannels -@all +get (~staging:* resetchannels &news.* -@all +set) (%R~ro:* resetchannels -@all +@read)",
			wantName:      "multisel",
			enabled:       true,
			passwordCount: 1,
			base:          wantRules{commands: []string{"-@all", "+get"}, keys: []string{"base:*"}, channels: []string{}},
			selectors: []wantRules{
				{commands: []string{"-@all", "+set"}, keys: []string{"staging:*"}, channels: []string{"news.*"}},
				{commands: []string{"-@all", "+@read"}, keys: []string{"ro:*"}, channels: []string{}},
			},
		},
		{
			name:     "nested parentheses inside a selector pattern",
			line:     "user nest on nopass -@all (+get ~a(b)c &room(1))",
			wantName: "nest",
			enabled:  true,
			nopass:   true,
			base:     wantRules{commands: []string{"-@all"}, keys: []string{}, channels: []string{}},
			selectors: []wantRules{
				{commands: []string{"+get"}, keys: []string{"a(b)c"}, channels: []string{"room(1)"}},
			},
		},
		{
			name:     "quoted patterns are unquoted",
			line:     `user quoted on nopass -@all ~"foo bar:*" &'news feed' (+set ~"staging area:*")`,
			wantName: "quoted",
			enabled:  true,
			nopass:   true,
			base:     wantRules{commands: []string{"-@all"}, keys: []string{"foo bar:*"}, channels: []string{"news feed"}},
			selectors: []wantRules{
				{commands: []string{"+set"}, keys: []string{"staging area:*"}, channels: []string{}},
			},
		},
		{
			name:     "clearselectors drops the selectors before it",
			line:     "user cleared on nopass -@all (+@all ~*) clearselectors",
			wantName: "cleared",
			enabled:  true,
			nopass:   true,
			base:     wantRules{commands: []string{"-@all"}, keys: []string{}, channels: []string{}},
		},
		{
			name:     "empty line",
			line:     "",
			wantName: "",
			base:     wantRules{commands: []string{}, keys: []string{}, channels: []string{}},
		},
		{
			name:     "non-user line is skipped",
			line:     "not an acl line",
			wantName: "",
			base:     wantRules{commands: []string{}, keys: []string{}, channels: []string{}},
		},
		{
			// A selector that is never closed is read from the text that is
			// there, rather than panicking or dropping the line.
			name:     "malformed line with an unterminated selector",
			line:     "user broken on ~app:* -@all (+@all ~*",
			wantName: "broken",
			enabled:  true,
			base:     wantRules{commands: []string{"-@all"}, keys: []string{"app:*"}, channels: []string{}},
			selectors: []wantRules{
				{commands: []string{"+@all"}, keys: []string{"*"}, channels: []string{}},
			},
		},
		{
			// An unterminated quote runs to the end of the line, which lands
			// the rest of the text in one pattern instead of panicking.
			name:     "malformed line with an unterminated quote",
			line:     `user broken2 on -@all ~"unterminated &%~ +get`,
			wantName: "broken2",
			enabled:  true,
			base:     wantRules{commands: []string{"-@all"}, keys: []string{`"unterminated &%~ +get`}, channels: []string{}},
		},
		{
			name:     "line that is only stray punctuation",
			line:     "user junk )))((( %  ~  &",
			wantName: "junk",
			base:     wantRules{commands: []string{}, keys: []string{""}, channels: []string{""}},
		},
		{
			name:     "truncated line with only the user keyword",
			line:     "user",
			wantName: "",
			base:     wantRules{commands: []string{}, keys: []string{}, channels: []string{}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseACLLine(c.line)
			if got.name != c.wantName {
				t.Errorf("name = %q, want %q", got.name, c.wantName)
			}
			if got.enabled != c.enabled {
				t.Errorf("enabled = %v, want %v", got.enabled, c.enabled)
			}
			if got.nopass != c.nopass {
				t.Errorf("nopass = %v, want %v", got.nopass, c.nopass)
			}
			if got.passwordCount != c.passwordCount {
				t.Errorf("passwordCount = %d, want %d", got.passwordCount, c.passwordCount)
			}
			checkRules(t, "base", got.base, c.base)
			if len(got.selectors) != len(c.selectors) {
				t.Fatalf("selector count = %d, want %d (%#v)", len(got.selectors), len(c.selectors), got.selectors)
			}
			for i := range c.selectors {
				checkRules(t, "selector", got.selectors[i], c.selectors[i])
			}
		})
	}
}

// resp2 builds the flat alternating-array form of an ACL GETUSER reply.
func resp2(pairs ...any) []any { return pairs }

// resp3 builds the map form of an ACL GETUSER reply, as the driver decodes it
// under RESP3.
func resp3(pairs ...any) map[any]any {
	out := map[any]any{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out[pairs[i]] = pairs[i+1]
	}
	return out
}

func TestACLUserFromGetUser(t *testing.T) {
	cases := []struct {
		name          string
		reply         any
		ok            bool
		enabled       bool
		nopass        bool
		passwordCount int64
		base          wantRules
		selectors     []wantRules
	}{
		{
			// Redis 7 default user, RESP2 array form.
			name: "resp2 default user with no selectors",
			reply: resp2(
				"flags", []any{"on", "sanitize-payload"},
				"passwords", []any{hashDecafbad},
				"commands", "+@all",
				"keys", "~*",
				"channels", "&*",
				"selectors", []any{},
			),
			ok:            true,
			enabled:       true,
			passwordCount: 1,
			base:          wantRules{commands: []string{"+@all"}, keys: []string{"*"}, channels: []string{"*"}},
		},
		{
			// The control: restrictive base rules, no selectors.
			name: "resp3 locked-down user with no selectors",
			reply: resp3(
				"flags", []any{"on", "sanitize-payload"},
				"passwords", []any{hashBadc0ffe},
				"commands", "-@all",
				"keys", "~none:*",
				"channels", "",
				"selectors", []any{},
			),
			ok:            true,
			enabled:       true,
			passwordCount: 1,
			base:          wantRules{commands: []string{"-@all"}, keys: []string{"none:*"}, channels: []string{}},
		},
		{
			name: "resp3 locked-down base with a permissive selector",
			reply: resp3(
				"flags", []any{"on", "sanitize-payload"},
				"passwords", []any{hashCafebabe},
				"commands", "-@all",
				"keys", "~cache:*",
				"channels", "&*",
				"selectors", []any{
					resp3("commands", "+@all", "keys", "~*", "channels", ""),
				},
			),
			ok:            true,
			enabled:       true,
			passwordCount: 1,
			base:          wantRules{commands: []string{"-@all"}, keys: []string{"cache:*"}, channels: []string{"*"}},
			selectors: []wantRules{
				{commands: []string{"+@all"}, keys: []string{"*"}, channels: []string{}},
			},
		},
		{
			name: "resp2 with multiple selectors",
			reply: resp2(
				"flags", []any{"on"},
				"passwords", []any{hashFeedface},
				"commands", "-@all +get",
				"keys", "~base:*",
				"channels", "",
				"selectors", []any{
					resp2("commands", "-@all +set", "keys", "~staging:*", "channels", "&news.*"),
					resp2("commands", "-@all +@read", "keys", "%R~ro:*", "channels", ""),
				},
			),
			ok:            true,
			enabled:       true,
			passwordCount: 1,
			base:          wantRules{commands: []string{"-@all", "+get"}, keys: []string{"base:*"}, channels: []string{}},
			selectors: []wantRules{
				{commands: []string{"-@all", "+set"}, keys: []string{"staging:*"}, channels: []string{"news.*"}},
				{commands: []string{"-@all", "+@read"}, keys: []string{"ro:*"}, channels: []string{}},
			},
		},
		{
			// Before Redis 7.0 keys and channels came back as arrays of bare
			// patterns and there was no selectors field at all.
			name: "redis 6 array-form keys and channels, no selectors field",
			reply: resp2(
				"flags", []any{"on", "nopass"},
				"passwords", []any{},
				"commands", "-@all +get",
				"keys", []any{"app:*", "cache:*"},
				"channels", []any{"news.*"},
			),
			ok:      true,
			enabled: true,
			nopass:  true,
			base:    wantRules{commands: []string{"-@all", "+get"}, keys: []string{"app:*", "cache:*"}, channels: []string{"news.*"}},
		},
		{
			name: "disabled user",
			reply: resp3(
				"flags", []any{"off"},
				"passwords", []any{},
				"commands", "-@all",
				"keys", "",
				"channels", "",
				"selectors", []any{},
			),
			ok:      true,
			enabled: false,
			base:    wantRules{commands: []string{"-@all"}, keys: []string{}, channels: []string{}},
		},
		{
			name:  "empty acl reply",
			reply: resp2(),
			ok:    true,
			base:  wantRules{commands: []string{}, keys: []string{}, channels: []string{}},
		},
		{
			// A reply shape the driver did not decode into a map or array is
			// rejected so the caller falls back to the ACL LIST line.
			name:  "unrecognized reply shape is rejected",
			reply: "not a reply",
			ok:    false,
		},
		{
			name:  "nil reply is rejected",
			reply: nil,
			ok:    false,
		},
		{
			name: "malformed entries must not panic",
			reply: resp2(
				"flags", "on",
				"passwords", aclNonArrayEntry,
				"commands", 42,
				"keys", []any{nil, "", "app:*"},
				"channels", map[any]any{},
				"selectors", []any{"junk", nil},
			),
			ok:   true,
			base: wantRules{commands: []string{}, keys: []string{"app:*"}, channels: []string{}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := aclUserFromGetUser("someone", c.reply)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if got.name != "someone" {
				t.Errorf("name = %q, want %q", got.name, "someone")
			}
			if got.enabled != c.enabled {
				t.Errorf("enabled = %v, want %v", got.enabled, c.enabled)
			}
			if got.nopass != c.nopass {
				t.Errorf("nopass = %v, want %v", got.nopass, c.nopass)
			}
			if got.passwordCount != c.passwordCount {
				t.Errorf("passwordCount = %d, want %d", got.passwordCount, c.passwordCount)
			}
			checkRules(t, "base", got.base, c.base)
			if len(got.selectors) != len(c.selectors) {
				t.Fatalf("selector count = %d, want %d (%#v)", len(got.selectors), len(c.selectors), got.selectors)
			}
			for i := range c.selectors {
				checkRules(t, "selector", got.selectors[i], c.selectors[i])
			}
		})
	}
}

// TestACLGetUserMatchesACLList pins the two read paths against each other on
// the same users, so the fallback never reports something different from the
// structured reply it stands in for.
func TestACLGetUserMatchesACLList(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		getuser any
	}{
		{
			name: "locked down, no selectors",
			line: "user locked on #" + hashBadc0ffe + " ~none:* resetchannels -@all",
			getuser: resp3(
				"flags", []any{"on"},
				"passwords", []any{hashBadc0ffe},
				"commands", "-@all",
				"keys", "~none:*",
				"channels", "",
				"selectors", []any{},
			),
		},
		{
			name: "locked down with a permissive selector",
			line: "user trap on #" + hashCafebabe + " ~cache:* &* -@all (~* resetchannels +@all)",
			getuser: resp3(
				"flags", []any{"on"},
				"passwords", []any{hashCafebabe},
				"commands", "-@all",
				"keys", "~cache:*",
				"channels", "&*",
				"selectors", []any{
					resp3("commands", "+@all", "keys", "~*", "channels", ""),
				},
			),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fromLine := parseACLLine(c.line)
			fromReply, ok := aclUserFromGetUser(fromLine.name, c.getuser)
			if !ok {
				t.Fatal("aclUserFromGetUser rejected the reply")
			}
			if !reflect.DeepEqual(fromLine, fromReply) {
				t.Errorf("ACL LIST parse and ACL GETUSER disagree:\n list = %#v\n get  = %#v", fromLine, fromReply)
			}
		})
	}
}
