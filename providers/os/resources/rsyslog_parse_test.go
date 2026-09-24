// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoalesceRsyslogLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		// expected (text, sourceLine) pairs in emission order
		want []struct {
			text string
			line int
		}
	}{
		{
			name: "drops blanks and comment-only lines",
			in:   "$ModLoad imuxsock\n\n# comment\n$ModLoad imklog\n",
			want: []struct {
				text string
				line int
			}{
				{"$ModLoad imuxsock", 1},
				{"$ModLoad imklog", 4},
			},
		},
		{
			name: "preserves source line for legacy directives",
			in:   "# header\n# header\n$ModLoad imuxsock\nauth.* /var/log/auth.log\n",
			want: []struct {
				text string
				line int
			}{
				{"$ModLoad imuxsock", 3},
				{"auth.* /var/log/auth.log", 4},
			},
		},
		{
			name: "single-line keyword block keeps its line",
			in:   "# comment\nmodule(load=\"imtcp\")\nauth.* /var/log/auth.log\n",
			want: []struct {
				text string
				line int
			}{
				{"module(load=\"imtcp\")", 2},
				{"auth.* /var/log/auth.log", 3},
			},
		},
		{
			name: "multi-line keyword block collapses to opening line number",
			in:   "$ModLoad imuxsock\nmodule(\n    load=\"imtcp\"\n    KeepAlive=\"on\"\n)\n",
			want: []struct {
				text string
				line int
			}{
				{"$ModLoad imuxsock", 1},
				// joined block uses the OPENING line (line 2 — `module(`)
				{`module( load="imtcp" KeepAlive="on" )`, 2},
			},
		},
		{
			name: "parens inside quotes do not affect block tracking",
			in:   `action(type="omfwd" template="(literal)" target="host")` + "\n",
			want: []struct {
				text string
				line int
			}{
				{`action(type="omfwd" template="(literal)" target="host")`, 1},
			},
		},
		{
			name: "non-blockkeyword paren line stays a single line",
			in:   "$Template foo,\"(literal)\"\n$IncludeConfig /a.conf\n",
			want: []struct {
				text string
				line int
			}{
				{`$Template foo,"(literal)"`, 1},
				{"$IncludeConfig /a.conf", 2},
			},
		},
		{
			name: "unterminated block surfaces best-effort",
			in:   "input(\n    type=\"imtcp\"\n",
			want: []struct {
				text string
				line int
			}{
				{`input( type="imtcp" `, 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coalesceRsyslogLines("/etc/rsyslog.conf", tt.in)
			require.Len(t, got, len(tt.want))
			for i, w := range tt.want {
				assert.Equal(t, w.text, got[i].text, "text @ %d", i)
				assert.Equal(t, w.line, got[i].sourceLine, "line @ %d", i)
				assert.Equal(t, "/etc/rsyslog.conf", got[i].sourceFile, "file @ %d", i)
			}
		})
	}
}

func TestHasBlockKeyword(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"module(load=\"imtcp\")", true},
		{"input(type=\"imtcp\" port=\"514\")", true},
		{"action(type=\"omfile\")", true},
		{"global(workDirectory=\"/var/lib/rsyslog\")", true},
		{"module (load=\"imtcp\")", true},       // whitespace tolerated
		{"module\t(load=\"imtcp\")", true},      // tab tolerated
		{"$ModLoad imuxsock", false},            // legacy form
		{"auth.* /var/log/auth.log", false},     // selector
		{"if $msg contains \"x\" then ", false}, // conditional
		{"ruleset(name=\"x\") {", false},        // ruleset is not in our keyword set (yet)
		{"modular thing", false},                // false-positive guard
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, hasBlockKeyword(tt.in))
		})
	}
}

func TestParseKVArgs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]any
	}{
		{"empty", "", map[string]any{}},
		{"single quoted", `load="imtcp"`, map[string]any{"load": "imtcp"}},
		{"single single-quoted", `load='imtcp'`, map[string]any{"load": "imtcp"}},
		{"unquoted", `port=514`, map[string]any{"port": "514"}},
		{
			"multiple pairs in any order",
			`type="imtcp" port="514" ruleset="net"`,
			map[string]any{"type": "imtcp", "port": "514", "ruleset": "net"},
		},
		{
			"key case-normalised",
			`StreamDriver.Mode="1"`,
			map[string]any{"streamdriver.mode": "1"},
		},
		{
			"escaped quote inside value",
			`template="foo\"bar"`,
			map[string]any{"template": `foo"bar`},
		},
		{
			"hash inside quoted value preserved",
			`target="host#1"`,
			map[string]any{"target": "host#1"},
		},
		{
			"queue prefix preserved on raw key",
			`type="omfwd" queue.type="LinkedList" queue.filename="fwd"`,
			map[string]any{"type": "omfwd", "queue.type": "LinkedList", "queue.filename": "fwd"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseKVArgs(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUnescapeQuoted(t *testing.T) {
	assert.Equal(t, `plain`, unescapeQuoted(`plain`))
	assert.Equal(t, `with "quote"`, unescapeQuoted(`with \"quote\"`))
	assert.Equal(t, `single 'q'`, unescapeQuoted(`single \'q\'`))
	assert.Equal(t, `slash \`, unescapeQuoted(`slash \\`))
	assert.Equal(t, `hash # in val`, unescapeQuoted(`hash \# in val`))
	// unknown escape preserved verbatim (rsyslog's lexer doesn't recognize \n etc.)
	assert.Equal(t, `\n`, unescapeQuoted(`\n`))
}

func TestClassifySelectorTarget(t *testing.T) {
	tests := []struct {
		target       string
		wantType     string
		wantProtocol string
	}{
		{"/var/log/messages", "omfile", ""},
		{"-/var/log/messages", "omfile", ""},
		{"@hostname", "omfwd", "udp"},
		{"@host:514", "omfwd", "udp"},
		{"@@hostname", "omfwd", "tcp"},
		{"@@host:514", "omfwd", "tcp"},
		{":omusrmsg:root,daisy", "omusrmsg", ""},
		{":omhttp:http://example", "omhttp", ""},
		{"~", "discard", ""},
		{"*", "omusrmsg", ""},
		{"|/run/myfifo", "ompipe", ""},
		{"unrecognized", "omfile", ""}, // defaults to omfile (matches rsyslog)
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			gotType, gotProto := classifySelectorTarget(tt.target)
			assert.Equal(t, tt.wantType, gotType)
			assert.Equal(t, tt.wantProtocol, gotProto)
		})
	}
}

func TestLegacyInputFromDirective(t *testing.T) {
	tests := []struct {
		name     string
		suffix   string
		value    string
		wantOK   bool
		wantType string
		wantPort int64
	}{
		{"tcp run", "TCPServerRun", "514", true, "imtcp", 514},
		{"udp run", "UDPServerRun", "514", true, "imudp", 514},
		{"relp run", "RELPServerRun", "2514", true, "imrelp", 2514},
		{"gss run", "GSSServerRun", "514", true, "imgssapi", 514},
		{"case-insensitive suffix", "tcpserverrun", "514", true, "imtcp", 514},
		{"non-listener directive skipped", "TCPServerKeepAlive", "on", false, "", 0},
		{"unrelated $Input prefix", "PollingInterval", "10", false, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := legacyInputFromDirective(tt.suffix, tt.value)
			assert.Equal(t, tt.wantOK, ok)
			if ok {
				assert.Equal(t, tt.wantType, got.moduleType)
				assert.Equal(t, tt.wantPort, got.port)
			}
		})
	}
}

func TestParseRsyslogFile_Modules(t *testing.T) {
	content := `# main config
$ModLoad imuxsock
$ModLoad imklog
module(load="imtcp" KeepAlive="on")
module(
    load="imudp"
    threads="2"
)
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)

	var modules []rsyslogEntry
	for _, e := range got {
		if e.kind == rsyslogKindModule {
			modules = append(modules, e)
		}
	}
	require.Len(t, modules, 4)

	// $ModLoad imuxsock at line 2
	assert.Equal(t, "imuxsock", modules[0].moduleName)
	assert.Equal(t, 2, modules[0].sourceLine)
	assert.Empty(t, modules[0].parameters, "legacy $ModLoad carries no params")

	// $ModLoad imklog at line 3
	assert.Equal(t, "imklog", modules[1].moduleName)
	assert.Equal(t, 3, modules[1].sourceLine)

	// modern single-line module() at line 4
	assert.Equal(t, "imtcp", modules[2].moduleName)
	assert.Equal(t, 4, modules[2].sourceLine)
	assert.Equal(t, "on", modules[2].parameters["keepalive"])

	// modern multi-line module() at line 5 (opening paren)
	assert.Equal(t, "imudp", modules[3].moduleName)
	assert.Equal(t, 5, modules[3].sourceLine)
	assert.Equal(t, "2", modules[3].parameters["threads"])
}

func TestParseRsyslogFile_Inputs(t *testing.T) {
	content := `# legacy form
$ModLoad imtcp
$InputTCPServerRun 514

# modern form
input(type="imudp" port="514" address="0.0.0.0" ruleset="remote" StreamDriver.Mode="1")
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)

	var inputs []rsyslogEntry
	for _, e := range got {
		if e.kind == rsyslogKindInput {
			inputs = append(inputs, e)
		}
	}
	require.Len(t, inputs, 2)

	// legacy: $InputTCPServerRun 514 (line 3)
	assert.Equal(t, "imtcp", inputs[0].moduleType)
	assert.Equal(t, int64(514), inputs[0].port)
	assert.Equal(t, 3, inputs[0].sourceLine)

	// modern: input(...) at line 6
	assert.Equal(t, "imudp", inputs[1].moduleType)
	assert.Equal(t, int64(514), inputs[1].port)
	assert.Equal(t, "0.0.0.0", inputs[1].address)
	assert.Equal(t, "remote", inputs[1].ruleset)
	assert.Equal(t, "1", inputs[1].streamDriverMode)
	assert.Equal(t, 6, inputs[1].sourceLine)
}

func TestParseRsyslogFile_Actions(t *testing.T) {
	content := `# modern action with TLS + queue config
action(
    type="omfwd"
    target="loghost.example.com"
    port="6514"
    protocol="tcp"
    StreamDriverMode="1"
    StreamDriver="gtls"
    template="RSYSLOG_TraditionalFileFormat"
    queue.type="LinkedList"
    queue.size="10000"
    queue.saveOnShutdown="on"
)

# omfile via 'file=' alias
action(type="omfile" file="/var/log/local.log")
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)

	var actions []rsyslogEntry
	for _, e := range got {
		if e.kind == rsyslogKindAction {
			actions = append(actions, e)
		}
	}
	require.Len(t, actions, 2)

	// modern omfwd with TLS + queue
	fwd := actions[0]
	assert.Equal(t, "omfwd", fwd.moduleType)
	assert.Equal(t, "loghost.example.com", fwd.target)
	assert.Equal(t, "tcp", fwd.protocol)
	assert.True(t, fwd.tlsEnabled)
	assert.Equal(t, "RSYSLOG_TraditionalFileFormat", fwd.template)
	assert.Equal(t, "LinkedList", fwd.queue["type"])
	assert.Equal(t, "10000", fwd.queue["size"])
	assert.Equal(t, "on", fwd.queue["saveonshutdown"])
	assert.Equal(t, 2, fwd.sourceLine)

	// omfile via file= alias
	fileAct := actions[1]
	assert.Equal(t, "omfile", fileAct.moduleType)
	assert.Equal(t, "/var/log/local.log", fileAct.target)
	assert.False(t, fileAct.tlsEnabled)
	assert.Empty(t, fileAct.queue, "no queue configured")
}

func TestParseRsyslogFile_Rules(t *testing.T) {
	content := `# multi-selector rule fans out to two rules and one action
*.info;mail.none;authpriv.none /var/log/messages

# negation form
auth,authpriv.none /var/log/quieted

# UDP forward
*.* @loghost

# TCP forward with port
*.warn @@loghost:514

# omusrmsg shorthand
*.emerg :omusrmsg:*
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)

	var rules []rsyslogEntry
	for _, e := range got {
		if e.kind == rsyslogKindRule {
			rules = append(rules, e)
		}
	}

	// rule 0: *.info -> /var/log/messages (line 2)
	require.Greater(t, len(rules), 0)
	assert.Equal(t, []string{"*"}, rules[0].facilities)
	assert.Equal(t, []string{"info"}, rules[0].severities)
	assert.Equal(t, "/var/log/messages", rules[0].target)
	assert.False(t, rules[0].negate)
	assert.Equal(t, 2, rules[0].sourceLine)

	// rule 1: mail.none → /var/log/messages, negate=true
	require.Greater(t, len(rules), 1)
	assert.Equal(t, []string{"mail"}, rules[1].facilities)
	assert.Equal(t, []string{"none"}, rules[1].severities)
	assert.True(t, rules[1].negate)
	assert.Equal(t, "/var/log/messages", rules[1].target)

	// rule 2: authpriv.none → /var/log/messages, negate=true
	require.Greater(t, len(rules), 2)
	assert.Equal(t, []string{"authpriv"}, rules[2].facilities)
	assert.True(t, rules[2].negate)

	// rule 3: auth,authpriv.none → /var/log/quieted (line 5)
	require.Greater(t, len(rules), 3)
	assert.Equal(t, []string{"auth", "authpriv"}, rules[3].facilities)
	assert.True(t, rules[3].negate)
	assert.Equal(t, "/var/log/quieted", rules[3].target)
	assert.Equal(t, 5, rules[3].sourceLine)

	// rule 4: *.* @loghost (line 8)
	require.Greater(t, len(rules), 4)
	assert.Equal(t, []string{"*"}, rules[4].facilities)
	assert.Equal(t, []string{"*"}, rules[4].severities)
	assert.Equal(t, "@loghost", rules[4].target)

	// rule 5: *.warn @@loghost:514 (line 11)
	require.Greater(t, len(rules), 5)
	assert.Equal(t, []string{"warn"}, rules[5].severities)
	assert.Equal(t, "@@loghost:514", rules[5].target)

	// rule 6: *.emerg :omusrmsg:* (line 14)
	require.Greater(t, len(rules), 6)
	assert.Equal(t, []string{"emerg"}, rules[6].severities)
	assert.Equal(t, ":omusrmsg:*", rules[6].target)
}

func TestParseRsyslogFile_SeverityPrefixes(t *testing.T) {
	// rsyslog severity selectors accept `=` (exactly), `!` (all except), and
	// `!=` (negate-exact) prefixes. Each must still produce a rule entry with
	// the prefix preserved on the severity token — previously the `!=` form
	// was dropped entirely, yielding zero rules with no error.
	content := `mail.info /var/log/mail.log
mail.=info /var/log/mail.exact.log
mail.!info /var/log/mail.notinfo.log
mail.!=info /var/log/mail.notexact.log
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)

	var rules []rsyslogEntry
	for _, e := range got {
		if e.kind == rsyslogKindRule {
			rules = append(rules, e)
		}
	}
	require.Len(t, rules, 4, "each severity prefix form must yield exactly one rule")

	assert.Equal(t, []string{"mail"}, rules[0].facilities)
	assert.Equal(t, []string{"info"}, rules[0].severities)
	assert.Equal(t, "/var/log/mail.log", rules[0].target)

	assert.Equal(t, []string{"=info"}, rules[1].severities)
	assert.Equal(t, "/var/log/mail.exact.log", rules[1].target)
	assert.False(t, rules[1].negate)

	assert.Equal(t, []string{"!info"}, rules[2].severities)
	assert.Equal(t, "/var/log/mail.notinfo.log", rules[2].target)
	assert.False(t, rules[2].negate)

	assert.Equal(t, []string{"!=info"}, rules[3].severities)
	assert.Equal(t, "/var/log/mail.notexact.log", rules[3].target)
	assert.False(t, rules[3].negate)
}

func TestParseRsyslogFile_SourceAttribution(t *testing.T) {
	// Every emitted entry must carry the file path we passed in. That's
	// how the typed accessors point findings at the originating fragment
	// instead of just "somewhere in /etc/rsyslog.conf-like".
	content := `$ModLoad imuxsock
auth.* /var/log/auth.log
`
	got := parseRsyslogFile("/etc/rsyslog.d/10-local.conf", content)
	require.NotEmpty(t, got)
	for _, e := range got {
		assert.Equal(t, "/etc/rsyslog.d/10-local.conf", e.sourceFile)
		assert.Greater(t, e.sourceLine, 0, "1-indexed source line")
	}
}

func TestParseRsyslogFile_IgnoresNonStatementLines(t *testing.T) {
	// Selector regex is permissive but we explicitly reject lines that
	// start with reserved tokens (`$`, `:`, `&`, `if`, `ruleset`, `call`,
	// `include`) so they don't masquerade as legacy selector rules.
	content := `# header
$WorkDirectory /var/spool/rsyslog
include(file="/etc/rsyslog.d/*.conf")
$IncludeConfig /etc/rsyslog.d/*.conf
if $msg contains "audit" then /var/log/audit.log
:omusrmsg:* "wall"
& stop
ruleset(name="net") {
    action(type="omfile" file="/var/log/net.log")
}
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)
	for _, e := range got {
		// Spotcheck: no rule should match the if/include/ruleset lines.
		if e.kind == rsyslogKindRule {
			assert.NotContains(t, e.facilities, "if")
			assert.NotContains(t, e.facilities, "include")
			assert.NotContains(t, e.facilities, "ruleset")
			assert.NotContains(t, e.facilities, "call")
		}
	}
}

// entriesOfKind filters parsed entries down to one kind, keeping order.
func entriesOfKind(entries []rsyslogEntry, kind rsyslogEntryKind) []rsyslogEntry {
	var out []rsyslogEntry
	for _, e := range entries {
		if e.kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func TestHasEmbeddedAction(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{`*.* action(type="omfwd"`, true},
		{`auth,authpriv.*	action (type="omfile"`, true},
		{`if $programname == 'sshd' then action(type="omfile"`, true},
		{`& action(type="omfile" file="/x")`, true},
		{`if $x then { action(type="omfile" file="/x") }`, true},
		{`template(name="t" type="string" string="action(%msg%)")`, false},
		{`$Template t,"see action( here"`, false},
		{`*.* /var/log/transaction(1).log`, false},
		{`*.* myaction(x)`, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, hasEmbeddedAction(tt.in))
		})
	}
}

func TestParseRsyslogFile_SelectorWithModernAction(t *testing.T) {
	content := `*.* action(type="omfwd" target="logs.example.com" port="514" protocol="tcp"
  action.resumeRetryCount="100"
  queue.type="LinkedList" queue.size="1000")
kern.*;mail.none action(type="omfile" file="/var/log/kern.log")
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)

	actions := entriesOfKind(got, rsyslogKindAction)
	require.Len(t, actions, 2)
	fwd := actions[0]
	assert.Equal(t, "omfwd", fwd.moduleType)
	assert.Equal(t, "logs.example.com", fwd.target)
	assert.Equal(t, "tcp", fwd.protocol)
	assert.Equal(t, "100", fwd.parameters["action.resumeretrycount"])
	assert.Equal(t, "LinkedList", fwd.queue["type"])
	assert.Equal(t, "1000", fwd.queue["size"])
	assert.Equal(t, 1, fwd.sourceLine)
	assert.Equal(t, "omfile", actions[1].moduleType)
	assert.Equal(t, "/var/log/kern.log", actions[1].target)

	rules := entriesOfKind(got, rsyslogKindRule)
	require.Len(t, rules, 3)
	assert.Equal(t, []string{"*"}, rules[0].facilities)
	assert.Equal(t, []string{"*"}, rules[0].severities)
	assert.Equal(t, []string{"kern"}, rules[1].facilities)
	assert.Equal(t, []string{"mail"}, rules[2].facilities)
	assert.True(t, rules[2].negate)

	// Every rule points at the action from its own line.
	for i, e := range got {
		if e.kind != rsyslogKindRule {
			continue
		}
		require.Greater(t, e.actionOffset, 0, "rule at %d has no action", i)
		backing := got[i+e.actionOffset]
		assert.Equal(t, rsyslogKindAction, backing.kind)
		assert.Equal(t, e.sourceLine, backing.sourceLine)
	}
}

func TestParseRsyslogFile_LegacyActionState(t *testing.T) {
	content := `$ActionQueueType LinkedList
$ActionQueueFileName fwdRule1
$ActionResumeRetryCount -1
*.* @@logs.example.com:6514
*.* @@second.example.com:514
$ActionQueueType LinkedList
action(type="omfile" file="/var/log/all.log")
*.* @@third.example.com:514
`
	actions := entriesOfKind(parseRsyslogFile("/etc/rsyslog.conf", content), rsyslogKindAction)
	require.Len(t, actions, 4)

	first := actions[0]
	assert.Equal(t, "LinkedList", first.queue["type"])
	assert.Equal(t, "fwdRule1", first.queue["filename"])
	assert.Equal(t, "-1", first.parameters["action.resumeretrycount"])

	t.Run("queue settings apply to the next action only", func(t *testing.T) {
		assert.Empty(t, actions[1].queue)
		assert.NotContains(t, actions[1].parameters, "action.resumeretrycount")
	})

	t.Run("a modern action consumes the pending queue settings", func(t *testing.T) {
		assert.Empty(t, actions[2].queue, "modern actions don't take legacy queue directives")
		assert.Empty(t, actions[3].queue, "the settings were reset by the modern action")
	})
}

func TestParseRsyslogFile_LegacySendStreamDriver(t *testing.T) {
	content := `$DefaultNetstreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
$ActionSendStreamDriverPermittedPeer logs.example.com
*.* @@logs.example.com:6514
*.* @udp.example.com:514
*.* @@second.example.com:6514
$ResetConfigVariables
*.* @@after-reset.example.com:6514
`
	actions := entriesOfKind(parseRsyslogFile("/etc/rsyslog.conf", content), rsyslogKindAction)
	require.Len(t, actions, 4)

	tls := actions[0]
	assert.True(t, tls.tlsEnabled)
	assert.Equal(t, "1", tls.parameters["streamdrivermode"])
	assert.Equal(t, "x509/name", tls.parameters["streamdriverauthmode"])
	assert.Equal(t, "logs.example.com", tls.parameters["streamdriverpermittedpeers"])

	t.Run("UDP forwards don't use the stream driver", func(t *testing.T) {
		assert.Equal(t, "udp", actions[1].protocol)
		assert.False(t, actions[1].tlsEnabled)
		assert.Empty(t, actions[1].parameters)
	})

	t.Run("the settings stay in effect for later TCP forwards", func(t *testing.T) {
		assert.True(t, actions[2].tlsEnabled)
	})

	t.Run("$ResetConfigVariables clears them", func(t *testing.T) {
		assert.False(t, actions[3].tlsEnabled)
		assert.Empty(t, actions[3].parameters)
	})
}

func TestParseRsyslogFile_FilterActions(t *testing.T) {
	content := `if $programname == 'sshd' then /var/log/sshd.log
& stop
if $syslogfacility-text == 'local0' then action(type="omfwd"
    target="logs.example.com" port="6514" protocol="tcp" StreamDriverMode="1")
:msg, contains, "error" -/var/log/errors.log
& @@logs.example.com:514
:programname, !isequal, "cron" /var/log/not-cron.log
if $msg contains "x" then { action(type="omfile" file="/var/log/x.log") }
if $syslogfacility-text == 'auth' then {
  action(type="omfile" file="/var/log/auth.log")
}
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)
	assert.Empty(t, entriesOfKind(got, rsyslogKindRule), "filters without a selector produce no rules")

	actions := entriesOfKind(got, rsyslogKindAction)
	want := []struct {
		typ, target, protocol string
		tls                   bool
		line                  int
	}{
		{"omfile", "/var/log/sshd.log", "", false, 1},
		{"discard", "stop", "", false, 2},
		{"omfwd", "logs.example.com", "tcp", true, 3},
		{"omfile", "/var/log/errors.log", "", false, 5},
		{"omfwd", "logs.example.com:514", "tcp", false, 6},
		{"omfile", "/var/log/not-cron.log", "", false, 7},
		{"omfile", "/var/log/x.log", "", false, 8},
		{"omfile", "/var/log/auth.log", "", false, 10},
	}
	require.Len(t, actions, len(want))
	for i, w := range want {
		assert.Equal(t, w.typ, actions[i].moduleType, "type @ %d", i)
		assert.Equal(t, w.target, actions[i].target, "target @ %d", i)
		assert.Equal(t, w.protocol, actions[i].protocol, "protocol @ %d", i)
		assert.Equal(t, w.tls, actions[i].tlsEnabled, "tls @ %d", i)
		assert.Equal(t, w.line, actions[i].sourceLine, "line @ %d", i)
	}
}

func TestParseRsyslogFile_LegacyTargetSyntax(t *testing.T) {
	content := `*.* @@(o,z9)logs.example.com:514;RSYSLOG_ForwardFormat
*.* @[2001:db8::1]:514
*.* :omrelp:relp.example.com:2514;RSYSLOG_ForwardFormat
*.*;auth,authpriv.none -/var/log/syslog
*.emerg :omusrmsg:*
daemon.* |/dev/xconsole
`
	got := parseRsyslogFile("/etc/rsyslog.conf", content)
	actions := entriesOfKind(got, rsyslogKindAction)
	want := []struct{ typ, target, template string }{
		{"omfwd", "logs.example.com:514", "RSYSLOG_ForwardFormat"},
		{"omfwd", "[2001:db8::1]:514", ""},
		{"omrelp", "relp.example.com:2514", "RSYSLOG_ForwardFormat"},
		{"omfile", "/var/log/syslog", ""},
		{"omusrmsg", "*", ""},
		{"ompipe", "/dev/xconsole", ""},
	}
	require.Len(t, actions, len(want))
	for i, w := range want {
		assert.Equal(t, w.typ, actions[i].moduleType, "type @ %d", i)
		assert.Equal(t, w.target, actions[i].target, "target @ %d", i)
		assert.Equal(t, w.template, actions[i].template, "template @ %d", i)
	}

	// Rules keep the raw token as written.
	rules := entriesOfKind(got, rsyslogKindRule)
	require.NotEmpty(t, rules)
	assert.Equal(t, "@@(o,z9)logs.example.com:514;RSYSLOG_ForwardFormat", rules[0].target)
}

func TestParseRsyslogFile_SelectorWithoutAction(t *testing.T) {
	got := parseRsyslogFile("/etc/rsyslog.conf", "local7.* foo bar\nnot-a-selector /var/log/x\n")
	assert.Empty(t, entriesOfKind(got, rsyslogKindAction), "a guessed omfile action is worse than none")

	rules := entriesOfKind(got, rsyslogKindRule)
	require.Len(t, rules, 1)
	assert.Equal(t, "foo bar", rules[0].target)
	assert.Zero(t, rules[0].actionOffset)
}

func TestApplyModuleDefaults(t *testing.T) {
	legacy := parseRsyslogFile("/etc/rsyslog.conf", `$ModLoad imtcp
$InputTCPServerStreamDriverMode 1
$InputTCPServerStreamDriverAuthMode x509/name
$InputTCPServerRun 6514
`)
	modern := parseRsyslogFile("/etc/rsyslog.d/10-listen.conf", `input(type="imtcp" port="6515")
input(type="imtcp" port="6516" StreamDriver.Mode="0")
input(type="imudp" port="514")
`)
	all := append(legacy, modern...)
	applyModuleDefaults(all)

	assert.Empty(t, entriesOfKind(all, rsyslogKindModule)[0].parameters,
		"the legacy directive is not folded into the $ModLoad entry")

	inputs := entriesOfKind(all, rsyslogKindInput)
	require.Len(t, inputs, 4)
	assert.Equal(t, "1", inputs[0].streamDriverMode, "legacy listener")
	assert.Equal(t, "x509/name", inputs[0].parameters["streamdriver.authmode"])
	assert.Equal(t, "1", inputs[1].streamDriverMode, "modern listener in another file")
	assert.Equal(t, "0", inputs[2].streamDriverMode, "the input's own setting wins")
	assert.Empty(t, inputs[3].streamDriverMode, "imudp is a different module")
}

func TestAssignRsyslogEntryIDs(t *testing.T) {
	got := parseRsyslogFile("/etc/rsyslog.conf", `$InputTCPServerStreamDriverMode 1
*.info;mail.none /var/log/messages
auth.* /var/log/auth.log
`)
	assignRsyslogEntryIDs(got)

	for i, e := range got {
		if e.kind == rsyslogKindModuleDefaults {
			assert.Empty(t, e.id)
			continue
		}
		assert.NotEmpty(t, e.id, "entry %d", i)
	}
	actions := entriesOfKind(got, rsyslogKindAction)
	require.Len(t, actions, 2)
	assert.Equal(t, "action//etc/rsyslog.conf:2/0", actions[0].id)
	assert.Equal(t, "action//etc/rsyslog.conf:3/1", actions[1].id)

	rules := entriesOfKind(got, rsyslogKindRule)
	require.Len(t, rules, 3)
	assert.Equal(t, "rule//etc/rsyslog.conf:2/0", rules[0].id)
	assert.Equal(t, "rule//etc/rsyslog.conf:2/1", rules[1].id)
	assert.Equal(t, "rule//etc/rsyslog.conf:3/2", rules[2].id)
}
