// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package bind9

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memFS serves configuration files from a map, standing in for the
// connection's filesystem.
func memFS(files map[string]string) OpenFunc {
	return func(path string) (io.ReadCloser, error) {
		content, ok := files[path]
		if !ok {
			return nil, io.ErrUnexpectedEOF
		}
		return io.NopCloser(strings.NewReader(content)), nil
	}
}

func TestParseStatements(t *testing.T) {
	stmts, err := Parse(`
options {
	directory "/var/cache/bind";
	dnssec-validation auto;
	listen-on-v6 { any; };
	allow-transfer { none; };
};
zone "example.com" IN {
	type master;
	file "db.example.com";
};
`)
	require.NoError(t, err)
	require.Len(t, stmts, 2)

	opts := stmts[0]
	assert.Equal(t, "options", opts.Name)
	assert.True(t, opts.IsBlock())
	assert.Equal(t, "/var/cache/bind", Value(opts.Block, "directory"))
	assert.Equal(t, "auto", Value(opts.Block, "dnssec-validation"))
	assert.Equal(t, []string{"any"}, List(opts.Block, "listen-on-v6"))
	assert.Equal(t, []string{"none"}, List(opts.Block, "allow-transfer"))

	zone := stmts[1]
	assert.Equal(t, "zone", zone.Name)
	// the class is an ordinary argument, so a zone declared with and without
	// one is read the same way
	assert.Equal(t, []string{"example.com", "IN"}, zone.Args)
	assert.Equal(t, "master", Value(zone.Block, "type"))
	assert.Equal(t, "db.example.com", Value(zone.Block, "file"))
}

func TestParseComments(t *testing.T) {
	// All three spellings named accepts, including a `#` and a `//` inside a
	// quoted value, where they are data rather than a comment.
	stmts, err := Parse(`
// a line comment
# another spelling
/* a block
   comment spanning lines */
options {
	directory "/var/cache/bind"; // trailing
	version "not#a//comment";
};
`)
	require.NoError(t, err)
	require.Len(t, stmts, 1)
	assert.Equal(t, "/var/cache/bind", Value(stmts[0].Block, "directory"))
	assert.Equal(t, "not#a//comment", Value(stmts[0].Block, "version"))
}

func TestParseEmptyBlockIsStillABlock(t *testing.T) {
	// `acl trusted { };` declares an empty ACL, which is not the same as not
	// declaring one, so the block must survive as an empty list.
	stmts, err := Parse(`acl "trusted" { };`)
	require.NoError(t, err)
	require.Len(t, stmts, 1)
	assert.True(t, stmts[0].IsBlock())
	assert.Empty(t, stmts[0].Block)
}

func TestParseQuotedEmptyString(t *testing.T) {
	// `version "";` hides the version by answering with an empty string, and
	// is a different configuration from not setting version at all.
	stmts, err := Parse(`options { version ""; };`)
	require.NoError(t, err)
	require.Len(t, stmts[0].Block, 1)
	assert.Equal(t, []string{""}, stmts[0].Block[0].Args)
	assert.Equal(t, "", Value(stmts[0].Block, "version"))
}

func TestParseLineNumbers(t *testing.T) {
	stmts, err := Parse("options {\n\trecursion no;\n};\n\nzone \".\" {\n\ttype hint;\n};")
	require.NoError(t, err)
	assert.Equal(t, 1, stmts[0].Line)
	assert.Equal(t, 2, stmts[0].Block[0].Line)
	assert.Equal(t, 5, stmts[1].Line, "a line number has to survive a preceding block")
}

func TestParseErrorsDoNotDiscardTheRest(t *testing.T) {
	// A truncated block at the end must not cost the reader the statements
	// that parsed cleanly before it.
	stmts, _ := Parse(`
options { recursion no; };
zone "broken" {
	type master;
`)
	require.NotEmpty(t, stmts)
	assert.Equal(t, "options", stmts[0].Name)
	assert.Equal(t, "no", Value(stmts[0].Block, "recursion"))
}

func TestListKeepsEntryArguments(t *testing.T) {
	// Entries are not always single words: a key reference or a negation
	// carries an argument that changes what the entry means.
	stmts, err := Parse(`options { allow-transfer { key "transfer-key"; !10.0.0.1; localhost; }; };`)
	require.NoError(t, err)
	assert.Equal(t, []string{`key transfer-key`, "!10.0.0.1", "localhost"}, List(stmts[0].Block, "allow-transfer"))
}

func TestParams(t *testing.T) {
	stmts, err := Parse(`options {
		recursion no;
		version "";
		allow-query { any; };
		max-cache-size 100m;
	};`)
	require.NoError(t, err)
	params := Params(stmts[0].Block)
	assert.Equal(t, map[string]string{
		"recursion":      "no",
		"version":        "",
		"max-cache-size": "100m",
	}, params, "block statements have no flat value and must not be invented")
}

func TestParseFilesExpandsIncludes(t *testing.T) {
	// The Debian layout: a named.conf that is nothing but includes.
	cfg := ParseFiles("/etc/bind/named.conf", memFS(map[string]string{
		"/etc/bind/named.conf": `
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
`,
		"/etc/bind/named.conf.options": `options { recursion no; dnssec-validation auto; };`,
		"/etc/bind/named.conf.local":   `zone "example.com" { type master; file "db.example.com"; };`,
	}))

	require.Empty(t, cfg.Errors)
	require.Len(t, cfg.Statements, 2)
	assert.Equal(t, "options", cfg.Statements[0].Name)
	assert.Equal(t, "zone", cfg.Statements[1].Name)
	assert.Equal(t, []string{
		"/etc/bind/named.conf",
		"/etc/bind/named.conf.local",
		"/etc/bind/named.conf.options",
	}, SortedFiles(cfg.Files))

	// the statement has to name the file it came from, not the root config
	assert.Equal(t, "/etc/bind/named.conf.options", cfg.Statements[0].File)
}

func TestParseFilesRelativeInclude(t *testing.T) {
	cfg := ParseFiles("/etc/bind/named.conf", memFS(map[string]string{
		"/etc/bind/named.conf":       `include "named.conf.local";`,
		"/etc/bind/named.conf.local": `zone "example.com" { type master; };`,
	}))
	require.Empty(t, cfg.Errors)
	require.Len(t, cfg.Statements, 1)
	assert.Equal(t, "zone", cfg.Statements[0].Name)
}

func TestParseFilesIncludeInsideBlock(t *testing.T) {
	// An include is legal wherever a statement is, so a view can be assembled
	// from fragments. A parser that only expands at the top level reports the
	// view as empty.
	cfg := ParseFiles("/etc/bind/named.conf", memFS(map[string]string{
		"/etc/bind/named.conf":     `view "internal" { include "/etc/bind/internal.zones"; };`,
		"/etc/bind/internal.zones": `zone "corp.example" { type master; };`,
	}))
	require.Empty(t, cfg.Errors)
	require.Len(t, cfg.Statements, 1)
	require.Len(t, cfg.Statements[0].Block, 1)
	assert.Equal(t, "zone", cfg.Statements[0].Block[0].Name)
	assert.Equal(t, "corp.example", cfg.Statements[0].Block[0].Arg(0))
}

func TestParseFilesIncludeCycle(t *testing.T) {
	// A cycle is a configuration error, not a reason to hang.
	cfg := ParseFiles("/etc/bind/named.conf", memFS(map[string]string{
		"/etc/bind/named.conf": `include "/etc/bind/loop.conf";`,
		"/etc/bind/loop.conf":  `options { recursion no; }; include "/etc/bind/named.conf";`,
	}))
	require.Len(t, cfg.Errors, 1)
	assert.Contains(t, cfg.Errors[0].Error(), "included more than once")
	// and everything before the cycle still parses
	require.Len(t, cfg.Statements, 1)
	assert.Equal(t, "options", cfg.Statements[0].Name)
}

func TestParseFilesMissingInclude(t *testing.T) {
	// A missing include is reported, and the rest of the configuration still
	// answers: a server whose optional fragment is absent is not unconfigured.
	cfg := ParseFiles("/etc/bind/named.conf", memFS(map[string]string{
		"/etc/bind/named.conf": `options { recursion no; }; include "/etc/bind/absent.conf";`,
	}))
	require.Len(t, cfg.Errors, 1)
	assert.Contains(t, cfg.Errors[0].Error(), "absent.conf")
	require.Len(t, cfg.Statements, 1)
	assert.Equal(t, "no", Value(cfg.Statements[0].Block, "recursion"))
}

func TestParseFilesMissingRoot(t *testing.T) {
	cfg := ParseFiles("/etc/bind/named.conf", memFS(nil))
	require.Len(t, cfg.Errors, 1)
	assert.Empty(t, cfg.Statements)
	assert.Empty(t, cfg.Files)
}

func TestArgValue(t *testing.T) {
	// The grammar hangs modifiers off a statement as bare argument pairs, both
	// before a block and after a value.
	stmts, err := Parse(`
options {
	listen-on port 5353 { 127.0.0.1; };
	listen-on-v6 { any; };
};
logging {
	channel "audit" { file "/var/log/named/audit.log" versions 3 size 5m; };
};
`)
	require.NoError(t, err)

	listen := First(stmts[0].Block, "listen-on")
	require.NotNil(t, listen)
	assert.Equal(t, "5353", listen.ArgValue("port"))
	// an absent modifier is not a zero one
	assert.Equal(t, "", First(stmts[0].Block, "listen-on-v6").ArgValue("port"))

	channel := First(stmts[1].Block, "channel")
	require.NotNil(t, channel)
	file := First(channel.Block, "file")
	require.NotNil(t, file)
	assert.Equal(t, "/var/log/named/audit.log", file.Arg(0))
	assert.Equal(t, "3", file.ArgValue("versions"))
	assert.Equal(t, "5m", file.ArgValue("size"))
	assert.Equal(t, "", file.ArgValue("suffix"), "a modifier that is not there reads empty")
}

func TestParseSize(t *testing.T) {
	tests := map[string]int64{
		"5m":        5 * 1024 * 1024,
		"20M":       20 * 1024 * 1024,
		"512k":      512 * 1024,
		"2g":        2 * 1024 * 1024 * 1024,
		"1024":      1024,
		"unlimited": Unlimited,
		// `default` and an absent value both mean the channel carries no cap
		// of its own, which is a different answer from "no rotation".
		"default":  0,
		"":         0,
		"nonsense": 0,
	}
	for in, expected := range tests {
		assert.Equal(t, expected, ParseSize(in), "size %q", in)
	}
}

func TestParseCount(t *testing.T) {
	assert.Equal(t, int64(3), ParseCount("3"))
	assert.Equal(t, int64(Unlimited), ParseCount("unlimited"))
	// absent, which for versions means BIND keeps one file and never rotates
	assert.Equal(t, int64(0), ParseCount(""))
	assert.Equal(t, int64(0), ParseCount("garbage"))
}
