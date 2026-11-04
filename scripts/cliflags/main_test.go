// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func rec(version string, flags ...Flag) Record {
	return Record{Version: version, Connectors: []Connector{{Name: "junos", Aliases: []string{"jun"}, Flags: flags}}}
}

func TestBreaking(t *testing.T) {
	username := Flag{Long: "username", Short: "u", Type: "String"}
	for _, tc := range []struct {
		name     string
		old, cur Record
		want     string // empty when nothing breaks
	}{
		{"unchanged", rec("14.0.0", username), rec("14.0.0", username), ""},
		{"new optional flag", rec("14.0.0", username), rec("14.0.0", username, Flag{Long: "port", Type: "Int"}), ""},
		{"new shorthand", rec("14.0.0", Flag{Long: "port"}), rec("14.0.0", Flag{Long: "port", Short: "P"}), ""},
		{"default changed", rec("14.0.0", Flag{Long: "port", Default: "1"}), rec("14.0.0", Flag{Long: "port", Default: "2"}), ""},
		{
			"the regression this exists for: shorthand dropped",
			rec("13.0.0", username), rec("14.0.0", Flag{Long: "username", Type: "String"}),
			"--username lost its shorthand -u",
		},
		{
			"shorthand moved to another flag still works",
			rec("14.0.0", username),
			rec("14.0.0", Flag{Long: "username", Type: "String"}, Flag{Long: "user", Short: "u", Type: "String"}),
			"",
		},
		{"flag removed", rec("14.0.0", username), rec("14.0.0"), "--username was removed"},
		{"flag removed in a new major version without deprecation", rec("14.0.0", username), rec("15.0.0"), "--username was removed"},
		{
			"deprecated flag removed in the same major version",
			rec("14.0.0", Flag{Long: "old", Options: []string{"Deprecated"}}), rec("14.1.0"),
			"--old was removed",
		},
		{"deprecated flag removed in a new major version", rec("14.0.0", Flag{Long: "old", Options: []string{"Deprecated"}}), rec("15.0.0"), ""},
		{"type changed", rec("14.0.0", Flag{Long: "port", Type: "Int"}), rec("14.0.0", Flag{Long: "port", Type: "String"}), "changed type from Int to String"},
		{"became required", rec("14.0.0", Flag{Long: "port"}), rec("14.0.0", Flag{Long: "port", Options: []string{"Required"}}), "--port became required"},
		{"new required flag", rec("14.0.0"), rec("14.0.0", Flag{Long: "port", Options: []string{"Required"}}), "new flag --port is required"},
		{"connector removed", rec("14.0.0"), Record{Version: "14.0.0"}, `connector "junos" was removed`},
		{
			"alias removed", rec("14.0.0"),
			Record{Version: "14.0.0", Connectors: []Connector{{Name: "junos"}}},
			`lost its alias "jun"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(Breaking(tc.old, tc.cur), "\n")
			if tc.want == "" && got != "" {
				t.Fatalf("expected no breaking change, got: %s", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("expected %q in: %s", tc.want, got)
			}
		})
	}
}

func TestClashes(t *testing.T) {
	got := Clashes(map[string]Record{
		"a": {Connectors: []Connector{{Flags: []Flag{{Long: "user", Short: "u"}}}}},
		"b": {Connectors: []Connector{{Flags: []Flag{{Long: "user", Short: "u"}}}}},
		"c": {Connectors: []Connector{{Flags: []Flag{{Long: "username", Short: "u"}, {Long: "port", Short: "P"}}}}},
	})
	if len(got) != 1 || !strings.Contains(got[0], "--user (a, b)") || !strings.Contains(got[0], "--username (c)") {
		t.Fatalf("unexpected clashes: %v", got)
	}
}

func TestParseConstants(t *testing.T) {
	dir := t.TempDir()
	conn := filepath.Join(dir, "connection")
	if err := os.MkdirAll(conn, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conn, "c.go"), []byte(`package connection
const OptionToken = "token"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := Parse("config.go", `package config
import "go.mondoo.com/mql/providers/`+filepath.Base(dir)+`/connection"
var Config = plugin.Provider{Connectors: []plugin.Connector{{
	Name: "x",
	Flags: []plugin.Flag{{Long: connection.OptionToken}},
}}}`, dir, workingTree)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Connectors[0].Flags[0].Long != "token" {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestParse(t *testing.T) {
	rec, err := Parse("config.go", `package config
var Config = plugin.Provider{
	Name: "junos",
	Version: "14.0.2",
	Connectors: []plugin.Connector{{
		Name: "junos",
		Aliases: []string{"z", "a"},
		Flags: []plugin.Flag{
			{Long: "user", Short: "u", Type: plugin.FlagType_String, Default: "admin", Option: plugin.FlagOption_Required | plugin.FlagOption_Hidden},
			{Long: "ask", Type: plugin.FlagType_Bool},
		},
	}},
}`, t.TempDir(), workingTree)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != "14.0.2" || len(rec.Connectors) != 1 {
		t.Fatalf("unexpected record: %+v", rec)
	}
	c := rec.Connectors[0]
	if c.Aliases[0] != "a" || c.Flags[0].Long != "ask" {
		t.Fatalf("expected sorted output: %+v", c)
	}
	u := c.Flags[1]
	if u.Short != "u" || u.Type != "String" || u.Default != "admin" || !u.has("Required") || !u.has("Hidden") {
		t.Fatalf("unexpected flag: %+v", u)
	}
}

// A flag the tool can't read has to stop it, not go missing from the record.
func TestParseRejectsWhatItCannotRead(t *testing.T) {
	for name, src := range map[string]string{
		"flags in a variable":   `package config; var C = plugin.Provider{Connectors: []plugin.Connector{{Name: "x", Flags: common}}}`,
		"an unknown constant":   `package config; var C = plugin.Provider{Connectors: []plugin.Connector{{Name: "x", Flags: []plugin.Flag{{Long: name}}}}}`,
		"connectors from a var": `package config; var C = plugin.Provider{Connectors: all}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse("config.go", src, t.TempDir(), workingTree); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// A provider without a record at the base is compared with the base's config, whose
// constants have to come from the base too: read from the working tree, the flag
// below looks unchanged.
func TestBaseConfigUsesBaseConstants(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "providers", "x", "config")
	if err := os.MkdirAll(config, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(flag string) {
		t.Helper()
		src := `package config
const optionToken = "` + flag + `"
var Config = plugin.Provider{Connectors: []plugin.Connector{{
	Name: "x",
	Flags: []plugin.Flag{{Long: optionToken}},
}}}
`
		if err := os.WriteFile(filepath.Join(config, "config.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull,
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write("token")
	git("init", "-q")
	git("add", ".")
	git("commit", "-qm", "base")

	write("api-token")
	if err := run(root, "", true, false); err != nil {
		t.Fatal(err)
	}
	if err := run(root, "HEAD", false, false); err == nil {
		t.Fatal("renaming the flag through its constant was not reported as breaking")
	}
}

func TestLiteralVersion(t *testing.T) {
	src := []byte(`package config
var Config = plugin.Provider{Name: "x", Version: "14.0.2"}`)
	if v := literalVersion(src); v != "14.0.2" {
		t.Fatalf("unexpected version: %q", v)
	}
	src = []byte(`package config
var Config = plugin.Provider{Name: "core", Version: mql.GetVersion()}`)
	if v := literalVersion(src); v != "" {
		t.Fatalf("unexpected version: %q", v)
	}
}
