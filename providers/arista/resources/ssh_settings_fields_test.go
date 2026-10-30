// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"strings"
	"testing"
	"unicode"

	"go.mondoo.com/mql/providers/arista/resources/eos"
)

// schemaFields returns the resource field names the generated struct carries,
// one per field declared in the .lr, in schema spelling.
func schemaFields(resource any) []string {
	t := reflect.TypeOf(resource).Elem()
	res := []string{}
	for f := range t.Fields() {
		f := f
		if !f.IsExported() || !strings.HasPrefix(f.Type.String(), "plugin.TValue[") {
			continue
		}
		r := []rune(f.Name)
		r[0] = unicode.ToLower(r[0])
		res = append(res, string(r))
	}
	return res
}

// TestSshSettingsArgsCoverEverySchemaField guards the whole class of bug rather
// than the eight fields that hit it. Codegen accepts a field declared in the
// .lr with no population path: the generated getter just hands back the zero
// TValue, whose State is 0 — unset, not null — which crosses the plugin
// boundary as a primitive with no type information and reads client-side as a
// null with nothing pointing back at the provider. Nothing fails to build and
// no test goes red, so a field added to the schema and the parser but not to
// the creator ships silently empty.
func TestSshSettingsArgsCoverEverySchemaField(t *testing.T) {
	args := sshSettingsArgs(&eos.SshSettings{})

	for _, field := range schemaFields(&mqlAristaEosSshSettings{}) {
		if _, ok := args[field]; !ok {
			t.Errorf("arista.eos.sshSettings.%s is declared in the schema but never populated", field)
		}
	}
}

// TestSshSettingsArgsCarryTheParsedValues pins the containment fields against
// a block that sets each of them, so a mapping that is present but wired to
// the wrong source value still fails.
func TestSshSettingsArgsCarryTheParsedValues(t *testing.T) {
	s := &eos.SshSettings{
		Vrfs:                   []string{"MGMT"},
		LoginTimeout:           30,
		ConnectionLimit:        20,
		ConnectionPerHostLimit: 5,
		EmptyPasswords:         "deny",
		LogLevel:               "verbose",
		ClientAliveInterval:    60,
		ClientAliveCountMax:    3,
	}
	args := sshSettingsArgs(s)

	for field, want := range map[string]any{
		"loginTimeout":           int64(30),
		"connectionLimit":        int64(20),
		"connectionPerHostLimit": int64(5),
		"emptyPasswords":         "deny",
		"logLevel":               "verbose",
		"clientAliveInterval":    int64(60),
		"clientAliveCountMax":    int64(3),
	} {
		if got := args[field].Value; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}

	vrfs, ok := args["vrfs"].Value.([]any)
	if !ok || len(vrfs) != 1 || vrfs[0] != "MGMT" {
		t.Errorf("vrfs = %v, want [MGMT]", args["vrfs"].Value)
	}
}
