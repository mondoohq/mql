// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// The black-box MQL suite: every test here drives a real query through the
// executor against a mock connection, rather than calling a Go function.
//
// It is one file rather than one per resource because it must live in package
// resources_test: testutils imports providers/os/provider, which imports this
// package, so a test in package resources cannot reach the testers below
// without an import cycle. White-box tests for a resource belong beside it, in
// <resource>_test.go.
package resources_test

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/providers/os/resources"
	"go.mondoo.com/mql/providers/os/resources/firefox"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
)

var x = testutils.InitTester(testutils.LinuxMock())

func testWindowsQuery(t *testing.T, query string) []*llx.RawResult {
	win := testutils.InitTester(testutils.WindowsMock())
	return win.TestQuery(t, query)
}

// Core Language constructs
// ------------------------
// These tests are more generic MQL and resource tests. We have migrated them
// from their previous core package into the OS package, because it requires
// more resources (like file). Long-term we'd like to move them to a standalone
// (and dedicated) mock provider for testing. Other tests are found in the
// core provider counterpart to this test file.

func testChain(t *testing.T, codes ...string) {
	tr := testutils.InitTester(testutils.LinuxMock())
	for i := range codes {
		code := codes[i]
		t.Run(code, func(t *testing.T) {
			tr.TestQuery(t, code)
		})
	}
}

func TestErroneousLlxChains(t *testing.T) {
	testChain(t,
		`file("/etc/crontab") {
			permissions.group_readable == false
			permissions.group_writeable == false
			permissions.group_executable == false
		}`,
	)

	testChain(t,
		`file("/etc/profile").content.contains("umask 027") || file("/etc/bashrc").content.contains("umask 027")`,
		`file("/etc/profile").content.contains("umask 027") || file("/etc/bashrc").content.contains("umask 027")`,
	)

	testChain(t,
		`users.map(name) { _.contains("a") _.contains("b") }`,
	)

	testChain(t,
		`user(name: 'i_definitely_dont_exist').authorizedkeys`,
	)
}

func TestResource_InitWithResource(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "file(asset.platform).exists",
			Expectation: false,
		},
		{
			Code:        "'linux'.contains(asset.family)",
			Expectation: true,
		},
	})
}

func TestOS_Vars(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "p = file('/dummy.json'); parse.json(file: p).params.length",
			Expectation: int64(15),
		},
	})
}

func TestMap(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "{a: 123}",
			Expectation: map[string]any{"a": int64(123)},
		},
		{
			Code:        "return {a: 123}",
			Expectation: map[string]any{"a": int64(123)},
		},
		{
			Code:        "{a: 1, b: 2, c: 3}.where(key == 'c')",
			Expectation: map[string]any{"c": int64(3)},
		},
		{
			Code:        "{a: 1, b: 2, c: 3}.where(value < 3)",
			Expectation: map[string]any{"a": int64(1), "b": int64(2)},
		},
		{
			Code:        "parse.xml('/dummy.xml').params.length",
			Expectation: int64(1),
		},
		{
			Code:        "parse.xml('/dummy.xml').params.root.box.length",
			Expectation: int64(3),
		},
		{
			Code:        "parse.json('/dummy.json').params.length",
			Expectation: int64(15),
		},
		{
			Code:        "parse.json('/dummy.json').params.keys.length",
			Expectation: int64(15),
		},
		{
			Code:        "parse.json('/dummy.json').params.values.length",
			Expectation: int64(15),
		},
		{
			Code: "parse.json('/dummy.json').params { _['Protocol'] != 1 }",
			Expectation: map[string]any{
				"__t": llx.BoolTrue,
				"__s": llx.BoolTrue,
				"CQ28lTwZsvVdJM4dCyeTdbQhExY8oiUIcMoPyPjXAJNgtjMLnHK6qgEVywRY1Hbw9QqInuL06EWIOaEMj2e9NA==": llx.BoolTrue,
				// the comparison's operand is collected as a datapoint, so that a
				// failing assertion can report the value it actually saw
				"LCXQj0xjiWsmFuiDOIUFsxcFUaSQPRQ6CTTXaNl3BENej4ffvSZX7Z1rBoDlePTJNeW8XeF4/gOgkSwenn88Sw==": llx.DictData(nil),
			},
		},
	})
}

func TestListResource(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())

	t.Run("list resource by default returns the list", func(t *testing.T) {
		res := x.TestQuery(t, "users")
		assert.NotEmpty(t, res)
		assert.Len(t, res[0].Data.Value, 4)
	})

	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "users.where(name == 'root').length",
			Expectation: int64(1),
		},
		{
			Code:        "users.list.where(name == 'root').length",
			Expectation: int64(1),
		},
		{
			Code:        "users.where(name == 'rooot').list { uid }",
			Expectation: []any{},
		},
		{
			Code:        "users.where(uid > 0).where(uid < 0).list",
			Expectation: []any{},
		},
		{
			Code: `users.where(name == 'root').list {
				uid == 0
				gid == 0
			}`,
			Expectation: []any{
				map[string]any{
					"__t": llx.BoolTrue,
					"__s": llx.BoolTrue,
					"BamDDGp87sNG0hVjpmEAPEjF6fZmdA6j3nDinlgr/y5xK3KaLgulyscoeEEaEASm2RkRXifnWj3ZbF0OZBF6XA==": llx.BoolTrue,
					"ytOUfV4UyOjY0C6HKzQ8GcA/hshrh2ahRySNG41RbFt3TNNf+6gBuHvs2hGTNDPUZR/oN8WH0QFIYYm/Vj3pGQ==": llx.BoolTrue,
					// uid and gid are collected as datapoints, so that a failing
					// assertion can report the values it actually saw
					"aBOtIXBPoe9nWUDBl9sr+N5w+QLjyg8Vsr5dDM1hapmEyb4hX9KM2Q87iKM2mFWBHve+BMe/lARHrXwwyfvOxA==": llx.IntData(0),
					"ylMU7sDF2mljSq+Et4sJDLsZL6AJTL8VaJMEMpBk0OljnQTRBZBoq7C/DfUXuM667DH0hA+hP4Ywv5gfmVppog==": llx.IntData(0),
				},
			},
		},
		{
			Code:        "users.map(name)",
			Expectation: []any([]any{"root", "bin", "chris", "christopher"}),
		},
		{
			// outside variables cause the block to be standalone
			Code:        "n=false; users.contains(n)",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			// variables do not override local fields in blocks
			Code:        "name=false; users.contains(name)",
			ResultIndex: 1,
			Expectation: true,
		},
	})
}

func TestListResource_Assertions(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "users.contains(name == 'root')",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "users.where(uid < 100).contains(name == 'root')",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "users.all(uid >= 0)",
			Expectation: true,
		},
		{
			Code:        "users.where(uid < 100).all(uid >= 0)",
			Expectation: true,
		},
		{
			Code:        "users.any(uid < 100)",
			Expectation: true,
		},
		{
			Code:        "users.where(uid < 100).any(uid < 50)",
			Expectation: true,
		},
		{
			Code:        "users.one(uid == 0)",
			Expectation: true,
		},
		{
			Code:        "users.where(uid < 100).one(uid == 0)",
			Expectation: true,
		},
		{
			Code:        "users.none(uid == 99999)",
			Expectation: true,
		},
		{
			Code:        "users.where(uid < 100).none(uid == 1000)",
			Expectation: true,
		},
	})
}

func TestResource_duplicateFields(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code: "users.list.duplicates(gid) { gid }",
			Expectation: []any{
				map[string]any{
					"__t": llx.BoolTrue,
					"__s": llx.NilData,
					"Cuv5ImO3PMlg/BnsKFcT/K88cResNOFnEZnbYwBT44aycwbRuvhhMqjq0E96i+POSgNSxO1QPi6U2VNNRuSPtQ==": &llx.RawData{
						Type:  "\x05",
						Value: int64(1000),
						Error: nil,
					},
				},
				map[string]any{
					"__t": llx.BoolTrue,
					"__s": llx.NilData,
					"Cuv5ImO3PMlg/BnsKFcT/K88cResNOFnEZnbYwBT44aycwbRuvhhMqjq0E96i+POSgNSxO1QPi6U2VNNRuSPtQ==": &llx.RawData{
						Type:  "\x05",
						Value: int64(1000),
						Error: nil,
					},
				},
			},
		},
	})
}

func TestDict_Methods_In(t *testing.T) {
	p := "parse.json('/dummy.json')."

	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        p + "params['hello'].in(['1','2','hello'])",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        p + "params['hello'].in(['1','2'])",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			// embedded value doesn't exist
			Code:        p + "params.e.hi.in(['hello','world'])",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			// embedded value doesn't exist
			Code:        p + "params.e.hi.in(['world'])",
			ResultIndex: 1,
			Expectation: false,
		},
	})
}

func TestDict_Methods_NotIn(t *testing.T) {
	p := "parse.json('/dummy.json')."

	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        p + "params['hello'].notIn(['1','2','hello'])",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			Code:        p + "params['hello'].notIn(['1','2'])",
			ResultIndex: 1,
			Expectation: true,
		},
	})
}

func TestDict_Methods_InRange(t *testing.T) {
	p := "parse.json('/dummy.json')."

	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        p + "params['1'].inRange(1,3)",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        p + "params['1'].inRange(3,4)",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			// value doesn't exist
			Code:        p + "params['123'].inRange(0,999)",
			ResultIndex: 1,
			Expectation: false,
		},
	})
}

func TestDict_Methods_Contains(t *testing.T) {
	p := "parse.json('/dummy.json')."

	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        p + "params['hello'].contains('ll')",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        p + "params['hello'].contains('lloo')",
			ResultIndex: 2,
			Expectation: false,
		},
		{
			Code:        p + "params['hello'].contains(['xx','he'])",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        p + "params['hello'].contains(['xx'])",
			ResultIndex: 2,
			Expectation: false,
		},
		{
			Code:        p + "params['string-array'].contains('a')",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].containsOnly(['c', 'a', 'b'])",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].containsOnly(['a', 'b'])",
			ResultIndex: 2,
			Expectation: false,
		},
		// {
		// 	p + "params['string-array'].containsOnly('a')",
		// 	1, false,
		// },
		{
			Code:        p + "params['string-array'].containsNone(['d','e'])",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].containsNone(['a', 'e'])",
			ResultIndex: 2,
			Expectation: false,
		},
		{
			Code:        p + "params['string-array'].containsNone([/z/, /ひ/])",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].containsNone([/a/, /z/])",
			ResultIndex: 2,
			Expectation: false,
		},
		{
			Code:        p + "params['string-array'].none('a')",
			ResultIndex: 2,
			Expectation: false,
		},
		{
			Code:        p + "params['string-array'].contains(_ == 'a')",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].none(_ == /a/)",
			ResultIndex: 2,
			Expectation: false,
		},
		{
			Code:        p + "params['string-array'].contains(value == 'a')",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].none(value == 'a')",
			ResultIndex: 2,
			Expectation: false,
		},
	})
}

func TestDict_Methods_Map(t *testing.T) {
	p := "parse.json('/dummy.json')."

	expectedTime, err := time.Parse(time.RFC3339, "2016-01-28T23:02:24Z")
	if err != nil {
		panic(err.Error())
	}

	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        p + "params.nonexistent.contains('sth')",
			Expectation: false,
			ResultIndex: 1,
		},
		{
			Code:        p + "params['string-array'].where(_ == 'a')",
			Expectation: []any{"a"},
		},
		{
			Code:        p + "params.users.recurse(name != empty).map(name)",
			Expectation: []any{"yor", "loid", "anya"},
		},
		{
			Code:        p + "params['string-array'].in(['a', 'b', 'c'])",
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].in(['z', 'b'])",
			Expectation: false,
		},
		{
			Code:        p + "params['string-array'].one(_ == 'a')",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].all(_ != 'z')",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        p + "params['string-array'].any(_ != 'a')",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        p + "params['does_not_exist'].any(_ != 'a')",
			ResultIndex: 1,
			Expectation: nil,
		},
		{
			Code:        p + "params['f'].map(_['ff'])",
			Expectation: []any{float64(3)},
		},
		// {
		// 	p + "params { _['1'] == _['1.0'] }",
		// 	0, true,
		// },
		{
			Code:        p + "params['1'] - 2",
			Expectation: float64(-1),
		},
		{
			Code:        p + "params['int-array']",
			Expectation: []any{float64(1), float64(2), float64(3)},
		},
		{
			Code:        p + "params['hello'] + ' world'",
			Expectation: "hello world",
		},
		{
			Code:        p + "params['hello'].trim('ho')",
			Expectation: "ell",
		},
		{
			Code:        p + "params['dict'].length",
			Expectation: int64(3),
		},
		{
			Code:        p + "params['dict'].keys.length",
			Expectation: int64(3),
		},
		{
			Code:        p + "params['dict'].values.length",
			Expectation: int64(3),
		},
		{
			Code:        "parse.date(" + p + "params['date'])",
			Expectation: &expectedTime,
		},
		{
			Code:        p + "params.first",
			Expectation: float64(1),
		},
		{
			Code:        p + "params.last",
			Expectation: "🌒",
		},
		{
			Code:        p + "params['aoa'].flat",
			Expectation: []any{float64(1), float64(2), float64(3)},
		},
		// Null equality: a missing dict key is null.
		{
			Code:        p + "params['yo'] == null",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        p + "params['yo'] != null",
			ResultIndex: 1,
			Expectation: false,
		},
		// Comparisons against nonexistent (null) dict keys evaluate to false,
		// not error. A missing value is not less/greater/equal to anything.
		{
			Code:        p + "params['yo'] > 3",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			Code:        p + "params['yo'] >= 3",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			Code:        p + "params['yo'] < 3",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			Code:        p + "params['yo'] <= 3",
			ResultIndex: 1,
			Expectation: false,
		},
	})

	x.TestSimpleErrors(t, []testutils.SimpleTest{
		{
			Code:        p + "params['does not exist'].values",
			Expectation: "failed to get values of `null`",
		},
	})
}

func TestDict_Methods_Array(t *testing.T) {
	p := "parse.json('/dummy.array.json')."

	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        p + "params[0]",
			Expectation: float64(1),
		},
		{
			Code:        p + "params[1]",
			Expectation: "hi",
		},
		{
			Code:        p + "params[2]",
			Expectation: map[string]any{"ll": float64(0)},
		},
		{
			Code:        p + "params.first",
			Expectation: float64(1),
		},
		{
			Code:        p + "params.last",
			Expectation: "z",
		},
		{
			Code:        p + "params.where(-1).first",
			Expectation: nil,
		},
		{
			Code:        p + "params.where(-1).last",
			Expectation: nil,
		},
	})
}

func TestDict_Methods_OtherJson(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "parse.json('/dummy.number.json').params",
			Expectation: float64(1.23),
		},
		{
			Code:        "parse.json('/dummy.string.json').params",
			Expectation: "hi",
		},
		{
			Code:        "parse.json('/dummy.true.json').params",
			Expectation: true,
		},
		{
			Code:        "parse.json('/dummy.false.json').params",
			Expectation: false,
		},
		{
			Code:        "parse.json('/dummy.null.json').params",
			Expectation: nil,
		},
	})
}

func TestArrayBlockMissingFileContent(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	res := x.TestQuery(t, "users.list { file(_.name + 'doesnotexist').content }")
	assert.NotEmpty(t, res)
	queryResult := res[len(res)-1]
	require.NotNil(t, queryResult)
	require.NoError(t, queryResult.Data.Error)
}

func TestBrokenQueryExecutionGH674(t *testing.T) {
	// See https://github.com/mondoohq/mql/issues/674
	x := testutils.InitTester(testutils.LinuxMock())
	bundle, err := x.Compile(`
a = file("/tmp/ref1").content.trim
file(a).path == "/tmp/ref2"
file(a).content.trim == "asdf"
	`)
	require.NoError(t, err)

	results := x.TestMqlc(t, bundle, nil)
	require.Len(t, results, 5)
}

// TestAssessment_ContextResourceListSurfacesFailures is an end-to-end regression
// test for "empty assessments": a failing list assertion over a resource that
// carries a `@context` annotation (here sshd.config.matchBlock) must surface the
// failing resources in the assessment's `actual` value.
//
// The context block has sub-fields (e.g. range) that can be unset; an unset
// sub-field serialized to an untyped primitive used to abort conversion of the
// entire failing-resource list, leaving `actual` empty. Reporters (CLI, SARIF)
// then showed no failing resources and no source locations.
func TestAssessment_ContextResourceListSurfacesFailures(t *testing.T) {
	bundle, err := x.Compile(`sshd.config.blocks.all(criteria == "nonexistent")`)
	require.NoError(t, err)

	results, err := x.ExecuteCode(bundle, nil)
	require.NoError(t, err)

	assessment := llx.Results2AssessmentLookupV2(bundle, func(s string) (*llx.RawResult, bool) {
		r, ok := results[s]
		return r, ok
	})
	require.NotNil(t, assessment)
	require.False(t, assessment.Success, "the check is expected to fail")
	require.NotEmpty(t, assessment.Results)

	item := assessment.Results[0]
	require.False(t, item.Success)
	require.NotNil(t, item.Actual, "failing resources must be surfaced in actual")

	rd := item.Actual.RawData()
	require.NoError(t, rd.Error)
	arr, ok := rd.Value.([]any)
	require.True(t, ok, "actual should be the list of failing resources")
	assert.NotEmpty(t, arr, "the failing-resource list must not be empty")
}

func TestResource_AuditdConfig(t *testing.T) {
	x.TestSimpleErrors(t, []testutils.SimpleTest{
		{
			Code:        "auditd.config('nopath').params",
			ResultIndex: 0,
			Expectation: "file 'nopath' not found",
		},
	})

	t.Run("auditd file path", func(t *testing.T) {
		res := x.TestQuery(t, "auditd.config.file.path")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
	})

	t.Run("auditd is downcasing relevant params", func(t *testing.T) {
		res := x.TestQuery(t, "auditd.config.params.log_format")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, "enriched", res[0].Data.Value)
	})

	t.Run("auditd is NOT downcasing other params", func(t *testing.T) {
		res := x.TestQuery(t, "auditd.config.params.log_file")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, "/var/log/audit/AuDiT.log", res[0].Data.Value)
	})
}

func TestResource_AuditdRules(t *testing.T) {
	t.Run("auditd rules path", func(t *testing.T) {
		x.TestSimple(t, []testutils.SimpleTest{
			{
				Code:        "auditd.rules.path",
				ResultIndex: 0,
				Expectation: "/etc/audit/rules.d",
			},
			{
				Code:        "auditd.rules.files.first.path",
				ResultIndex: 0,
				Expectation: "/etc/sudoers",
			},
			{
				Code:        "auditd.rules.controls[0].flag",
				ResultIndex: 0,
				Expectation: "-D",
			},
			{
				Code:        "auditd.rules.syscalls.where(action==\"always\" && fields.contains(key==\"path\" && value==\"/usr/bin/systemd-run\")).length",
				ResultIndex: 0,
				Expectation: int64(2),
			},
		})
	})

	t.Run("-k flag normalized into fields", func(t *testing.T) {
		// The -k flag is shorthand for -F key=<value>. Verify that the
		// parser normalizes it into the fields array so queries don't
		// need to check both representations.
		x.TestSimple(t, []testutils.SimpleTest{
			{
				Code:        `auditd.rules.syscalls.where(keyname == "priv_escalation")[0].fields.where(key == "key" && value == "priv_escalation").length`,
				ResultIndex: 0,
				Expectation: int64(1),
			},
		})
	})

	t.Run("auditd comparisons field", func(t *testing.T) {
		x.TestSimple(t, []testutils.SimpleTest{
			// Test that rules with -C have populated comparisons
			{
				Code:        "auditd.rules.syscalls.where(comparisons.length > 0).length",
				ResultIndex: 0,
				Expectation: int64(1),
			},
			// Test that rules without -C have empty comparisons
			{
				Code:        "auditd.rules.syscalls.where(comparisons.length == 0).length",
				ResultIndex: 0,
				Expectation: int64(3),
			},
			// Test filtering by comparison field values
			{
				Code:        `auditd.rules.syscalls.where(comparisons.any(field1 == "uid" && op == "!=" && field2 == "euid")).length`,
				ResultIndex: 0,
				Expectation: int64(1),
			},
			// Test accessing comparisons field on a specific rule
			{
				Code:        `auditd.rules.syscalls.where(keyname == "priv_escalation")[0].comparisons[0].field1`,
				ResultIndex: 0,
				Expectation: "uid",
			},
			// Test accessing second comparison
			{
				Code:        `auditd.rules.syscalls.where(keyname == "priv_escalation")[0].comparisons[1].field2`,
				ResultIndex: 0,
				Expectation: "egid",
			},
		})
	})
}

func TestResource_Auditpol(t *testing.T) {

	t.Run("list contains the policy rows, not the CSV header", func(t *testing.T) {
		res := testWindowsQuery(t, "auditpol.length")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(59), res[0].Data.Value)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testWindowsQuery(t, "auditpol.where(subcategory == 'Credential Validation')[0].subcategory")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Credential Validation", res[0].Data.Value)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testWindowsQuery(t, "auditpol.where(subcategory == 'Credential Validation').length")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(1), res[0].Data.Value)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testWindowsQuery(t, "auditpol.where(subcategory == 'Credential Validation')[0].inclusionsetting")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Success", res[0].Data.Value)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testWindowsQuery(t, "auditpol.where(subcategory == 'Application Group Management') { inclusionsetting == 'Success and Failure'}")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		r, found := res[0].Data.IsTruthy()
		assert.False(t, r)
		assert.True(t, found)
	})

	// success / failure booleans derived from inclusionsetting, exercised
	// through the resource methods rather than the pure helper.
	successFailureCases := []struct {
		subcategory string // its inclusionsetting in the recording
		success     bool
		failure     bool
	}{
		{"System Integrity", true, true},            // "Success and Failure"
		{"Security State Change", true, false},      // "Success"
		{"Security System Extension", false, false}, // "No Auditing"
	}
	for _, tc := range successFailureCases {
		t.Run("success for "+tc.subcategory, func(t *testing.T) {
			res := testWindowsQuery(t, "auditpol.where(subcategory == '"+tc.subcategory+"')[0].success")
			assert.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.Equal(t, tc.success, res[0].Data.Value)
		})
		t.Run("failure for "+tc.subcategory, func(t *testing.T) {
			res := testWindowsQuery(t, "auditpol.where(subcategory == '"+tc.subcategory+"')[0].failure")
			assert.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.Equal(t, tc.failure, res[0].Data.Value)
		})
	}
}

// TestResource_AuditpolGerman exercises success/failure end-to-end against a
// recording of a German-localized `auditpol /r`, where both the subcategory
// names and the inclusion settings are localized ("Erfolg und Fehler" etc.).
// It proves the parse -> resource -> locale-table chain on non-English output
// and that the cnspec audit-policy queries — which select by locale-independent
// GUID and assert on the success/failure booleans — hold on a German system.
func TestResource_AuditpolGerman(t *testing.T) {
	abs, err := filepath.Abs("testdata/auditpol_windows_de.json")
	require.NoError(t, err)
	de := testutils.InitTester(testutils.RecordingMock(abs))

	// subcategoryguid -> expected booleans for its German inclusion setting.
	cases := []struct {
		guid             string
		setting          string
		success, failure bool
	}{
		{"0CCE9239-69AE-11D9-BED3-505054503030", "Erfolg und Fehler", true, true},
		{"0CCE922F-69AE-11D9-BED3-505054503030", "Erfolg", true, false},
		{"0CCE9234-69AE-11D9-BED3-505054503030", "Fehler", false, true},
		{"0CCE9211-69AE-11D9-BED3-505054503030", "Keine Überwachung", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.setting, func(t *testing.T) {
			res := de.TestQuery(t, "auditpol.where(subcategoryguid == '"+tc.guid+"')[0].success")
			require.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.Equal(t, tc.success, res[0].Data.Value, "success")

			res = de.TestQuery(t, "auditpol.where(subcategoryguid == '"+tc.guid+"')[0].failure")
			require.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.Equal(t, tc.failure, res[0].Data.Value, "failure")
		})
	}

	// The exact assertion patterns the cnspec mondoo-windows-security queries
	// use, verified against the German recording (props removed in cnspec#2744).
	patternCases := []struct {
		query string
		want  bool
	}{
		{"auditpol.where(subcategoryguid == '0CCE9217-69AE-11D9-BED3-505054503030').all(failure)", true},
		{"auditpol.where(subcategoryguid == '0CCE922F-69AE-11D9-BED3-505054503030').all(success)", true},
		{"auditpol.where(subcategoryguid == '0CCE9239-69AE-11D9-BED3-505054503030').all(success && failure)", true},
		{"auditpol.where(subcategoryguid == '0CCE9234-69AE-11D9-BED3-505054503030').all(failure && success == false)", true},
	}
	for _, tc := range patternCases {
		t.Run(tc.query, func(t *testing.T) {
			res := de.TestQuery(t, tc.query)
			require.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.Equal(t, tc.want, res[0].Data.Value)
		})
	}
}

func TestResource_AuthorizedKeys(t *testing.T) {
	t.Run("view authorized keys file", func(t *testing.T) {
		res := x.TestQuery(t, "authorizedkeys('/home/chris/.ssh/authorized_keys').content")
		assert.NotEmpty(t, res)
		assert.Equal(t, 745, len(res[0].Data.Value.(string)))
	})

	t.Run("test authorized keys type", func(t *testing.T) {
		res := x.TestQuery(t, "authorizedkeys('/home/chris/.ssh/authorized_keys').list[0].type")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "ssh-rsa", res[0].Data.Value)
	})

	t.Run("test authorized keys type", func(t *testing.T) {
		res := x.TestQuery(t, "authorizedkeys('/home/chris/.ssh/authorized_keys').list[0].label")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "chris@lollyrock.com", res[0].Data.Value)
	})

	t.Run("test that the user exists", func(t *testing.T) {
		res := x.TestQuery(t, "users.where( name == 'chris' ).list[0].authorizedkeys.list[0].type")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "ssh-rsa", res[0].Data.Value)
	})
}

const passwdContent = `root:x:0:0::/root:/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
mail:x:8:12::/var/spool/mail:/usr/bin/nologin
`

func TestResource_File(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "file('/etc/passwd').exists",
			ResultIndex: 0, Expectation: true,
		},
		{
			Code:        "file('/etc/passwd').basename",
			ResultIndex: 0, Expectation: "passwd",
		},
		{
			Code:        "file('/etc/passwd').dirname",
			ResultIndex: 0, Expectation: "/etc",
		},
		{
			Code:        "file('/etc/passwd').size",
			ResultIndex: 0, Expectation: int64(len(passwdContent)),
		},
		{
			Code:        "file('/etc/passwd').permissions.mode",
			ResultIndex: 0, Expectation: int64(420),
		},
		{
			Code:        "file('/etc/passwd').content",
			ResultIndex: 0, Expectation: passwdContent,
		},
	})
}

func TestResource_File_NotExist(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "file('Nope').exists",
			ResultIndex: 0, Expectation: false,
		},
		{
			Code:        "file('Nope').content",
			ResultIndex: 0, Expectation: nil,
		},
		{
			Code:        "file('Nope').content == 'x'",
			ResultIndex: 0, Expectation: nil,
		},
		{
			Code:        "file('Nope').size > 0",
			ResultIndex: 0, Expectation: nil,
		},
		{
			Code:        "file('Nope').permissions.mode == 420",
			ResultIndex: 0, Expectation: nil,
		},
		{
			Code:        "file('Nope').user.name == 'root'",
			ResultIndex: 0, Expectation: nil,
		},
		{
			Code:        "file('Nope').group.name == 'root'",
			ResultIndex: 0, Expectation: nil,
		},
	})
}

func TestResource_File_Permissions(t *testing.T) {
	testCases := []struct {
		mode            int64
		userReadable    bool
		userWriteable   bool
		userExecutable  bool
		groupReadable   bool
		groupWriteable  bool
		groupExecutable bool
		otherReadable   bool
		otherWriteable  bool
		otherExecutable bool
		suid            bool
		sgid            bool
		sticky          bool
		isDir           bool
		isFile          bool
		isSymlink       bool

		focus      bool
		expectedID string
	}{
		{
			mode:            0o755,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  true,
			groupReadable:   true,
			groupExecutable: true,
			otherReadable:   true,
			otherExecutable: true,
			isFile:          true,

			expectedID: "-rwxr-xr-x",
		},
		{
			mode:            0o755,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  true,
			groupReadable:   true,
			groupExecutable: true,
			otherReadable:   true,
			otherExecutable: true,
			isFile:          true,
			suid:            true,

			expectedID: "-rwsr-xr-x",
		},
		{
			mode:            0o655,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  false,
			groupReadable:   true,
			groupExecutable: true,
			otherReadable:   true,
			otherExecutable: true,
			isFile:          true,
			suid:            true,

			expectedID: "-rwSr-xr-x",
		},
		{
			mode:            0o755,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  true,
			groupReadable:   true,
			groupExecutable: true,
			otherReadable:   true,
			otherExecutable: true,
			isDir:           true,

			expectedID: "drwxr-xr-x",
		},
		{
			mode:            0o755,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  true,
			groupReadable:   true,
			groupExecutable: true,
			otherReadable:   true,
			otherExecutable: true,
			isDir:           true,
			sticky:          true,

			expectedID: "drwxr-xr-t",
		},
		{
			mode:            0o754,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  true,
			groupReadable:   true,
			groupExecutable: true,
			otherReadable:   true,
			otherExecutable: false,
			isDir:           true,
			sticky:          true,

			expectedID: "drwxr-xr-T",
		},
		{
			mode:            0o755,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  true,
			groupReadable:   true,
			groupExecutable: true,
			otherReadable:   true,
			otherExecutable: true,
			isFile:          true,
			sgid:            true,
			focus:           true,
			expectedID:      "-rwxr-sr-x",
		},
		{
			mode:            0o754,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  true,
			groupReadable:   true,
			groupExecutable: false,
			otherReadable:   true,
			otherExecutable: true,
			isFile:          true,
			sgid:            true,

			expectedID: "-rwxr-Sr-x",
		},
		{
			mode:            0o755,
			userReadable:    true,
			userWriteable:   true,
			userExecutable:  true,
			groupReadable:   true,
			groupExecutable: true,
			otherReadable:   true,
			otherExecutable: true,
			isSymlink:       true,

			expectedID: "lrwxr-xr-x",
		},
	}

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	for _, tc := range testCases {
		if !tc.focus {
			continue
		}

		permRaw, err := resources.CreateResource(
			runtime,
			"file.permissions",
			map[string]*llx.RawData{
				"mode":             llx.IntData(int64(tc.mode)),
				"user_readable":    llx.BoolData(tc.userReadable),
				"user_writeable":   llx.BoolData(tc.userWriteable),
				"user_executable":  llx.BoolData(tc.userExecutable),
				"group_readable":   llx.BoolData(tc.groupReadable),
				"group_writeable":  llx.BoolData(tc.groupWriteable),
				"group_executable": llx.BoolData(tc.groupExecutable),
				"other_readable":   llx.BoolData(tc.otherReadable),
				"other_writeable":  llx.BoolData(tc.otherWriteable),
				"other_executable": llx.BoolData(tc.otherExecutable),
				"suid":             llx.BoolData(tc.suid),
				"sgid":             llx.BoolData(tc.sgid),
				"sticky":           llx.BoolData(tc.sticky),
				"isDirectory":      llx.BoolData(tc.isDir),
				"isFile":           llx.BoolData(tc.isFile),
				"isSymlink":        llx.BoolData(tc.isSymlink),
			},
		)
		require.NoError(t, err)
		require.Equal(t, tc.expectedID, permRaw.MqlID())
	}
}

func TestResource_FilesFind(t *testing.T) {
	res := x.TestQuery(t, "files.find(from: '/etc').list")
	assert.NotEmpty(t, res)
	testutils.TestNoResultErrors(t, res)
	assert.Equal(t, 5, len(res[0].Data.Value.([]any)))
}

// These tests cover what only the resource layer can show: that a field
// resolves to an explicit null rather than staying unset, that an error
// reaches the caller naming the file it came from, and that a policy set is
// traversable by key from MQL. What a policy document parses to, which paths
// are probed, and how two sources merge are settled in the firefox package,
// against the same shapes but without a runtime in the way.

// The recording each test runs against is built here rather than checked in.
// A stored recording of an unmanaged host is a copy of the candidate list, and
// a copy goes stale silently: add a probe path to the resource and the file
// still describes the old host, so the new path is never exercised. Building
// it from PolicyFileCandidates means the fixture cannot drift from the code.
func firefoxLinuxHost(t *testing.T, files map[string]string) firefoxHost {
	t.Helper()

	type recordedResource struct {
		Resource string
		ID       string
		Fields   map[string]*llx.RawData
	}

	resources := []recordedResource{}
	for _, path := range firefox.PolicyFileCandidates("linux") {
		fields := map[string]*llx.RawData{
			"path":   llx.StringData(path),
			"exists": llx.BoolData(false),
		}
		if content, ok := files[path]; ok {
			fields["exists"] = llx.BoolData(true)
			fields["content"] = llx.StringData(content)
		}
		resources = append(resources, recordedResource{
			Resource: "file",
			ID:       path,
			Fields:   fields,
		})
	}

	recording := struct {
		Assets []struct {
			Asset       *inventory.Asset   `json:"asset"`
			Connections []any              `json:"connections"`
			Resources   []recordedResource `json:"resources"`
		} `json:"assets"`
	}{
		Assets: []struct {
			Asset       *inventory.Asset   `json:"asset"`
			Connections []any              `json:"connections"`
			Resources   []recordedResource `json:"resources"`
		}{{
			Asset: &inventory.Asset{
				Id:          "firefox-policies-linux",
				PlatformIds: []string{"//platformid.api.mondoo.app/test/firefox-policies-linux"},
				Name:        "firefox-policies-linux",
				Platform: &inventory.Platform{
					Name:    "debian",
					Arch:    "aarch64",
					Title:   "Debian GNU/Linux",
					Family:  []string{"debian", "linux", "unix", "os"},
					Version: "12",
				},
			},
			Connections: []any{map[string]any{
				"url":       "local://",
				"provider":  "os",
				"connector": "local",
				"version":   "",
			}},
			Resources: resources,
		}},
	}

	raw, err := json.Marshal(recording)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "recording.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	tester := testutils.InitTester(testutils.RecordingMock(path))
	return firefoxHost{
		query: func(t *testing.T, query string) []*llx.RawResult {
			t.Helper()
			res := tester.TestQuery(t, query)
			require.NotEmpty(t, res)
			return res
		},
	}
}

type firefoxHost struct {
	query func(t *testing.T, query string) []*llx.RawResult
}

// value returns the result of a single-value query.
func (h firefoxHost) value(t *testing.T, query string) *llx.RawResult {
	t.Helper()
	res := h.query(t, query)
	return res[0]
}

// outcome returns what a comparison evaluated to, which is what a policy check
// reports, rather than the value being compared.
func (h firefoxHost) outcome(t *testing.T, query string) *llx.RawResult {
	t.Helper()
	res := h.query(t, query)
	return res[len(res)-1]
}

const (
	// A managed host, in the shape Debian's firefox-esr package installs.
	esrPolicy = `{
  "policies": {
    "SSLVersionMin": "tls1.2",
    "SanitizeOnShutdown": { "Cache": true, "Cookies": false, "Locked": true },
    "Preferences": {
      "security.default_personal_cert": { "Value": "Ask Every Time", "Status": "locked" }
    }
  }
}`
	esrPolicyPath = "/usr/lib/firefox-esr/distribution/policies.json"

	systemPolicyPath = "/etc/firefox/policies/policies.json"
)

// An unmanaged Firefox has no policy file anywhere, and that is the normal
// state of the overwhelming majority of hosts. Every field has to resolve to
// an explicit answer rather than being left unset, because an unresolved field
// is what makes the runtime either re-fetch forever or panic on a missing
// value.
func TestResource_FirefoxPoliciesUnmanaged(t *testing.T) {
	x := firefoxLinuxHost(t, nil)

	t.Run("configured is false, not an error", func(t *testing.T) {
		res := x.value(t, "firefox.policies.configured")
		assert.Empty(t, res.Result().Error)
		assert.Equal(t, false, res.Data.Value)
	})

	t.Run("source names nothing", func(t *testing.T) {
		res := x.value(t, "firefox.policies.source")
		assert.Empty(t, res.Result().Error)
		assert.Equal(t, "", res.Data.Value)
	})

	t.Run("params resolves to null", func(t *testing.T) {
		res := x.value(t, "firefox.policies.params")
		assert.Empty(t, res.Result().Error)
		assert.Nil(t, res.Data.Value)
	})

	t.Run("file resolves to null", func(t *testing.T) {
		res := x.value(t, "firefox.policies.file")
		assert.Empty(t, res.Result().Error)
		assert.Nil(t, res.Data.Value)
	})

	t.Run("inputs is an empty list", func(t *testing.T) {
		res := x.value(t, "firefox.policies.inputs.length")
		assert.Empty(t, res.Result().Error)
		assert.Equal(t, int64(0), res.Data.Value)
	})

	// The direction that actually matters. A check that reads an absent policy
	// as satisfied is worse than no check at all, because it reports a host as
	// hardened precisely when it is not.
	t.Run("a check against an absent policy is false, never vacuously true", func(t *testing.T) {
		res := x.outcome(t, `firefox.policies.params["SSLVersionMin"] == "tls1.2"`)
		assert.NotEqual(t, true, res.Data.Value, "an unconfigured host must not satisfy a policy check")
	})

	t.Run("reading a key out of a null policy set does not panic", func(t *testing.T) {
		res := x.value(t, `firefox.policies.params["SanitizeOnShutdown"]["Cookies"]`)
		assert.Nil(t, res.Data.Value)
	})
}

// A managed host, reached through the probe order rather than through a path
// the test names. Debian and Ubuntu ship Firefox as firefox-esr, so the ESR
// install prefix has to be one of the paths that probe finds.
func TestResource_FirefoxPoliciesManaged(t *testing.T) {
	x := firefoxLinuxHost(t, map[string]string{esrPolicyPath: esrPolicy})

	t.Run("the file is found and reported", func(t *testing.T) {
		res := x.value(t, "firefox.policies.file.path")
		assert.Empty(t, res.Result().Error)
		assert.Equal(t, esrPolicyPath, res.Data.Value)
	})

	t.Run("configured is true and the source is the file", func(t *testing.T) {
		assert.Equal(t, true, x.value(t, "firefox.policies.configured").Data.Value)
		assert.Equal(t, "file", x.value(t, "firefox.policies.source").Data.Value)
	})

	t.Run("a check against a configured policy passes", func(t *testing.T) {
		res := x.outcome(t, `firefox.policies.params["SSLVersionMin"] == "tls1.2"`)
		assert.Empty(t, res.Result().Error)
		assert.Equal(t, true, res.Data.Value)
	})

	t.Run("nested policies are reachable by key", func(t *testing.T) {
		res := x.value(t, `firefox.policies.params["SanitizeOnShutdown"]["Locked"]`)
		assert.Equal(t, true, res.Data.Value)
	})

	t.Run("preferences keyed by preference name are reachable", func(t *testing.T) {
		res := x.value(t,
			`firefox.policies.params["Preferences"]["security.default_personal_cert"]["Status"]`)
		assert.Equal(t, "locked", res.Data.Value)
	})

	t.Run("inputs lists the one file that contributed", func(t *testing.T) {
		assert.Equal(t, int64(1), x.value(t, "firefox.policies.inputs.length").Data.Value)
		assert.Equal(t, "file", x.value(t, "firefox.policies.inputs[0].source").Data.Value)
	})
}

// /etc wins outright over the install prefix, and nothing is merged between
// them: the losing file's keys are absent, not overridden.
func TestResource_FirefoxPoliciesFirstMatchWins(t *testing.T) {
	x := firefoxLinuxHost(t, map[string]string{
		systemPolicyPath: `{"policies":{"AdminOwned":true,"SSLVersionMin":"tls1.3"}}`,
		esrPolicyPath:    esrPolicy,
	})

	assert.Equal(t, systemPolicyPath, x.value(t, "firefox.policies.file.path").Data.Value)
	assert.Equal(t, "tls1.3", x.value(t, `firefox.policies.params["SSLVersionMin"]`).Data.Value)
	assert.Nil(t, x.value(t, `firefox.policies.params["Preferences"]`).Data.Value,
		"a key of the losing file must not appear in the result")
}

// A policy file that exists but declares nothing is not a managed host, and
// must not be reported as one. The file is still reported, so a permission or
// ownership check can compose onto it.
func TestResource_FirefoxPoliciesEmptyFile(t *testing.T) {
	x := firefoxLinuxHost(t, map[string]string{systemPolicyPath: ""})

	t.Run("an empty file declares no configuration", func(t *testing.T) {
		res := x.value(t, "firefox.policies.configured")
		assert.Empty(t, res.Result().Error)
		assert.Equal(t, false, res.Data.Value)
	})

	t.Run("params resolves to null rather than an empty dict", func(t *testing.T) {
		res := x.value(t, "firefox.policies.params")
		assert.Empty(t, res.Result().Error)
		assert.Nil(t, res.Data.Value)
	})

	t.Run("the file that was found is still reported", func(t *testing.T) {
		assert.Equal(t, systemPolicyPath, x.value(t, "firefox.policies.file.path").Data.Value)
	})
}

// A deployed-but-broken policy file is a misconfiguration worth surfacing.
// Reporting it as "no policy deployed" would be a false all-clear on a host an
// administrator believes is locked down, so it has to be distinguishable from
// absent — and the error has to name the file, or "the JSON is broken" is not
// actionable on a host that could carry one in any of several locations.
func TestResource_FirefoxPoliciesMalformedFile(t *testing.T) {
	x := firefoxLinuxHost(t, map[string]string{systemPolicyPath: `{"policies": {`})

	res := x.value(t, "firefox.policies.configured")
	require.NotEmpty(t, res.Result().Error, "malformed JSON must surface as an error, not as an unmanaged host")
	assert.Contains(t, res.Result().Error, "failed to parse Firefox policy file")
	assert.Contains(t, res.Result().Error, systemPolicyPath)
}

func TestResource_Groups(t *testing.T) {

	t.Run("test a specific group", func(t *testing.T) {
		res := x.TestQuery(t, "groups.list[0].name")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "root", res[0].Data.Value)
	})

	t.Run("test group init (gid)", func(t *testing.T) {
		res := x.TestQuery(t, "group(gid: 1000).name")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "chris", res[0].Data.Value)
	})

	t.Run("test group init (name)", func(t *testing.T) {
		res := x.TestQuery(t, "group(name: 'chris').gid")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(1000), res[0].Data.Value)
	})
}

// The recording format, mirrored here so a recording can be built in the test
// rather than checked in. Checking one in would pin the base64 of the collection
// script as a lookup key, and the first edit to the script would leave a
// recording nothing matches.
type iisRecordingResource struct {
	Resource string
	ID       string
	Fields   map[string]*llx.RawData
}

type iisRecordingConnection struct {
	Url        string `json:"url"`
	ProviderID string `json:"provider"`
	Connector  string `json:"connector"`
	Version    string `json:"version"`
}

type iisRecordingAsset struct {
	Asset       *inventory.Asset         `json:"asset"`
	Connections []iisRecordingConnection `json:"connections"`
	Resources   []iisRecordingResource   `json:"resources"`
}

type iisRecording struct {
	Assets []iisRecordingAsset `json:"assets"`
}

// iisMock builds a Windows runtime whose only recorded command is the IIS
// collection script, answering with the given payload. The command key is
// derived from the shipped script, so it stays correct however the script
// changes.
func iisMock(t *testing.T, payload string) llx.Runtime {
	t.Helper()
	return iisMockCommand(t, 0, payload, "")
}

// iisFailingMock answers the collection script the way a host that refuses it
// does: a non-zero exit code and a message on stderr.
func iisFailingMock(t *testing.T, stderr string) llx.Runtime {
	t.Helper()
	return iisMockCommand(t, 1, "", stderr)
}

func iisMockCommand(t *testing.T, exitcode int64, stdout string, stderr string) llx.Runtime {
	t.Helper()

	rec := iisRecording{
		Assets: []iisRecordingAsset{
			{
				Asset: &inventory.Asset{
					Id:          "windows-iis",
					PlatformIds: []string{"windows"},
					Name:        "windows",
					Platform: &inventory.Platform{
						Name:    "windows",
						Arch:    "x86_64",
						Title:   "Windows Server",
						Family:  []string{"windows", "os"},
						Build:   "rolling",
						Version: "2022",
					},
				},
				Connections: []iisRecordingConnection{
					{Url: "local://", ProviderID: "os", Connector: "local"},
				},
				Resources: []iisRecordingResource{
					{
						Resource: "command",
						// The staged command, not powershell.Encode: the script
						// is far too long for a command line and is written to
						// the target as a file. That command *is* the id of the
						// `command` resource, so it is the key a recording is
						// filed under — and it stays derivable here because the
						// path is a client-side literal plus the script's
						// content hash, with nothing read off a host.
						ID: powershell.StagedCommand(
							powershell.StagedWindowsPath("iis", windows.IIS_CONFIGURATION)),
						Fields: map[string]*llx.RawData{
							"exitcode": llx.IntData(exitcode),
							"stdout":   llx.StringData(stdout),
							"stderr":   llx.StringData(stderr),
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(rec)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "iis-recording.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	return testutils.RecordingMock(abs)
}

func iisFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("windows", "testdata", name))
	require.NoError(t, err)
	return string(data)
}

// TestIisResourceOverrides drives the whole resource through MQL. It is the
// counterpart to the parser tests: it proves the schema wires up, the typed
// application pool reference resolves, and the values a policy would read are
// the resolved ones.
//
// It runs on the **hand-authored** payload rather than on the capture, because
// it is about the override case — a site whose configuration disagrees with the
// server's — and no host this suite has captured has one. See the comment on
// iisSynthetic in windows/iis_test.go. TestIisResourceOnCapture below is the
// same wiring driven by a payload a real server produced.
func TestIisResourceOverrides(t *testing.T) {
	runtime := iisMock(t, iisFixture(t, "iis_synthetic.json"))
	tester := testutils.InitTester(runtime)

	tester.TestSimple(t, []testutils.SimpleTest{
		{Code: "iis.installed", ResultIndex: 0, Expectation: true},
		{Code: "iis.version", ResultIndex: 0, Expectation: "10.0"},
		{Code: "iis.sites.length", ResultIndex: 0, Expectation: int64(2)},
		{Code: "iis.appPools.length", ResultIndex: 0, Expectation: int64(2)},

		// The server scope declares directory browsing off. Reading only this
		// would report the site below as compliant.
		{Code: "iis.config.path", ResultIndex: 0, Expectation: "MACHINE/WEBROOT/APPHOST"},
		{Code: "iis.config.directoryBrowsingEnabled", ResultIndex: 0, Expectation: false},

		// The legacy site overrides it, and the resource reports the override.
		{
			Code:        `iis.sites.where(name == "legacy")[0].config.directoryBrowsingEnabled`,
			ResultIndex: 0, Expectation: true,
		},
		{
			Code:        `iis.sites.where(name == "legacy")[0].config.path`,
			ResultIndex: 0, Expectation: "MACHINE/WEBROOT/APPHOST/legacy",
		},
		{
			Code:        `iis.sites.where(name == "legacy")[0].config.machineKeyValidation`,
			ResultIndex: 0, Expectation: "SHA1",
		},
		{
			Code:        `iis.sites.where(name == "legacy")[0].config.sessionStateTimeout`,
			ResultIndex: 0, Expectation: int64(3600),
		},
		{
			Code:        `iis.sites.where(name == "Default Web Site")[0].config.machineKeyValidation`,
			ResultIndex: 0, Expectation: "HMACSHA256",
		},

		// A section this payload does not declare reads null, not false. Note
		// what is *not* being claimed: a real server does declare these at
		// server scope, and TestIisResourceOnCapture reads values for them.
		// This payload omits them, and the point is only that an absent section
		// yields null rather than a made-up zero value.
		{Code: "iis.config.compilationDebug", ResultIndex: 0, Expectation: nil},
		{Code: "iis.config.sessionStateMode", ResultIndex: 0, Expectation: nil},

		// The typed application pool reference resolves to the pool itself.
		{
			Code:        `iis.sites.where(name == "legacy")[0].appPool.identityType`,
			ResultIndex: 0, Expectation: "SpecificUser",
		},
		{
			Code:        `iis.sites.where(name == "Default Web Site")[0].appPool.identityType`,
			ResultIndex: 0, Expectation: "ApplicationPoolIdentity",
		},
		{
			Code:        `iis.appPools.where(name == "LegacyPool")[0].idleTimeout`,
			ResultIndex: 0, Expectation: int64(0),
		},

		// An application resolves at its own scope, below the site's.
		{
			Code:        `iis.sites.where(name == "legacy")[0].applications.where(path == "/shop")[0].config.sessionStateTimeout`,
			ResultIndex: 0, Expectation: int64(900),
		},
		{
			Code:        `iis.sites.where(name == "legacy")[0].applications.where(path == "/shop")[0].config.path`,
			ResultIndex: 0, Expectation: "MACHINE/WEBROOT/APPHOST/legacy/shop",
		},
		// The root application shares the site's scope, so it reports the site's
		// value rather than resolving a second time.
		{
			Code:        `iis.sites.where(name == "legacy")[0].applications.where(path == "/")[0].config.sessionStateTimeout`,
			ResultIndex: 0, Expectation: int64(3600),
		},

		{
			Code:        `iis.sites.where(name == "legacy")[0].bindings.where(protocol == "https")[0].port`,
			ResultIndex: 0, Expectation: int64(443),
		},
		{
			Code:        `iis.sites.where(name == "legacy")[0].config.customHeaders["X-Powered-By"]`,
			ResultIndex: 0, Expectation: "ASP.NET",
		},
		// Every application declares a virtual directory at "/", so the ids have
		// to carry the site and the application as well as the path. If they did
		// not, the second one would resolve to the cached first and report its
		// physical path.
		{
			Code:        `iis.sites.where(name == "legacy")[0].applications.where(path == "/")[0].virtualDirectories[0].physicalPath`,
			ResultIndex: 0, Expectation: `D:\sites\legacy`,
		},
		{
			Code:        `iis.sites.where(name == "legacy")[0].applications.where(path == "/shop")[0].virtualDirectories[0].physicalPath`,
			ResultIndex: 0, Expectation: `D:\sites\legacy\shop`,
		},
		{
			Code:        `iis.sites.where(name == "Default Web Site")[0].applications[0].virtualDirectories[0].path`,
			ResultIndex: 0, Expectation: "/",
		},

		// The escape hatch reaches a section with no field of its own.
		{
			Code:        `iis.config.sections["system.webServer/security/requestFiltering"]["requestLimits"]["maxUrl"]`,
			ResultIndex: 0, Expectation: float64(4096),
		},
	})
}

// TestIisConfigurationSectionsReachEverySetting exercises the escape hatch on
// settings deliberately left without a field of their own, because a field that
// is only a second name for a value already in `sections` is API we would have
// to keep. These paths are the documented alternative, so they are tested rather
// than assumed: the verbs filter, which shares its attribute name with the file
// extension filter that does have a field, and the machine key cipher, which
// sits beside the validation algorithm that does.
func TestIisConfigurationSectionsReachEverySetting(t *testing.T) {
	runtime := iisMock(t, iisFixture(t, "iis_synthetic.json"))
	tester := testutils.InitTester(runtime)

	tester.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        `iis.config.sections["system.webServer/security/requestFiltering"]["verbs"]["allowUnlisted"]`,
			ResultIndex: 0, Expectation: true,
		},
		{
			Code:        `iis.config.sections["system.webServer/security/requestFiltering"]["fileExtensions"]["allowUnlisted"]`,
			ResultIndex: 0, Expectation: true,
		},
		{
			Code:        `iis.sites.where(name == "legacy")[0].config.sections["system.web/machineKey"]["decryption"]`,
			ResultIndex: 0, Expectation: "Auto",
		},

		// A section the payload does not declare has no key, and reading
		// through the missing key yields null instead of failing the whole
		// query. That is what makes the escape hatch usable against a scope
		// that genuinely declares less than another one.
		{Code: `iis.config.sections["system.web/machineKey"]`, ResultIndex: 0, Expectation: nil},
		{Code: `iis.config.sections["system.web/machineKey"]["decryption"]`, ResultIndex: 0, Expectation: nil},

		// Key material is dropped during collection, so it is in neither a field
		// nor the raw section.
		{
			Code:        `iis.sites.where(name == "legacy")[0].config.sections["system.web/machineKey"]["validationKey"]`,
			ResultIndex: 0, Expectation: nil,
		},
	})
}

// TestIisCollectFailurePropagates covers the failure mode the shared collection
// creates. Every field below iis comes out of one script run, but the fields do
// not share a cache entry, so an error handed only to whichever field ran first
// would leave the rest reading an empty result — reporting a host that refused
// the collection as a host that simply does not run IIS, on which every check
// passes. The second and later accessors are the case that matters here.

// TestIisResourceOnCapture drives the resource through MQL on a payload a real
// Windows Server 2022 produced, in its non-hardened state. Its point is the
// enum-valued fields: every one of them used to reach a policy as a bare number
// formatted as a string, which is a value that looks usable and is not.
func TestIisResourceOnCapture(t *testing.T) {
	runtime := iisMock(t, iisFixture(t, "iis.json"))
	tester := testutils.InitTester(runtime)

	tester.TestSimple(t, []testutils.SimpleTest{
		{Code: "iis.installed", ResultIndex: 0, Expectation: true},
		{Code: "iis.version", ResultIndex: 0, Expectation: "10.0"},
		{Code: "iis.sites.length", ResultIndex: 0, Expectation: int64(2)},
		{Code: "iis.appPools.length", ResultIndex: 0, Expectation: int64(2)},

		// A flags attribute: 519 is Read|Write|Execute|Script, which is not a
		// member of its own enum and cannot be resolved by a lookup.
		{Code: "iis.config.handlerAccessPolicy", ResultIndex: 0, Expectation: "Read, Write, Execute, Script"},

		// Plain enums, all of which are Int32 in the payload the API hands over.
		{Code: "iis.config.authenticationMode", ResultIndex: 0, Expectation: "None"},
		{Code: "iis.config.sessionStateMode", ResultIndex: 0, Expectation: "StateServer"},
		{Code: "iis.config.sessionStateCookieless", ResultIndex: 0, Expectation: "UseUri"},
		{Code: "iis.config.machineKeyValidation", ResultIndex: 0, Expectation: "MD5"},
		{Code: "iis.config.customErrorsMode", ResultIndex: 0, Expectation: "Off"},
		{Code: "iis.config.httpErrorsMode", ResultIndex: 0, Expectation: "Detailed"},
		{Code: "iis.config.formsProtection", ResultIndex: 0, Expectation: "None"},

		// The ASP.NET sections read at server scope. The schema used to
		// document them as null here and the tests used to assert it.
		{Code: "iis.config.compilationDebug", ResultIndex: 0, Expectation: true},
		{Code: "iis.config.trustLevel", ResultIndex: 0, Expectation: "Full"},
		{Code: `iis.config.sections["system.web/machineKey"]["decryption"]`, ResultIndex: 0, Expectation: "Auto"},

		// Key material is dropped during collection, so it reaches neither a
		// typed field nor the raw section — on a real payload, not only on one
		// written to omit it.
		{Code: `iis.config.sections["system.web/machineKey"]["validationKey"]`, ResultIndex: 0, Expectation: nil},
		{Code: `iis.config.sections["system.web/machineKey"]["decryptionKey"]`, ResultIndex: 0, Expectation: nil},

		// A site's log format, as everything that names a log format spells it.
		{
			Code:        `iis.sites.where(name == "Default Web Site")[0].logFormat`,
			ResultIndex: 0, Expectation: "NCSA",
		},
		// The one scope in this capture that actually overrides its parent.
		{
			Code:        `iis.sites.where(name == "fixture-b")[0].applications.where(path == "/app1")[0].config.sessionStateTimeout`,
			ResultIndex: 0, Expectation: int64(3600),
		},
		{
			Code:        `iis.sites.where(name == "fixture-b")[0].config.sessionStateTimeout`,
			ResultIndex: 0, Expectation: int64(7200),
		},
	})
}

func TestIisCollectFailurePropagates(t *testing.T) {
	runtime := iisFailingMock(t, "access is denied")
	tester := testutils.InitTester(runtime)

	const expected = "failed to read IIS configuration: access is denied"

	// The first field to ask runs the collection and sees the failure.
	tester.TestSimpleErrors(t, []testutils.SimpleTest{
		{Code: "iis.installed", ResultIndex: 0, Expectation: expected},
	})

	// Every later field reaches the cached outcome and must see the same
	// failure. Reporting false, "" or an empty list here would be the silent
	// pass this test exists to prevent.
	tester.TestSimpleErrors(t, []testutils.SimpleTest{
		{Code: "iis.installed", ResultIndex: 0, Expectation: expected},
		{Code: "iis.version", ResultIndex: 0, Expectation: expected},
		{Code: "iis.config", ResultIndex: 0, Expectation: expected},
		{Code: "iis.applicationHost", ResultIndex: 0, Expectation: expected},
		{Code: "iis.sites", ResultIndex: 0, Expectation: expected},
		{Code: "iis.appPools", ResultIndex: 0, Expectation: expected},
	})
}

// TestIisResourceAbsent is the case the skill calls out: on a host that does not
// run IIS the resource must answer, and it must not answer in a way that makes a
// check pass. installed is false and the collections are empty, so a policy has
// to filter on installed rather than iterate.
func TestIisResourceAbsent(t *testing.T) {
	runtime := iisMock(t, iisFixture(t, "iis_not_installed.json"))
	tester := testutils.InitTester(runtime)

	tester.TestSimple(t, []testutils.SimpleTest{
		{Code: "iis.installed", ResultIndex: 0, Expectation: false},
		{Code: "iis.version", ResultIndex: 0, Expectation: ""},
		{Code: "iis.sites.length", ResultIndex: 0, Expectation: int64(0)},
		{Code: "iis.appPools.length", ResultIndex: 0, Expectation: int64(0)},
		// Null rather than an empty configuration whose every field reads false.
		{Code: "iis.config", ResultIndex: 0, Expectation: nil},
		{Code: "iis.applicationHost", ResultIndex: 0, Expectation: nil},
	})
}

// jbossCompilerConfig builds a compiler bound to the same schema a scan uses,
// so a checksum computed here is the one a score would be keyed by.
func jbossCompilerConfig() mqlc.CompilerConfig {
	core := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "core"})
	os := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "os"})
	return mqlc.NewConfig(core.Add(os), mql.Features{byte(mql.ResourceContext)})
}

// TestJbossAuditLogPartsAreIndependentlyAssertable is the regression for the
// reason the audit log is modeled attribute by attribute rather than as one
// "auditing is on" boolean.
//
// A score is keyed by the checksum of the compiled query, and the name a
// variable is given is not part of that checksum — only the shape of the
// expression is. Two checks whose bodies compile identically therefore resolve
// to a single score, and the one written first disappears from the report with
// no error.
//
// Hardening guidance for this server states more than a dozen separate
// requirements — that the event type is recorded, that boot-time operations
// are covered, that reads are covered, that the record carries a timestamp,
// that it lands somewhere durable, that it is shipped off the host — and every
// one of them hangs off the same switch. If the switch were all this resource
// exposed, those checks could only be written one way, and all but one of them
// would vanish. Each has to be able to assert the switch *and* the part of the
// block its own evidence depends on, which is what the fields below exist for.
func TestJbossAuditLogPartsAreIndependentlyAssertable(t *testing.T) {
	conf := jbossCompilerConfig()

	// Each entry asserts the switch plus one further condition that a distinct
	// requirement genuinely depends on. None of them can pass while auditing is
	// off, and no two of them are the same assertion.
	queries := []string{
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.where(type == "file").length > 0`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.logger.logBoot == true`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.logger.logReadOnly == true`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.logger.handlers.length > 0`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.formatters.length > 0`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.formatters.all(includeDate == true)`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.formatters.all(compact == false)`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.formatters.all(escapeControlCharacters == true)`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.formatters.all(name != "")`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.all(name != "")`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.all(formatter != "")`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.where(type == "file").all(path != "")`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.where(type == "file").all(relativeTo != "")`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.where(type == "file").all(rotateAtStartup == false)`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.all(maxFailureCount > 0)`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.where(type == "syslog").length > 0`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.handlers.where(type == "syslog").all(transport == "tcp")`,
		`jboss.management.auditLog.enabled == true
		 jboss.management.auditLog.serverLogger.logReadOnly == true`,
	}

	checksums := map[string]int{}
	for i, query := range queries {
		bundle, err := mqlc.Compile(query, nil, conf)
		require.NoError(t, err, "query %d", i)
		require.NotNil(t, bundle)
		checksums[bundle.CodeV2.Id]++
	}

	duplicates := []string{}
	for checksum, count := range checksums {
		if count > 1 {
			duplicates = append(duplicates, checksum)
		}
	}

	assert.Empty(t, duplicates,
		"two of these compile to the same code and would collapse into one score")
	assert.Len(t, checksums, len(queries))
}

// Renaming a variable does not change the compiled code, which is why the
// distinctness above has to come from the assertions themselves rather than
// from how they are written.
func TestJbossVariableNamesDoNotChangeTheChecksum(t *testing.T) {
	conf := jbossCompilerConfig()

	first, err := mqlc.Compile(
		"auditLog = jboss.management.auditLog\nauditLog.enabled == true", nil, conf)
	require.NoError(t, err)

	second, err := mqlc.Compile(
		"log = jboss.management.auditLog\nlog.enabled == true", nil, conf)
	require.NoError(t, err)

	assert.Equal(t, first.CodeV2.Id, second.CodeV2.Id,
		"the variable name is not part of the checksum")
}

func TestResource_JournaldConfig(t *testing.T) {
	x.TestSimpleErrors(t, []testutils.SimpleTest{
		{
			Code:        "journald.config('nopath').sections",
			ResultIndex: 0,
			Expectation: "file 'nopath' not found",
		},
	})

	t.Run("journald file path", func(t *testing.T) {
		res := x.TestQuery(t, "journald.config.file.path")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
	})

	t.Run("backwards compatibility: journald is downcasing relevant params", func(t *testing.T) {
		res := x.TestQuery(t, "journald.config.params.Compress")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, "yes", res[0].Data.Value)
	})

	t.Run("journald is downcasing relevant params", func(t *testing.T) {
		res := x.TestQuery(t, "journald.config.sections.where(name == 'Journal')[0].params.where(name == 'Compress')[0].value")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, "yes", res[0].Data.Value)
	})

	t.Run("backwards compatibility: journald is NOT downcasing other params", func(t *testing.T) {
		res := x.TestQuery(t, "journald.config.params.Storage")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, "persistent", res[0].Data.Value)
	})

	t.Run("journald is NOT downcasing other params", func(t *testing.T) {
		res := x.TestQuery(t, "journald.config.sections.where(name == 'Journal')[0].params.where(name == 'Storage')[0].value")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, "persistent", res[0].Data.Value)
	})
}

func TestResource_KernelParameters(t *testing.T) {

	t.Run("test a specific kernel parameters", func(t *testing.T) {
		res := x.TestQuery(t, `kernel.parameters["net.ipv4.ip_forward"]`)
		assert.NotEmpty(t, res)

		assert.Equal(t, "1", res[0].Data.Value)
	})
}

func TestResource_KernelModules(t *testing.T) {

	t.Run("grab a kernel module", func(t *testing.T) {
		res := x.TestQuery(t, "kernel.modules[0].name")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "xfrm_user", res[0].Data.Value)
	})

	t.Run("grab a kernel module by name", func(t *testing.T) {
		res := x.TestQuery(t, "kernel.module('xfrm_user').size")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "36864", res[0].Data.Value)
	})
}

func TestResource_K8sKubelet(t *testing.T) {
	x := testutils.InitTester(testutils.KubeletMock())

	t.Run("kubelet configFile path", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configFile.path")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
	})

	t.Run("kubelet process executable", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.process.executable")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, "/var/lib/minikube/binaries/v1.28.3/kubelet", res[0].Data.Value)
	})

	t.Run("kubelet config file flag", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"config\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "/var/lib/kubelet/config.yaml", res[0].Data.Value)
	})

	t.Run("check for default value", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"volumePluginDir\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/", res[0].Data.Value)
	})

	t.Run("check for config file param", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"healthzBindAddress\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "127.0.0.1", res[0].Data.Value)
	})

	t.Run("check for cli flag overwrite", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.process.flags[\"runtime-request-timeout\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "7m", res[0].Data.Value)

		res = x.TestQuery(t, "kubelet.configFile.content")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Contains(t, res[0].Data.Value, "runtimeRequestTimeout: 15m0s")

		res = x.TestQuery(t, "kubelet.configuration[\"runtimeRequestTimeout\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "7m", res[0].Data.Value)
	})

	t.Run("kubelet config clientCAFile", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"authentication\"][\"x509\"][\"clientCAFile\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Contains(t, "/var/lib/minikube/certs/ca.crt", res[0].Data.Value)
	})

	t.Run("typed anonymousAuthEnabled", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.anonymousAuthEnabled")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, false, res[0].Data.Value)
	})

	t.Run("typed authorizationMode", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.authorizationMode")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Webhook", res[0].Data.Value)
	})

	t.Run("typed clientCAFile", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.clientCAFile")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "/var/lib/minikube/certs/ca.crt", res[0].Data.Value)
	})

	t.Run("typed makeIPTablesUtilChains default", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.makeIPTablesUtilChains")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})

	t.Run("typed eventRecordQPS default", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.eventRecordQPS")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(50), res[0].Data.Value)
	})
}

func TestResource_K8sKubeletAKS(t *testing.T) {
	// AKS is special in that regard, that it does not have a kubelet config file
	// everything is configured via the kubelet process flags
	x := testutils.InitTester(testutils.KubeletAKSMock())

	t.Run("kubelet configFile path", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configFile")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
	})

	t.Run("kubelet configFile exists", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configFile.exists")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.False(t, res[0].Data.Value.(bool))
	})

	t.Run("kubelet process executable", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.process.executable")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, "/var/lib/minikube/binaries/v1.28.3/kubelet", res[0].Data.Value)
	})

	t.Run("kubelet config file flag", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"config\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, nil, res[0].Data.Value)
	})

	t.Run("kubelet flag anonymous-auth", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"authentication\"][\"anonymous\"][\"enabled\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "false", res[0].Data.Value)
	})

	t.Run("kubelet flag tls-cipher-suites", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"tlsCipherSuites\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, 8, len(res[0].Data.Value.([]any)))
		assert.Contains(t, res[0].Data.Value.([]any), "TLS_RSA_WITH_AES_128_GCM_SHA256")
	})

	t.Run("kubelet flag eviction-hard", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"evictionHard\"][\"memory.available\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "750Mi", res[0].Data.Value)
	})

	t.Run("check for cli flag overwrite", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.process.flags[\"read-only-port\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "0", res[0].Data.Value)

		// default is 10250
		res = x.TestQuery(t, "kubelet.configuration[\"readOnlyPort\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "0", res[0].Data.Value)
	})

	t.Run("typed readOnlyPort coerces string flag", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.readOnlyPort")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(0), res[0].Data.Value)
	})

	t.Run("typed tlsCipherSuites", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.tlsCipherSuites")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, 8, len(res[0].Data.Value.([]any)))
		assert.Contains(t, res[0].Data.Value.([]any), "TLS_RSA_WITH_AES_128_GCM_SHA256")
	})

	t.Run("typed anonymousAuthEnabled from flag", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.anonymousAuthEnabled")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, false, res[0].Data.Value)
	})
}

func TestResource_K8sKubeletEKS(t *testing.T) {
	// EKS is different because it uses a JSON config file
	// and set's the read-only-port to 0
	x := testutils.InitTester(testutils.KubeletEKSMock())

	t.Run("kubelet configFile path", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configFile")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
	})

	t.Run("kubelet config readOnlyPort", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.configuration[\"readOnlyPort\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, 0.0, res[0].Data.Value)
	})

	t.Run("typed readOnlyPort coerces float config", func(t *testing.T) {
		res := x.TestQuery(t, "kubelet.readOnlyPort")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(0), res[0].Data.Value)
	})
}

func TestResource_LoginDefs(t *testing.T) {

	t.Run("specific logindefs param", func(t *testing.T) {
		res := x.TestQuery(t, "logindefs.params[\"UID_MIN\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "1000", res[0].Data.Value)
	})
}

func TestResource_Mount(t *testing.T) {

	t.Run("check first mount entry", func(t *testing.T) {
		res := x.TestQuery(t, "mount.list[0].device")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "proc", res[0].Data.Value)
	})

	t.Run("search for mountpoint on root /", func(t *testing.T) {
		res := x.TestQuery(t, "mount.where(path == \"/\").list[0].device")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "/dev/sda1", res[0].Data.Value)
	})

	t.Run("check mount point resource", func(t *testing.T) {
		res := x.TestQuery(t, "mount.point(\"/dev\").mounted")
		assert.NotEmpty(t, res)
		assert.Equal(t, true, res[0].Data.Value)

		res = x.TestQuery(t, "mount.point(\"/notthere\").mounted")
		assert.NotEmpty(t, res)
		assert.Equal(t, false, res[0].Data.Value)
	})

	t.Run("mount point size from df", func(t *testing.T) {
		res := x.TestQuery(t, "mount.point(\"/\").size")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		// 51340776 KB * 1024
		assert.Equal(t, int64(51340776*1024), res[0].Data.Value)
	})

	t.Run("mount point used from df", func(t *testing.T) {
		res := x.TestQuery(t, "mount.point(\"/\").used")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		// 12165612 KB * 1024
		assert.Equal(t, int64(12165612*1024), res[0].Data.Value)
	})

	t.Run("mount point available from df", func(t *testing.T) {
		res := x.TestQuery(t, "mount.point(\"/\").available")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		// 36537668 KB * 1024
		assert.Equal(t, int64(36537668*1024), res[0].Data.Value)
	})

	t.Run("mount point size is null for unmounted path", func(t *testing.T) {
		res := x.TestQuery(t, "mount.point(\"/notthere\").size")
		assert.NotEmpty(t, res)
		assert.Nil(t, res[0].Data.Value)
	})
}

func TestResource_OSRootCertificates(t *testing.T) {
	t.Run("list root certificates", func(t *testing.T) {
		res := x.TestQuery(t, "os.rootCertificates().length")
		assert.NotEmpty(t, res)
		assert.Equal(t, int64(1), res[0].Data.Value.(int64))
	})
}

func TestResource_Package(t *testing.T) {
	t.Run("existing package", func(t *testing.T) {
		res := x.TestQuery(t, "package(\"acl\").installed")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})

	t.Run("missing package", func(t *testing.T) {
		res := x.TestQuery(t, "package(\"unknown\").installed")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, false, res[0].Data.Value)
	})
}

func TestResource_Pam(t *testing.T) {
	t.Run("with missing files", func(t *testing.T) {
		res := x.TestQuery(t, "pam.conf.content")
		assert.NotEmpty(t, res)
		assert.Error(t, res[0].Data.Error, "returned an error")
	})

	t.Run("exists is false without erroring when files are missing", func(t *testing.T) {
		res := x.TestQuery(t, "pam.conf.exists")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
		assert.Equal(t, false, res[0].Data.Value)
	})
}

// Example use for certificate parser:
// parse.certificates('/etc/ssl/cert.pem').list {
// 		fingerprints
// 		serial
// 		subjectKeyID
// 		authorityKeyID
// 		isCA
// 		version
// 		keyUsage
// 		extendedKeyUsage
// 		crlDistributionPoints
// 		ocspServer
// 		issuingCertificateUrl
// 		issuer { serialNumber commonName }
// 		subject {serialNumber commonName}
// 		policyidentifier
// 		extensions { identifier }
// }

func TestResource_ParseCertificates(t *testing.T) {
	t.Run("view authorized keys file", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').content")
		require.NotEmpty(t, res)
		assert.Equal(t, 1207, len(res[0].Data.Value.(string)))
	})

	t.Run("test certificate serial", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].serial")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "06:6c:9f:cf:99:bf:8c:0a:39:e2:f0:78:8a:43:e6:96:36:5b:ca", res[0].Data.Value)
	})

	t.Run("test certificate issuer commonname", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].issuer.commonName")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Amazon Root CA 1", res[0].Data.Value)
	})

	t.Run("test certificate issuer dn", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].issuer.dn")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "CN=Amazon Root CA 1,O=Amazon,C=US", res[0].Data.Value)
	})

	t.Run("test certificate subjectkeyid", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].subjectKeyID")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "84:18:cc:85:34:ec:bc:0c:94:94:2e:08:59:9c:c7:b2:10:4e:0a:08", res[0].Data.Value)
	})

	t.Run("test certificate authoritykeyid", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].authorityKeyID")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "", res[0].Data.Value)
	})

	t.Run("test certificate version", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].version")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(3), res[0].Data.Value)
	})

	t.Run("test certificate isca", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].isCA")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})

	t.Run("test certificate keyusage", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].keyUsage")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		list := res[0].Data.Value.([]any)
		assert.Contains(t, list, "CRLSign")
		assert.Contains(t, list, "DigitalSignature")
		assert.Contains(t, list, "CertificateSign")
	})

	t.Run("test certificate extendedkeyusage", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].extendedKeyUsage")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{}, res[0].Data.Value)
	})

	t.Run("test certificate crldistributionpoints", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].crlDistributionPoints")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{}, res[0].Data.Value)
	})

	t.Run("test certificate ocspserver", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].ocspServer")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{}, res[0].Data.Value)
	})

	t.Run("test certificate issuingcertificateurl", func(t *testing.T) {
		res := x.TestQuery(t, "parse.certificates('/etc/ssl/cert.pem').list[0].issuingCertificateUrl")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{}, res[0].Data.Value)
	})

	t.Run("test certificate loading from content", func(t *testing.T) {
		cert := `-----BEGIN CERTIFICATE-----
MIIFWDCCBECgAwIBAgIQaMJ5PP8vl9sQAAAAAAEvHjANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFENDAeFw0yMjAyMDYwOTI3MzJaFw0yMjA1MDcw
OTI3MzFaMBUxEzARBgNVBAMTCm1vbmRvby5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC4oVPC4ORJlZt/FEfrJ4g8gCBPKW0m9rH/e4J78jZTrsye
7w7tXFY7ZeHGQizEsJtfpsipwsldTOoCygDKWI/7xnx9AKe79wRfZecijV11s5MN
TfSlNSgaKZ5DAha8oVszAmPDxD6dDWqMPGL0XHw86aaBimnrh48930qBFwoKyf5I
cWCz77McF0PYNk57VDMB7BVIlthEvVmrSp9zloHOa78LoiexPOTHQSjAZTvnUiMn
EMRL3J9ZFYyshw56oE9hR3getBvlpwOKpS+5MSorOI5/ZSApn6ZF8c0F5IJVlTNR
T3ffKYz02Y4Rz348cgZkpo8t8Gp5/5OYoxjBRm81AgMBAAGjggJxMIICbTAOBgNV
HQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAd
BgNVHQ4EFgQU5TBHEo55zzpw6/s3QckdsaprbtYwHwYDVR0jBBgwFoAUJeIYDrJX
kZQq5dRdhpCD3lOzuJIweAYIKwYBBQUHAQEEbDBqMDUGCCsGAQUFBzABhilodHRw
Oi8vb2NzcC5wa2kuZ29vZy9zL2d0czFkNC9za0xzTXRrWUpUczAxBggrBgEFBQcw
AoYlaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzMWQ0LmRlcjAVBgNVHREE
DjAMggptb25kb28uY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkC
BQMwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybHMucGtpLmdvb2cvZ3RzMWQ0
L0VVQzBtUTR5TVBjLmNybDCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AFGjsPX9
AXmcVm24N3iPDKR6zBsny/eeiEKaDf7UiwXlAAABfs6aMmoAAAQDAEcwRQIhAMy2
aufiYVITPFDElL1aWVMTo0rBEmQ520rXbTcfzI4JAiAawIFvNix2Vp3Ybuk7doHp
q/sICyNRt+Zrz/wNNfziegB2AEalVet1+pEgMLWiiWn0830RLEF0vv1JuIWr8vxw
/m1HAAABfs6aMoMAAAQDAEcwRQIhAJXJReJyMJskegnWDmfq0ovGZ90A7c9lYebj
7jfJyGGlAiABVuFTV0/jxdAV5XNOyUxN3Y3qhdeSfVM/82qPTub26zANBgkqhkiG
9w0BAQsFAAOCAQEAagCxD1/ctRgSA96MLhIKAey6CHmkECgGb4B+liuO1PwG+Ft9
x4KigQjZ193+z7aSb6CSxIEzUyDfGTMqmER1MOmN5wJhzw7pnZ0VXDLePcTJPqtA
q5uRwWdrXRKsoXPbizcs25btZNgcswHLOzNYxCT5Qf9pprxTcMoIlROFF6WT0wxq
pmYrmQ+eJ9Ny8Fi6ovMWlUch4qg3bcj6QQ0FZ3zPX/6kI9FXGvJ+4rL/WE3Ouc+b
XjazfGmfrd3uVevgxgkfeMsKtKgHCpr7f0qpqgko9F5De68JZg+lV/ganyOxKi5M
ym+AS505m2l07i2SYbM82nyP74qYD3b3QmrZSQ==
-----END CERTIFICATE-----`

		res := x.TestQuery(t, "parse.certificates(content: '"+cert+"').list[0].issuer.commonName")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "GTS CA 1D4", res[0].Data.Value)
	})
}

func TestParsePlist(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "parse.plist('/dummy.plist').params['allowdownloadsignedenabled']",
			ResultIndex: 0,
			// validates that the output is not uint64
			Expectation: float64(1),
		},
	})
}

// Regression for profile-managed macOS checks: a managed-preferences plist keys
// its settings by preference domain, and the domain contains dots. Reading one
// with dot notation used to walk "com", find nothing, and hand back null - so
// the branch of every such CIS check that inspects the MDM evidence could never
// evaluate true, however correctly the profile was deployed.
func TestDictDottedKeyAccessors(t *testing.T) {
	// Shaped like /Library/Managed Preferences/<user>/complete.plist, including
	// the two traps it really contains: a domain that is a prefix of a sibling
	// domain, and a domain whose own keys are dotted.
	const doc = `{` +
		`"com.apple.security.firewall": {"EnableFirewall": {"value": true}},` +
		`"com.apple.MCX": {"com.apple.EnergySaver.desktop.ACPower": {"value": "on"}},` +
		`"com.apple.MCX.FileVault2": {"Enable": {"value": "On"}},` +
		`"plain": {"nested": {"leaf": 7}}` +
		`}`
	parse := "parse.json(content: '" + doc + "').params"

	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        parse + ".com.apple.security.firewall.EnableFirewall.value",
			ResultIndex: 0,
			Expectation: true,
		},
		{
			// Resolves only by abandoning the shorter "com.apple.MCX" match.
			Code:        parse + ".com.apple.MCX.FileVault2.Enable.value",
			ResultIndex: 0,
			Expectation: "On",
		},
		{
			// A dotted key nested inside a dotted domain.
			Code:        parse + ".com.apple.MCX.com.apple.EnergySaver.desktop.ACPower.value",
			ResultIndex: 0,
			Expectation: "on",
		},
		{
			// Undotted keys keep resolving exactly as they did before.
			Code:        parse + ".plain.nested.leaf",
			ResultIndex: 0,
			Expectation: float64(7),
		},
		{
			// A setting the document does not carry is still absent.
			Code:        parse + ".com.apple.MCX.DisableGuestAccount.value",
			ResultIndex: 0,
			Expectation: nil,
		},
		{
			// Bracket notation, the form shipping content already uses, is
			// unchanged.
			Code:        parse + `["com.apple.security.firewall"]["EnableFirewall"]["value"]`,
			ResultIndex: 0,
			Expectation: true,
		},
	})
}

func TestParseJson(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "parse.json(content: '{\"a\": 1}').params",
			ResultIndex: 0,
			Expectation: map[string]any{"a": float64(1)},
		},
		{
			Code:        "parse.json(content: '[{\"a\": 1}]').params[0]",
			ResultIndex: 0,
			Expectation: map[string]any{"a": float64(1)},
		},
	})
}

func TestParseIniMissingFile(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        `parse.ini("/etc/security/pwquality.conf").content`,
			ResultIndex: 0,
			Expectation: "",
		},
		{
			Code:        `parse.ini("/etc/security/pwquality.conf").sections`,
			ResultIndex: 0,
			Expectation: map[string]any{},
		},
		{
			Code:        `parse.ini("/etc/security/pwquality.conf").params`,
			ResultIndex: 0,
			Expectation: map[string]any{},
		},
		{
			Code:        `parse.ini("/etc/audit/does-not-exist.conf").params`,
			ResultIndex: 0,
			Expectation: map[string]any{},
		},
	})
}

func TestParseXML(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "parse.xml(content: '<root />').params",
			ResultIndex: 0,
			Expectation: map[string]any{"root": map[string]any{}},
		},
		{
			Code:        "parse.xml(content: '<root>\n\t\t\n</root>').params",
			ResultIndex: 0,
			Expectation: map[string]any{"root": map[string]any{}},
		},
		{
			Code:        "parse.xml(content: '<root>\n\tworld\n</root>').params",
			ResultIndex: 0,
			Expectation: map[string]any{"root": "world"},
		},
		{
			Code:        "parse.xml(content: '<root>\n\tworld\n\twide\n</root>').params",
			ResultIndex: 0,
			Expectation: map[string]any{"root": "world\n\twide"},
		},
		{
			Code:        "parse.xml(content: '<root><box /></root>').params",
			ResultIndex: 0,
			Expectation: map[string]any{"root": map[string]any{"box": map[string]any{}}},
		},
		{
			Code:        "parse.xml(content: '<root><box>world</box></root>').params",
			ResultIndex: 0,
			Expectation: map[string]any{"root": map[string]any{"box": "world"}},
		},
		{
			Code:        "parse.xml(content: '<root><box>hello</box><box>world</box></root>').params",
			ResultIndex: 0,
			Expectation: map[string]any{"root": map[string]any{"box": []any{
				"hello",
				"world",
			}}},
		},
		{
			Code:        "parse.xml(content: '<root><box><hello a=\"1\"/></box><box><world b=\"2\">1<c>3</c>4</world></box><box>🌎</box></root>').params",
			ResultIndex: 0,
			Expectation: map[string]any{"root": map[string]any{"box": []any{
				map[string]any{"hello": map[string]any{"@a": "1"}},
				map[string]any{"world": map[string]any{
					"@b":     "2",
					"c":      "3",
					"__text": "1\n4",
				}},
				"🌎",
			}}},
		},
	})
}

func TestParseYamlParams(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        `parse.yaml(content: "simple: test").params`,
			ResultIndex: 0,
			Expectation: map[string]any{
				"simple": "test",
			},
		},
		{
			Code:        `parse.yaml(content: "number: 42").params`,
			ResultIndex: 0,
			Expectation: map[string]any{
				"number": float64(42),
			},
		},
		{
			Code:        `parse.yaml(content: "enabled: true").params`,
			ResultIndex: 0,
			Expectation: map[string]any{
				"enabled": true,
			},
		},
		{
			Code:        `parse.yaml(content: "parent:\n  child: value").params`,
			ResultIndex: 0,
			Expectation: map[string]any{
				"parent": map[string]any{
					"child": "value",
				},
			},
		},
		{
			Code:        `parse.yaml(content: "").params`,
			ResultIndex: 0,
			Expectation: map[string]any{},
		},
		{
			Code:        `parse.yaml(content: "---\nname: single-doc\nversion: 1.2").params`,
			ResultIndex: 0,
			Expectation: map[string]any{
				"name":    "single-doc",
				"version": float64(1.2),
			},
		},
		{
			Code:        `parse.yaml(content: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\ndata:\n  key1: value1\n  key2: value2").params`,
			ResultIndex: 0,
			Expectation: map[string]any{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata": map[string]any{
					"name": "test",
				},
				"data": map[string]any{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
		{
			Code:        `parse.yaml(content: "items:\n  - name: item1\n  - name: item2").params`,
			ResultIndex: 0,
			Expectation: map[string]any{
				"items": []any{
					map[string]any{"name": "item1"},
					map[string]any{"name": "item2"},
				},
			},
		},
		{
			Code:        `parse.yaml(content: "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod\nspec:\n  containers:\n  - name: test\n    image: nginx").params`,
			ResultIndex: 0,
			Expectation: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name": "test-pod",
				},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "test",
							"image": "nginx",
						},
					},
				},
			},
		},
	})
}

func TestParseYamlDocuments(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        `parse.yaml(content: "").documents`,
			ResultIndex: 0,
			Expectation: []any{},
		},
		{
			Code:        `parse.yaml(content: "simple: test").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{
					"simple": "test",
				},
			},
		},
		{
			Code:        `parse.yaml(content: "---\nname: single-doc\nversion: 1.2").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{
					"name":    "single-doc",
					"version": float64(1.2),
				},
			},
		},
		{
			Code:        `parse.yaml(content: "name: trailing-doc\nversion: 1.2\n---").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{
					"name":    "trailing-doc",
					"version": float64(1.2),
				},
			},
		},
		{
			Code:        `parse.yaml(content: "---\nname: wrapped-doc\nversion: 1.2\n---").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{
					"name":    "wrapped-doc",
					"version": float64(1.2),
				},
			},
		},
		{
			Code:        `parse.yaml(content: "name: doc1\n---\nname: doc2").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{"name": "doc1"},
				map[string]any{"name": "doc2"},
			},
		},
		{
			Code:        `parse.yaml(content: "---\nname: doc1\n---\nname: doc2").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{"name": "doc1"},
				map[string]any{"name": "doc2"},
			},
		},
		{
			Code:        `parse.yaml(content: "name: doc1\n---\nname: doc2\n---").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{"name": "doc1"},
				map[string]any{"name": "doc2"},
			},
		},
		{
			Code:        `parse.yaml(content: "name: doc1\n---\nname: doc2\n---\nname: doc3").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{"name": "doc1"},
				map[string]any{"name": "doc2"},
				map[string]any{"name": "doc3"},
			},
		},
		{
			Code:        `parse.yaml(content: "name: doc1\n---\nname: doc2").documents[0]`,
			ResultIndex: 0,
			Expectation: map[string]any{"name": "doc1"},
		},
		{
			Code:        `parse.yaml(content: "name: doc1\n---\nname: doc2").documents[1]`,
			ResultIndex: 0,
			Expectation: map[string]any{"name": "doc2"},
		},
		{
			Code:        `parse.yaml(content: "name: doc1\n---\n\n---\nname: doc2").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{"name": "doc1"},
				map[string]any{"name": "doc2"},
			},
		},
		{
			Code:        `parse.yaml(content: "apiVersion: v1\nkind: Service\n---\napiVersion: apps/v1\nkind: Deployment").documents`,
			ResultIndex: 0,
			Expectation: []any{
				map[string]any{
					"apiVersion": "v1",
					"kind":       "Service",
				},
				map[string]any{
					"apiVersion": "apps/v1",
					"kind":       "Deployment",
				},
			},
		},
		{
			Code:        `parse.yaml(content: "---").documents`,
			ResultIndex: 0,
			Expectation: []any{},
		},
		{
			Code:        `parse.yaml(content: "---\n---").documents`,
			ResultIndex: 0,
			Expectation: []any{},
		},
		{
			Code:        `parse.yaml(content: "name: doc1\n---\nname: doc2\n---\nname: doc3").documents.length`,
			ResultIndex: 0,
			Expectation: int64(3),
		},
	})
}

func TestResource_Processes(t *testing.T) {

	t.Run("test a specific process entry", func(t *testing.T) {
		res := x.TestQuery(t, "processes.list[0].pid")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(1), res[0].Data.Value)
	})

	t.Run("test a specific process entry with filter v1", func(t *testing.T) {
		res := x.TestQuery(t, "processes{ pid command }.list[0]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)

		m, ok := res[0].Data.Value.(map[string]any)
		if !ok {
			t.Error("failed to retrieve correct type of result")
			t.FailNow()
		}

		assert.Equal(t, types.Block, res[0].Data.Type)
		assert.Equal(t, llx.StringData("/sbin/init"), m["inW9aIPV3zVln3ROYYeru57EdXnE2cK452ZDPxvPs9HFaftOPsef3usY0JSS/J+EWStj+thfd7AH5XdflLF81Q=="])
		assert.Equal(t, llx.IntData(1), m["vGNOj/UnoXRncBiEGYvtT8Xml8xKuzl85lo7SkIdwF7X3tQLa/Tnv0M0UEA8pZdsQmfGkhHh3FFH3PiDFBEMwA=="])
	})
}

func TestResource_Python(t *testing.T) {
	x := testutils.InitTester(testutils.RecordingMock("./languages/python/testdata/linux.json"))

	t.Run("parse all packages", func(t *testing.T) {
		res := x.TestQuery(t, "python.packages")
		assert.NotEmpty(t, res)
		require.Empty(t, res[0].Result().Error)
		values, ok := res[0].Data.Value.([]any)
		require.True(t, ok, "type assertion failed")
		assert.Equal(t, 136, len(values), "expected two parsed packages")
	})

	t.Run("parse child packages", func(t *testing.T) {
		res := x.TestQuery(t, "python.toplevel")
		assert.NotEmpty(t, res)
		require.Empty(t, res[0].Result().Error)
		values, ok := res[0].Data.Value.([]any)
		require.True(t, ok, "type assertion failed")
		assert.Equal(t, 3, len(values), "expected a single child/leaf package")
	})
}

func TestResource_PythonPackage(t *testing.T) {
	x := testutils.InitTester(testutils.RecordingMock("./languages/python/testdata/rhel.json"))

	t.Run("parse python pkg info", func(t *testing.T) {
		res := x.TestQuery(t, "python.package(\"/usr/lib/python3.6/site-packages/python_dateutil-2.6.1-py3.6.egg-info/PKG-INFO\").name")
		assert.NotEmpty(t, res)
		require.Empty(t, res[0].Result().Error)
		assert.Equal(t, "python-dateutil", res[0].Data.Value, "expected name of parsed package")
	})

	t.Run("parse python metadata", func(t *testing.T) {
		res := x.TestQuery(t, "python.package(\"/usr/lib/python3.6/site-packages/six-1.11.0.dist-info/METADATA\").name")
		assert.NotEmpty(t, res)
		require.Empty(t, res[0].Result().Error)
		assert.Equal(t, "six", res[0].Data.Value, "expected name of parsed package")
	})

	t.Run("test python package cpes", func(t *testing.T) {
		res := x.TestQuery(t, "python.package(\"/usr/lib/python3.6/site-packages/six-1.11.0.dist-info/METADATA\").cpes.map(uri)[0]")
		assert.NotEmpty(t, res)
		require.Empty(t, res[0].Result().Error)
		assert.Equal(t, "cpe:2.3:a:six_project:six:1.11.0:*:*:*:*:*:*:*", res[0].Data.Value, "expected name of parsed package")
	})
}

func TestResource_Registrykey(t *testing.T) {
	t.Run("non existent registry key", func(t *testing.T) {
		res := testWindowsQuery(t, "registrykey('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization').exists")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, false, res[0].Data.Value)
	})

	t.Run("registry key path", func(t *testing.T) {
		res := testWindowsQuery(t, "registrykey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').path")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", res[0].Data.Value)
	})

	t.Run("existing registry key", func(t *testing.T) {
		res := testWindowsQuery(t, "registrykey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').exists")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})

	t.Run("registry key properties", func(t *testing.T) {
		res := testWindowsQuery(t, "registrykey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').properties")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, 24, len(res[0].Data.Value.(map[string]any)))
	})

	t.Run("registry key children", func(t *testing.T) {
		res := testWindowsQuery(t, "registrykey('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').children")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"Audit", "UIPI"}, res[0].Data.Value)
	})

	t.Run("non-existent registry key - props", func(t *testing.T) {
		res := testWindowsQuery(t, "registrykey('nope').properties")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, &llx.RawData{Type: types.Map(types.String, types.String)}, res[0].Data)
	})

	t.Run("non-existent registry key - items", func(t *testing.T) {
		res := testWindowsQuery(t, "registrykey('nope').items")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Nil(t, res[0].Data.Value)
	})

	// A missing registry property must not error when its fields are read or
	// compared — this is what lets policies drop the
	// `switch(x) { case _ != empty: ... default: false }` workaround around
	// registrykey.property(...).data.
	t.Run("missing property does not error on field access or comparison", func(t *testing.T) {
		existPath := "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
		queries := []string{
			// missing property on an existing key path
			"registrykey.property(path: '" + existPath + "', name: 'DoesNotExist').exists",
			"registrykey.property(path: '" + existPath + "', name: 'DoesNotExist').data > 0",
			"registrykey.property(path: '" + existPath + "', name: 'DoesNotExist').data > 0 && registrykey.property(path: '" + existPath + "', name: 'DoesNotExist').data <= 30",
			// missing property on a non-existent key path
			"registrykey.property(path: 'HKEY_LOCAL_MACHINE\\Nope\\Nope', name: 'DoesNotExist').data > 0",
		}
		for _, q := range queries {
			t.Run(q, func(t *testing.T) {
				res := testWindowsQuery(t, q)
				assert.NotEmpty(t, res)
				last := res[len(res)-1]
				assert.NoError(t, last.Data.Error)
				assert.Equal(t, false, last.Data.Value)
			})
		}
	})
}

func TestResource_RegistrykeyPerUserHive(t *testing.T) {
	// A per-user read (userSid + ntuserDat) must resolve cleanly even when the
	// hive can't be read (here: the mock has no recording for it). It degrades to
	// "not present" rather than erroring, so callers don't get a false positive.
	t.Run("property in an unreadable user hive does not exist", func(t *testing.T) {
		res := testWindowsQuery(t, `registrykey.property(userSid: 'S-1-5-21-1-2-3-1001', ntuserDat: 'C:\Users\test\NTUSER.DAT', path: 'Software\Policies\Microsoft\Windows\CloudContent', name: 'DisableThirdPartySuggestions').exists`)
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, false, res[0].Data.Value)
	})

	t.Run("path is interpreted relative to the user hive", func(t *testing.T) {
		res := testWindowsQuery(t, `registrykey(userSid: 'S-1-5-21-1-2-3-1001', ntuserDat: 'C:\Users\test\NTUSER.DAT', path: 'Software\Policies').path`)
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, `Software\Policies`, res[0].Data.Value)
	})

	t.Run("userSid is exposed on the key", func(t *testing.T) {
		res := testWindowsQuery(t, `registrykey(userSid: 'S-1-5-21-1-2-3-1001', ntuserDat: 'C:\Users\test\NTUSER.DAT', path: 'Software\Policies').userSid`)
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "S-1-5-21-1-2-3-1001", res[0].Data.Value)
	})
}

func TestResource_RsyslogConf(t *testing.T) {
	t.Run("files includes main conf and .d fragments", func(t *testing.T) {
		res := x.TestQuery(t, "rsyslog.conf.files.length")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, int64(2), res[0].Data.Value)
	})

	t.Run("content aggregates all files", func(t *testing.T) {
		res := x.TestQuery(t, "rsyslog.conf.content")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		content := res[0].Data.Value.(string)
		// Main conf content
		assert.Contains(t, content, "$ModLoad imuxsock")
		// Fragment content from rsyslog.d/50-default.conf
		assert.Contains(t, content, "kern.* /var/log/kern.log")
	})

	t.Run("settings strips comments and blanks", func(t *testing.T) {
		res := x.TestQuery(t, "rsyslog.conf.settings")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		settings := res[0].Data.Value.([]any)
		assert.Greater(t, len(settings), 0)
		// Verify comment-only and blank lines are excluded
		for _, s := range settings {
			line := s.(string)
			assert.NotEmpty(t, line)
			assert.NotEqual(t, "#", string(line[0]), "settings should not contain comment lines")
		}
	})

	t.Run("settings contains expected directives", func(t *testing.T) {
		res := x.TestQuery(t, "rsyslog.conf.settings")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		settings := res[0].Data.Value.([]any)
		// Check for a known directive from the main conf
		found := false
		for _, s := range settings {
			if s.(string) == "$ModLoad imuxsock" {
				found = true
				break
			}
		}
		assert.True(t, found, "settings should contain '$ModLoad imuxsock'")
	})

	t.Run("path returns default", func(t *testing.T) {
		res := x.TestQuery(t, "rsyslog.conf.path")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, "/etc/rsyslog.conf", res[0].Data.Value)
	})
}

func TestResource_Secpol(t *testing.T) {

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testWindowsQuery(t, "secpol.systemaccess['PasswordHistorySize']")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "0", res[0].Data.Value)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testWindowsQuery(t, "secpol.privilegerights['SeNetworkLogonRight']")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{
			"S-1-1-0",
			"S-1-5-32-544",
			"S-1-5-32-545",
			"S-1-5-32-551",
		}, res[0].Data.Value)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testWindowsQuery(t, "secpol.privilegerights['SeNetworkLogonRight'] == ['S-1-1-0', 'S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-551']")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[1].Result().Error)
		assert.Equal(t, true, res[1].Data.Value)
	})

	// A privilege right that is not assigned to anyone simply does not appear
	// in the policy, so secpol.privilegerights['SeMissing'] resolves to a typed
	// null array. Calling assertion methods on it must fail cleanly (return a
	// graceful false) rather than erroring the whole check — this is what lets
	// policies drop the `switch(x) { case _ != empty: ... default: false }`
	// workaround that previously guarded against the error.
	t.Run("missing privilege right does not error on assertion methods", func(t *testing.T) {
		queries := []string{
			"secpol.privilegerights['SeMissingRight'].contains('S-1-5-32-544')",
			"secpol.privilegerights['SeMissingRight'].any(_ == 'S-1-5-32-544')",
			"secpol.privilegerights['SeMissingRight'].all(_ == 'S-1-5-32-544')",
			"secpol.privilegerights['SeMissingRight'].none(_ == 'S-1-5-32-544')",
			"secpol.privilegerights['SeMissingRight'].one(_ == 'S-1-5-32-544')",
		}
		for _, q := range queries {
			t.Run(q, func(t *testing.T) {
				res := testWindowsQuery(t, q)
				assert.NotEmpty(t, res)
				last := res[len(res)-1]
				// no error, and the check fails gracefully (false)
				assert.NoError(t, last.Data.Error)
				assert.Equal(t, false, last.Data.Value)
			})
		}
	})
}

// TestResource_SecpolGerman covers a German host, where secedit names the
// principals of a user right instead of reporting their SIDs.
func TestResource_SecpolGerman(t *testing.T) {
	abs, err := filepath.Abs("testdata/secpol_windows_de.json")
	require.NoError(t, err)
	de := testutils.InitTester(testutils.RecordingMock(abs))

	res := de.TestQuery(t, "secpol.privilegerights['SeDenyNetworkLogonRight']")
	require.NotEmpty(t, res)
	assert.Empty(t, res[0].Result().Error)
	assert.Equal(t, []any{"S-1-5-32-544", "S-1-5-32-546"}, res[0].Data.Value)
}

// TestResource_SecpolSidLookupKilled pins the blast radius of a failing SID
// lookup: every field that does not need it keeps answering, which is most of
// what a Windows benchmark reads out of secpol.
func TestResource_SecpolSidLookupKilled(t *testing.T) {
	abs, err := filepath.Abs("testdata/secpol_windows_de_lookup_killed.json")
	require.NoError(t, err)
	de := testutils.InitTester(testutils.RecordingMock(abs))

	for _, q := range []string{
		"secpol.systemaccess['PasswordHistorySize']",
		"secpol.systemaccess['LockoutBadCount']",
		"secpol.eventaudit['AuditLogonEvents']",
		`secpol.registryvalues['MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing']`,
	} {
		t.Run(q, func(t *testing.T) {
			res := de.TestQuery(t, q)
			require.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.NotEmpty(t, res[0].Data.Value)
		})
	}

	// the field that does need it reports the failure rather than a list the
	// unresolved names were quietly dropped from
	res := de.TestQuery(t, "secpol.privilegerights['SeDenyNetworkLogonRight']")
	require.NotEmpty(t, res)
	assert.Contains(t, res[0].Result().Error, "could not resolve privilege right account names")
}

func TestResource_Services(t *testing.T) {

	t.Run("test a specific service entry", func(t *testing.T) {
		res := x.TestQuery(t, "services.list[0].name")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "acpid", res[0].Data.Value)
	})
}

func TestResource_Service(t *testing.T) {
	t.Run("test a specific service name", func(t *testing.T) {
		res := x.TestQuery(t, "service('dbus').name")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "dbus", res[0].Data.Value)
	})

	t.Run("test a specific service enabled", func(t *testing.T) {
		res := x.TestQuery(t, "service('dbus').enabled")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})

	t.Run("test a specific service running", func(t *testing.T) {
		res := x.TestQuery(t, "service('dbus').running")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})
}

func TestResource_Shadow(t *testing.T) {
	t.Run("list shadow entries", func(t *testing.T) {
		res := x.TestQuery(t, "shadow.list")
		assert.NotEmpty(t, res)
		assert.Equal(t, 3, len(res[0].Data.Value.([]any)))
	})

	t.Run("test a specific shadow entry", func(t *testing.T) {
		res := x.TestQuery(t, "shadow.list[0].user")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "root", res[0].Data.Value)
	})

	t.Run("test empty dates that set upper bounds", func(t *testing.T) {
		res := x.TestQuery(t, "shadow.list[0].maxdays")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(math.MaxInt64), res[0].Data.Value)

		res = x.TestQuery(t, "shadow.list[0].inactivedays")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(math.MaxInt64), res[0].Data.Value)
	})

	t.Run("test empty dates that set lower bounds", func(t *testing.T) {
		res := x.TestQuery(t, "shadow.list[0].mindays")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(-1), res[0].Data.Value)

		res = x.TestQuery(t, "shadow.list[0].warndays")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(-1), res[0].Data.Value)
	})
}

func TestResource_SSHD(t *testing.T) {
	x.TestSimpleErrors(t, []testutils.SimpleTest{
		{
			Code:        "sshd.config('nopath').params['2'] == '3'",
			ResultIndex: 0,
			Expectation: "file '/etc/ssh/nopath' not found",
		},
	})

	t.Run("sshd file path", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.file.path")
		assert.NotEmpty(t, res)
		assert.NoError(t, res[0].Data.Error)
	})

	t.Run("sshd file error propagation", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config('nope').params")
		assert.Error(t, res[0].Data.Error)
	})

	t.Run("specific sshd param", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.params[\"UsePAM\"]")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "yes", res[0].Data.Value)
	})

	t.Run("parse ciphers", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.ciphers")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"}, res[0].Data.Value)
	})

	t.Run("parse block ciphers", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.blocks[0].ciphers")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"}, res[0].Data.Value)
	})

	t.Run("parse macs", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.macs")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256"}, res[0].Data.Value)
	})

	t.Run("parse block macs", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.blocks[0].macs")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256"}, res[0].Data.Value)
	})

	t.Run("parse kexs", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.kexs")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"curve25519-sha256@libssh.org", "diffie-hellman-group-exchange-sha256"}, res[0].Data.Value)
	})

	t.Run("parse block kexs", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.blocks[0].kexs")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"curve25519-sha256@libssh.org", "diffie-hellman-group-exchange-sha256"}, res[0].Data.Value)
	})

	t.Run("parse hostKeys", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.hostkeys")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"}, res[0].Data.Value)
	})

	t.Run("parse block hostKeys", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.blocks[0].hostkeys")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"}, res[0].Data.Value)
	})

	t.Run("parse HostKeyAlgorithms", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.hostkeyalgorithms")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp521-cert-v01@openssh.com"}, res[0].Data.Value)
	})

	t.Run("parse block HostKeyAlgorithms", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.blocks[0].hostkeyalgorithms")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp521-cert-v01@openssh.com"}, res[0].Data.Value)
	})

	t.Run("parse permitRootLogin", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.permitRootLogin")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"no"}, res[0].Data.Value)
	})

	t.Run("parse block permitRootLogin", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.blocks[0].permitRootLogin")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"no"}, res[0].Data.Value)
	})

	t.Run("parse blocks", func(t *testing.T) {
		var res []*llx.RawResult

		res = x.TestQuery(t, "sshd.config.blocks.map(criteria)")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"", "Group sftp-users", "User myservice"}, res[0].Data.Value)

		res = x.TestQuery(t, "sshd.config.blocks.map(params.AllowTcpForwarding)")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []any{"no", "yes", nil}, res[0].Data.Value)

		ranges := []any{
			llx.NewRange().AddLineRange(1, 172),
			llx.NewRange().AddLineRange(173, 177),
			llx.NewRange().AddLineRange(178, 180),
		}
		res = x.TestQuery(t, "sshd.config.blocks.map(context.range)")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, ranges, res[0].Data.Value)

		paths := []any{
			"/etc/ssh/sshd_config",
			"/etc/ssh/sshd_config",
			"/etc/ssh/sshd_config",
		}
		res = x.TestQuery(t, "sshd.config.blocks.map(context.file.path)")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, paths, res[0].Data.Value)
	})

	t.Run("expose block match criteria in params.Match", func(t *testing.T) {
		res := x.TestQuery(t, "sshd.config.params.Match")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Group sftp-users,User myservice", res[0].Data.Value)
	})
}

// These execute against the arch mock, whose /dummy.json contains a `_` key
// holding null and no key named `NOPE` - the two cases ADR 043 has to tell
// apart: a value that is null because that is what was there, versus a key the
// query claimed exists and does not.
const strictDoc = "parse.json('/dummy.json').params"

// runStrict compiles in the given mode and returns the expression's own value.
// Results are ordered value-first, with the query's truthiness appended, so
// index 0 is the chain's result and the tail is the assertion outcome.
func runStrict(t *testing.T, code string, strict bool) *llx.RawResult {
	t.Helper()
	return runStrictAll(t, code, strict)[0]
}

// runStrictOutcome returns the query's final boolean, which is what a comparison
// resolves to.
func runStrictOutcome(t *testing.T, code string, strict bool) *llx.RawResult {
	t.Helper()
	all := runStrictAll(t, code, strict)
	return all[len(all)-1]
}

func runStrictAll(t *testing.T, code string, strict bool) []*llx.RawResult {
	t.Helper()

	x := testutils.InitTester(testutils.LinuxMock())
	conf := mqlc.NewConfig(x.Runtime.Schema(), testutils.Features)
	conf.Strict = strict

	bundle, err := mqlc.Compile(code, nil, conf)
	require.NoError(t, err, "compiling %q", code)

	results := x.TestMqlc(t, bundle, nil)
	require.NotEmpty(t, results, "no results for %q", code)
	return results
}

func assertValue(t *testing.T, res *llx.RawResult, expected any, code string) {
	t.Helper()
	require.NoError(t, res.Data.Error, "%q should not error", code)
	assert.Equal(t, expected, res.Data.Value, "%q", code)
}

func assertNull(t *testing.T, res *llx.RawResult, code string) {
	t.Helper()
	require.NoError(t, res.Data.Error, "%q should not error", code)
	assert.Nil(t, res.Data.Value, "%q should be null", code)
}

func assertErrors(t *testing.T, res *llx.RawResult, contains string, code string) {
	t.Helper()
	require.Error(t, res.Data.Error, "%q should error", code)
	assert.Contains(t, res.Data.Error.Error(), contains, "%q", code)
}

// TestStrict_nonStrictUnchanged is the compatibility guarantee. Every one of
// these silently yields null today, and must keep doing so.
func TestStrict_nonStrictUnchanged(t *testing.T) {
	for _, code := range []string{
		strictDoc + "['NOPE']",
		strictDoc + "['NOPE']['b']",
		strictDoc + ".NOPE",
		strictDoc + "['_']['b']",
	} {
		t.Run(code, func(t *testing.T) {
			assertNull(t, runStrict(t, code, false), code)
		})
	}

	// the silent false that motivates the whole ADR
	code := strictDoc + "['NOPE'] == 'no'"
	assertValue(t, runStrictOutcome(t, code, false), false, code)
}

// TestStrict_missingKeyErrors covers the case strict mode exists for: a key the
// query names that is not there. Notably it errors even as a terminal lookup,
// which is what catches a typo that only ever feeds a comparison.
func TestStrict_missingKeyErrors(t *testing.T) {
	for _, code := range []string{
		strictDoc + "['NOPE']",
		strictDoc + ".NOPE",
		strictDoc + "['NOPE']['b']",
	} {
		t.Run(code, func(t *testing.T) {
			assertErrors(t, runStrict(t, code, true), "cannot find key \"NOPE\"", code)
		})
	}

	// The one that matters most: a mistyped key compared against a value used to
	// come back as a clean `false`, which reads as a passing check.
	code := strictDoc + "['NOPE'] == 'no'"
	assertErrors(t, runStrict(t, code, true), "cannot find key \"NOPE\"", code)
}

// TestStrict_nullValueIsNotAMissingKey pins the distinction the rule rests on.
// `_` is present and holds null, so reading it resolves; only reading *through*
// it fails.
func TestStrict_nullValueIsNotAMissingKey(t *testing.T) {
	code := strictDoc + "['_']"
	assertNull(t, runStrict(t, code, true), code)

	code = strictDoc + "['_']['b']"
	assertErrors(t, runStrict(t, code, true), "the value it reads from is null", code)
}

// TestStrict_dottedKeyWalkStillReportsRealTypos is the risk the dotted-key walk
// runs: a chain over a document keyed by preference domain has to survive the
// nulls its intermediate segments produce, without that tolerance swallowing a
// name the document genuinely does not contain (ADR 043).
func TestStrict_dottedKeyWalkStillReportsRealTypos(t *testing.T) {
	const doc = "parse.json(content: '" +
		`{"com.apple.security.firewall": {"EnableFirewall": {"value": true}}}` +
		"').params"

	// The whole path resolves, so none of the intermediate misses may error.
	code := doc + ".com.apple.security.firewall.EnableFirewall.value"
	res := runStrict(t, code, true)
	require.NoError(t, res.Data.Error, "%q should resolve", code)
	assert.Equal(t, true, res.Data.Value)

	// A segment that continues no key in the document is a claim about
	// something absent, and still has to be reported as one.
	code = doc + ".com.apple.security.firewallX.EnableFirewall.value"
	assertErrors(t, runStrict(t, code, true), "cannot find key", code)

	// Same once the domain itself has resolved: the walk is over, and the leaf
	// name is simply not there.
	code = doc + ".com.apple.security.firewall.NOPE"
	assertErrors(t, runStrict(t, code, true), "cannot find key", code)
}

// TestStrict_dottedKeyWalkKeepsItsHandsOff checks that tolerating the nulls a
// walk produces does not become a general licence to read through null.
func TestStrict_dottedKeyWalkKeepsItsHandsOff(t *testing.T) {
	// A Kubernetes label continues the text of `labels.app` but no dot chain can
	// reach it, so "app" is simply missing and has to be reported.
	code := "parse.json(content: '" +
		`{"labels": {"app.kubernetes.io/name": "web"}}` +
		"').params.labels.app"
	assertErrors(t, runStrict(t, code, true), "cannot find key", code)

	// Only a key lookup continues a walk. Anything else reading through the
	// null an unfinished walk produced is reading through a null.
	code = "parse.json(content: '" + `{"com.apple.x": 1}` + "').params.com.length"
	require.Error(t, runStrict(t, code, true).Data.Error, "%q should error", code)

	// A guard upstream ends the walk rather than widening itself over the rest
	// of the chain.
	code = "parse.json(content: '" + `{"com.apple.firewall": {"on": true}}` + "').params.com?.apple.NOPE"
	assertNull(t, runStrict(t, code, true), code)

	// And a guard downstream does not reach back over it. `a.b?` says b may be
	// missing, not that anything in the chain may be - so the key that went
	// missing first is still reported, in a document with no dotted keys at all.
	code = "parse.json(content: '" + `{"server": {"port": 22}}` + "').params.PermitRootLogn.value?"
	assertErrors(t, runStrict(t, code, true), "cannot find key", code)
}

// TestStrict_optionalWaivesBothCauses is the double duty: one mark, in one
// position, covers both an absent key and a present-but-null value.
func TestStrict_optionalWaivesBothCauses(t *testing.T) {
	for _, code := range []string{
		strictDoc + "['NOPE']?",       // absent key, terminal
		strictDoc + "['NOPE']?['b']",  // absent key, dereferenced
		strictDoc + "['_']?['b']",     // present but null, dereferenced
		strictDoc + ".NOPE?",          // bare-word sugar
		strictDoc + "?['NOPE']?['b']", // guards stacked
	} {
		t.Run(code, func(t *testing.T) {
			assertNull(t, runStrict(t, code, true), code)
		})
	}
}

// TestStrict_shortCircuitIsNotSticky is the JavaScript property: a guard covers
// the link it is attached to and hands a null down the chain, but it does not
// silence a *different* link further along.
func TestStrict_shortCircuitIsNotSticky(t *testing.T) {
	// `e` exists and is a dict, so the guard on it never fires; `NOPE` inside it
	// is still missing and must still error.
	code := strictDoc + "['e']?['NOPE']"
	assertErrors(t, runStrict(t, code, true), "cannot find key \"NOPE\"", code)

	// with the guard moved to the link that actually misses, it resolves
	code = strictDoc + "['e']?['NOPE']?"
	assertNull(t, runStrict(t, code, true), code)
}

// TestStrict_operatorsStillTakeNull is the exemption. Comparisons receive a null
// as an operand rather than as a failed dereference, so `== null` stays the way
// to test for null and does not become an error.
func TestStrict_operatorsStillTakeNull(t *testing.T) {
	code := strictDoc + "['_'] == null"
	assertValue(t, runStrictOutcome(t, code, true), true, code)

	code = strictDoc + "['_'] != null"
	assertValue(t, runStrictOutcome(t, code, true), false, code)
}

// TestStrict_resolvedChainsAreUnaffected: strict mode must be invisible to a
// query that was already correct.
func TestStrict_resolvedChainsAreUnaffected(t *testing.T) {
	for _, tc := range []struct {
		code     string
		expected any
	}{
		{strictDoc + "['hello']", "hello"},
		{strictDoc + ".hello", "hello"},
		{strictDoc + "['e']['hi']", "hello"},
		{strictDoc + ".e.hi", "hello"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			assertValue(t, runStrict(t, tc.code, true), tc.expected, tc.code)
		})
	}

	code := strictDoc + "['hello'] == 'hello'"
	assertValue(t, runStrictOutcome(t, code, true), true, code)
}

func TestResource_Sudoers(t *testing.T) {
	t.Run("files are discovered", func(t *testing.T) {
		res := x.TestQuery(t, "sudoers.files.length")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, int64(1), res[0].Data.Value)
	})

	t.Run("content aggregates all files", func(t *testing.T) {
		res := x.TestQuery(t, "sudoers.content")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		content := res[0].Data.Value.(string)
		assert.Contains(t, content, "root ALL=(ALL:ALL) ALL")
		assert.Contains(t, content, "ADMINS ALL=(ALL) NOPASSWD: ALL")
		assert.Contains(t, content, "Defaults secure_path=")
	})

	t.Run("userSpecs parsing", func(t *testing.T) {
		res := x.TestQuery(t, "sudoers.userSpecs.length")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, int64(6), res[0].Data.Value)
	})

	t.Run("userSpec fields", func(t *testing.T) {
		// Test root user spec has all expected fields populated
		res := x.TestQuery(t, "sudoers.userSpecs.where(users.contains(\"root\")).first")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)

		// Verify hosts field
		res = x.TestQuery(t, "sudoers.userSpecs.where(users.contains(\"root\")).first.hosts")
		require.NotEmpty(t, res)
		hosts, ok := res[0].Data.Value.([]any)
		require.True(t, ok)
		assert.Contains(t, hosts, "ALL")

		// Verify commands field
		res = x.TestQuery(t, "sudoers.userSpecs.where(users.contains(\"root\")).first.commands")
		require.NotEmpty(t, res)
		commands, ok := res[0].Data.Value.([]any)
		require.True(t, ok)
		assert.Contains(t, commands, "ALL")
	})

	t.Run("userSpec with NOPASSWD tag", func(t *testing.T) {
		res := x.TestQuery(t, "sudoers.userSpecs.where(tags.contains(\"NOPASSWD\")).length")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, int64(2), res[0].Data.Value)
	})

	t.Run("defaults parsing", func(t *testing.T) {
		res := x.TestQuery(t, "sudoers.defaults.length")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, int64(6), res[0].Data.Value)
	})

	t.Run("defaults fields", func(t *testing.T) {
		// Test secure_path has correct value
		res := x.TestQuery(t, "sudoers.defaults.where(parameter == \"secure_path\").first.value")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", res[0].Data.Value)

		// Test negated flag (!lecture)
		res = x.TestQuery(t, "sudoers.defaults.where(parameter == \"lecture\").first.negated")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, true, res[0].Data.Value)
	})

	t.Run("defaults scoped entries", func(t *testing.T) {
		// Test host-scoped default
		res := x.TestQuery(t, "sudoers.defaults.where(scope == \"host\").first.target")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, "webservers", res[0].Data.Value)
	})

	t.Run("aliases parsing", func(t *testing.T) {
		res := x.TestQuery(t, "sudoers.aliases.length")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, int64(7), res[0].Data.Value)
	})

	t.Run("alias fields", func(t *testing.T) {
		// Note: alias type is stored as lowercase without "_Alias" suffix
		res := x.TestQuery(t, "sudoers.aliases.where(type == \"user\" && name == \"ADMINS\").first.members")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		members, ok := res[0].Data.Value.([]any)
		require.True(t, ok)
		assert.Equal(t, 3, len(members))
		assert.Contains(t, members, "alice")
	})

	t.Run("all alias types present", func(t *testing.T) {
		// Verify all 4 alias types are parsed
		res := x.TestQuery(t, "sudoers.aliases.where(type == \"host\").length")
		require.NotEmpty(t, res)
		assert.Equal(t, int64(2), res[0].Data.Value)

		res = x.TestQuery(t, "sudoers.aliases.where(type == \"cmnd\").length")
		require.NotEmpty(t, res)
		assert.Equal(t, int64(2), res[0].Data.Value)

		res = x.TestQuery(t, "sudoers.aliases.where(type == \"runas\").length")
		require.NotEmpty(t, res)
		assert.Equal(t, int64(1), res[0].Data.Value)
	})

	t.Run("metadata fields", func(t *testing.T) {
		// Test file and lineNumber are populated
		res := x.TestQuery(t, "sudoers.userSpecs.first.file")
		require.NotEmpty(t, res)
		require.NoError(t, res[0].Data.Error)
		assert.Equal(t, "/etc/sudoers", res[0].Data.Value)

		res = x.TestQuery(t, "sudoers.userSpecs.first.lineNumber")
		require.NotEmpty(t, res)
		lineNum, ok := res[0].Data.Value.(int64)
		require.True(t, ok)
		assert.Greater(t, lineNum, int64(0))
	})
}

func TestResource_Users(t *testing.T) {

	t.Run("test a specific user's name", func(t *testing.T) {
		res := x.TestQuery(t, "users.list[0].name")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "root", res[0].Data.Value)
	})

	t.Run("test contains", func(t *testing.T) {
		res := x.TestQuery(t, "users.contains(name == 'root')")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[1].Data.Value)
	})

	t.Run("test contains", func(t *testing.T) {
		res := x.TestQuery(t, "users.contains(group != null)")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[1].Data.Value)
	})

	t.Run("test user init (uid)", func(t *testing.T) {
		res := x.TestQuery(t, "user(uid: 1000).name")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "chris", res[0].Data.Value)
	})

	t.Run("test user init (name)", func(t *testing.T) {
		res := x.TestQuery(t, "user(name: 'chris').uid")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(1000), res[0].Data.Value)
	})
}

func TestResource_WindowsAuditPolicy(t *testing.T) {
	// one tester for all subtests, so lookups, list iteration, and the
	// missing-subcategory stub share a runtime and exercise resource caching
	win := testutils.InitTester(testutils.WindowsMock())

	t.Run("list all subcategories", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.length")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(59), res[0].Data.Value)
	})

	t.Run("lookup by English name", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.subcategory('Logon') { success && failure }")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		truthy, found := res[0].Data.IsTruthy()
		assert.True(t, found)
		assert.True(t, truthy)
	})

	t.Run("lookup is case-insensitive", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.subcategory('logon').guid")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "0CCE9215-69AE-11D9-BED3-505054503030", res[0].Data.Value)
	})

	t.Run("lookup by GUID", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.subcategory('0CCE922B-69AE-11D9-BED3-505054503030').name")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Process Creation", res[0].Data.Value)
	})

	t.Run("lookup by braced GUID", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.subcategory('{0CCE922B-69AE-11D9-BED3-505054503030}').name")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Process Creation", res[0].Data.Value)
	})

	t.Run("category from the well-known table", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.subcategory('Credential Validation').category")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Account Logon", res[0].Data.Value)
	})

	t.Run("filter by category", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.where(category == 'Detailed Tracking').length")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, int64(6), res[0].Data.Value)
	})

	t.Run("success and failure derive from the inclusion setting", func(t *testing.T) {
		cases := []struct {
			name             string // its inclusion setting in the recording
			success, failure bool
		}{
			{"System Integrity", true, true},            // "Success and Failure"
			{"Security State Change", true, false},      // "Success"
			{"Security System Extension", false, false}, // "No Auditing"
		}
		for _, tc := range cases {
			res := win.TestQuery(t, "windows.auditPolicy.subcategory('"+tc.name+"').success")
			require.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.Equal(t, tc.success, res[0].Data.Value, "success for %s", tc.name)

			res = win.TestQuery(t, "windows.auditPolicy.subcategory('"+tc.name+"').failure")
			require.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.Equal(t, tc.failure, res[0].Data.Value, "failure for %s", tc.name)
		}
	})

	t.Run("raw settings pass through unchanged", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.subcategory('Logon').inclusionSetting")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Success and Failure", res[0].Data.Value)

		// on an English system the localized name is the English name
		res = win.TestQuery(t, "windows.auditPolicy.subcategory('Logon').localizedName")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Logon", res[0].Data.Value)
	})

	t.Run("missing subcategory audits nothing and fails checks cleanly", func(t *testing.T) {
		res := win.TestQuery(t, "windows.auditPolicy.subcategory('No Such Subcategory').success")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, false, res[0].Data.Value)

		res = win.TestQuery(t, "windows.auditPolicy.subcategory('No Such Subcategory').guid")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Nil(t, res[0].Data.Value)

		res = win.TestQuery(t, "windows.auditPolicy.subcategory('No Such Subcategory') { success && failure }")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		truthy, found := res[0].Data.IsTruthy()
		assert.True(t, found)
		assert.False(t, truthy)

		// a missed lookup must not poison the cache for present subcategories
		res = win.TestQuery(t, "windows.auditPolicy.subcategory('Logon').success")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})
}

// TestResource_WindowsAuditPolicyGerman exercises the resource end-to-end
// against a recording of a German-localized `auditpol /r`: subcategory names
// and inclusion settings arrive localized, while name, category, and the
// success/failure booleans must come out language-stable.
func TestResource_WindowsAuditPolicyGerman(t *testing.T) {
	abs, err := filepath.Abs("testdata/auditpol_windows_de.json")
	require.NoError(t, err)
	de := testutils.InitTester(testutils.RecordingMock(abs))

	// "Richtlinienänderungen überwachen" / "Erfolg" on GUID 0CCE922F
	t.Run("English name resolves on a German system", func(t *testing.T) {
		res := de.TestQuery(t, "windows.auditPolicy.subcategory('Audit Policy Change').success")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)

		res = de.TestQuery(t, "windows.auditPolicy.subcategory('Audit Policy Change').failure")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, false, res[0].Data.Value)

		res = de.TestQuery(t, "windows.auditPolicy.subcategory('Audit Policy Change').localizedName")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Richtlinienänderungen überwachen", res[0].Data.Value)
	})

	t.Run("localized name resolves too", func(t *testing.T) {
		res := de.TestQuery(t, "windows.auditPolicy.subcategory('Richtlinienänderungen überwachen').guid")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "0CCE922F-69AE-11D9-BED3-505054503030", res[0].Data.Value)
	})

	t.Run("names and categories are reported in English", func(t *testing.T) {
		res := de.TestQuery(t, "windows.auditPolicy.subcategory('0CCE9217-69AE-11D9-BED3-505054503030').name")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Account Lockout", res[0].Data.Value)

		res = de.TestQuery(t, "windows.auditPolicy.subcategory('Account Lockout').category")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, "Logon/Logoff", res[0].Data.Value)
	})

	// the issue's motivating check shape: "Success and Failure" on a
	// localized system, asserted without GUIDs or props
	t.Run("audit check pattern", func(t *testing.T) {
		res := de.TestQuery(t, "windows.auditPolicy.subcategory('Account Lockout') { success && failure }")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		truthy, found := res[0].Data.IsTruthy()
		assert.True(t, found)
		assert.True(t, truthy)
	})
}

// AppArmor on a host that does not have it.
//
// The resource used to fail every field with "AppArmor kernel interfaces
// unavailable" on such a host, so a policy could not ask about AppArmor at all
// without erroring on RHEL, NixOS or anything else that ships SELinux or
// nothing. selinux answers installed=false on a host without SELinux, and
// apparmor now answers the same way: absent is a fact it can report, while a
// profile list that exists and cannot be read stays an error.
func TestApparmorAbsent(t *testing.T) {
	t.Run("installed is a measured false, not an error", func(t *testing.T) {
		res := x.TestQuery(t, "apparmor.installed")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, false, res[0].Data.Value)
	})

	t.Run("nothing is confined", func(t *testing.T) {
		res := x.TestQuery(t, "apparmor.profiles")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Empty(t, res[0].Data.Value, "a host without AppArmor loads no profiles")

		res = x.TestQuery(t, "apparmor.processes")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Empty(t, res[0].Data.Value, "a host without AppArmor confines no process")
	})

	t.Run("version is null rather than an invented empty", func(t *testing.T) {
		res := x.TestQuery(t, "apparmor.version")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Nil(t, res[0].Data.Value, "there is no AppArmor version to report")
	})

	// The gate a policy is meant to use: asking whether AppArmor confines
	// anything must not error on a host that has none.
	t.Run("the policy gate resolves", func(t *testing.T) {
		res := x.TestQuery(t, "apparmor.installed && apparmor.profiles.none(mode == \"complain\")")
		require.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		truthy, found := res[0].Data.IsTruthy()
		assert.True(t, found)
		assert.False(t, truthy, "AppArmor is not installed, so the gate is false")
	})
}
