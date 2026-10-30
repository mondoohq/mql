// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package exec_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
	"go.uber.org/goleak"
)

func runtime() llx.Runtime {
	return testutils.LinuxMock()
}

func TestMain(m *testing.M) {
	// Prevent "goleak: Errors on successful test run: found unexpected goroutines"
	opts := []goleak.Option{
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	}
	// verify that we are not leaking goroutines
	goleak.VerifyTestMain(m, opts...)
}

func TestMqlHundreds(t *testing.T) {
	for i := range 500 {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			res, err := exec.Exec("asset.platform", runtime(), testutils.Features, nil)
			assert.NoError(t, err)
			assert.NoError(t, res.Error)
			assert.Equal(t, "arch", res.Value)
		})
	}
}

func TestMqlSimple(t *testing.T) {
	tests := []struct {
		query     string
		assertion any
	}{
		{"asset.platform", "arch"},
		{"asset { platform version }", map[string]any{
			"platform": "arch",
			"version":  "rolling",
		}},
		{"users { name uid }", []any{
			map[string]any{"name": "root", "uid": int64(0)},
			map[string]any{"name": "bin", "uid": int64(1)},
			map[string]any{"name": "chris", "uid": int64(1000)},
			map[string]any{"name": "christopher", "uid": int64(1001)},
		}},
	}

	for i := range tests {
		one := tests[i]
		t.Run(one.query, func(t *testing.T) {
			res, err := exec.Exec(one.query, runtime(), testutils.Features, nil)
			assert.NoError(t, err)
			assert.NoError(t, res.Error)
			assert.Equal(t, one.assertion, res.Value)
		})
	}
}

// Regression test for https://github.com/mondoohq/mql/issues/1174: a case whose
// condition is a constant boolean (`case true:` / `case false:`) used to compile
// to the same Bool primitive the compiler emits for `default`, so the runtime
// misidentified it as the default case and fell through to the last default-looking
// arg. These must now match by their actual truthiness.
func TestMqlSwitch(t *testing.T) {
	tests := []struct {
		query     string
		assertion any
	}{
		{"switch { case true: 1; case false: 2; }", int64(1)},
		{"switch { case false: 1; case true: 2; }", int64(2)},
		{"switch { case true: 1; default: 2; }", int64(1)},
		{"switch { case false: 1; default: 2; }", int64(2)},
		{"switch { case false: 1; case false: 2; default: 3; }", int64(3)},
		{`switch(1) { case _ > 0: "pos"; default: "neg" }`, "pos"},
		{`switch(1) { case _ < 0: "neg"; default: "other" }`, "other"},
	}

	for i := range tests {
		one := tests[i]
		t.Run(one.query, func(t *testing.T) {
			res, err := exec.Exec(one.query, runtime(), testutils.Features, nil)
			require.NoError(t, err)
			require.NoError(t, res.Error)
			assert.Equal(t, one.assertion, res.Value)
		})
	}
}

func TestCustomData(t *testing.T) {
	query := "{ \"a\": \"valuea\", \"b\": \"valueb\"}"

	value, err := exec.Exec(query, runtime(), testutils.Features, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": "valuea", "b": "valueb"}, value.Value)
}

func TestJsonArrayBounds(t *testing.T) {
	t.Run("out of bounds", func(t *testing.T) {
		query := `x = parse.json(content: '{"arr": []}').params
	x['arr'][0]`
		value, err := exec.Exec(query, runtime(), testutils.Features, nil)
		require.NoError(t, err)
		require.Contains(t, value.Error.Error(), "array index out of bound")
	})

	t.Run("positive index", func(t *testing.T) {
		query := `x = parse.json(content: '{"arr": [1, 2, 3]}').params
x['arr'][1]`
		value, err := exec.Exec(query, runtime(), testutils.Features, nil)
		require.NoError(t, err)
		require.Equal(t, float64(2), value.Value)
	})

	t.Run("negative index", func(t *testing.T) {
		query := `x = parse.json(content: '{"arr": [1, 2, 3]}').params
x['arr'][-1]`
		value, err := exec.Exec(query, runtime(), testutils.Features, nil)
		require.NoError(t, err)
		require.Equal(t, float64(3), value.Value)
	})

	t.Run("negative index out of bounds", func(t *testing.T) {
		query := `x = parse.json(content: '{"arr": [1, 2, 3]}').params
x['arr'][-4]`
		value, err := exec.Exec(query, runtime(), testutils.Features, nil)
		require.NoError(t, err)
		require.Contains(t, value.Error.Error(), "array index out of bound")
	})
}

func TestMqlProps(t *testing.T) {
	query := "props.a + props.b"
	props := mqlc.SimpleProps{
		"a": llx.IntPrimitive(2),
		"b": llx.IntPrimitive(2),
	}

	value, err := exec.Exec(query, runtime(), testutils.Features, props)
	require.NoError(t, err)
	assert.Equal(t, int64(4), value.Value)
}

func TestMqlIfElseProps(t *testing.T) {
	me := exec.New(runtime(), mql.DefaultFeatures)
	query := "if (props.a > 2) { return {\"a\": \"valuea\"} } return {\"a\": \"valueb\"}"

	props := mqlc.SimpleProps{
		"a": llx.IntPrimitive(3),
	}
	value, err := me.Exec(query, props)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": "valuea"}, value.Value)

	props = mqlc.SimpleProps{
		"a": llx.IntPrimitive(2),
	}
	value, err = me.Exec(query, props)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": "valueb"}, value.Value)
}

func TestMqlIfAndProps(t *testing.T) {
	me := exec.New(runtime(), mql.DefaultFeatures)
	query := "if (props.a > 2) { return {\"a\": \"valuea\"} }"

	props := mqlc.SimpleProps{
		"a": llx.IntPrimitive(3),
	}
	value, err := me.Exec(query, props)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": "valuea"}, value.Value)

	props = mqlc.SimpleProps{
		"a": llx.IntPrimitive(2),
	}
	value, err = me.Exec(query, props)
	require.NoError(t, err)
	assert.Equal(t, nil, value.Value)
}

func TestResourceAliases(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "os.unix.sshd.config.file.path",
			ResultIndex: 0,
			Expectation: "/etc/ssh/sshd_config",
		},
		{
			Code:        "os.unix.sshd { config.file.path }",
			ResultIndex: 0,
			Expectation: map[string]any{
				"_":   llx.ResourceData(&llx.MockResource{Name: "sshd"}, "os.unix.sshd"),
				"__s": llx.NilData,
				"__t": llx.BoolData(true),
				"SM/iGp+gb6JBt0bBm5RWqTtPLKzx6ebI+nUm4Q6LCQDuEu1QSRsWqEI3Tl/oK+u0b0eit+nTLhNdjlsOdIIDJQ==": llx.StringData("/etc/ssh/sshd_config"),
			},
		},
	})
}

func TestTypeCasts(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "/regex2string/",
			ResultIndex: 0,
			Expectation: "regex2string",
		},
		{
			Code:        "regex('s.*g') == 'string'",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "int(1.23)",
			ResultIndex: 0,
			Expectation: int64(1),
		},
		{
			Code:        "int('12')",
			ResultIndex: 0,
			Expectation: int64(12),
		},
		{
			Code:        "float(123)",
			ResultIndex: 0,
			Expectation: float64(123),
		},
		{
			Code:        "float('123')",
			ResultIndex: 0,
			Expectation: float64(123),
		},
		{
			Code:        "int(float('1.23'))",
			ResultIndex: 0,
			Expectation: int64(1),
		},
		{
			Code:        "bool(1.23)",
			ResultIndex: 0,
			Expectation: true,
		},
		{
			Code:        "bool(0)",
			ResultIndex: 0,
			Expectation: false,
		},
		{
			Code:        "bool('true')",
			ResultIndex: 0,
			Expectation: true,
		},
		{
			Code:        "bool('false')",
			ResultIndex: 0,
			Expectation: false,
		},
	})
}

func TestResource_List_Builtins(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "customGroups.length",
			ResultIndex: 0,
			Expectation: int64(5),
		},
		{
			Code:        "customGroups.first",
			ResultIndex: 0,
			Expectation: &llx.MockResource{Name: "mgroup", ID: "group1"},
		},
		{
			Code:        "customGroups.first.name",
			ResultIndex: 0,
			Expectation: "group1",
		},
		{
			Code:        "customGroups.last",
			ResultIndex: 0,
			Expectation: &llx.MockResource{Name: "mgroup", ID: "group7"},
		},
		{
			Code:        "customGroups == empty",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			Code:        "customGroups != empty",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "emptyGroups == empty",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "emptyGroups != empty",
			ResultIndex: 1,
			Expectation: false,
		},
	})
}

func TestNullResources(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "muser.group",
			ResultIndex: 0,
			Expectation: &llx.MockResource{Name: "mgroup", ID: "group one"},
		},
		{
			Code:        "muser.nullgroup",
			ResultIndex: 0,
			Expectation: nil,
		},
		{
			Code:        "muser.nullgroup.name",
			ResultIndex: 0,
			Expectation: nil,
		},
		{
			Code:        "muser.nullgroup == null",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "muser.nullgroup == empty",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        "muser.groups.where(null) == empty",
			ResultIndex: 2,
			Expectation: false,
		},
		{
			Code:        "muser.groups.where(name == '').map(name) + ['one']",
			ResultIndex: 0,
			Expectation: []any{"one"},
		},
		{
			Code:        "muser.groups.where(name == '') == empty",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        "muser.groups",
			ResultIndex: 0,
			Expectation: []any{
				&llx.MockResource{Name: "mgroup", ID: "group one"},
				nil,
			},
		},
		{
			Code:        "muser { nullgroup }",
			ResultIndex: 0,
			Expectation: map[string]any{
				"_":   &llx.RawData{Type: types.Resource("muser"), Value: &llx.MockResource{Name: "muser"}},
				"__s": llx.NilData,
				"__t": llx.BoolTrue,
				"A8qiFMpyfjKsr3OzVu+L+43W0BvYXoCPiwM7zu8AFQkBYEBMvZfR73ZsdfIqswmN1n9Qs/Soc1D7qxJipXv/ZA==": llx.ResourceData(nil, "mgroup"),
			},
		},
	})
}

func TestNamedFunctions(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "muser.groups.where(group: group != empty).length",
			ResultIndex: 0, Expectation: int64(1),
		},
		{
			Code:        "muser.groups.where(_: _ != empty).length",
			ResultIndex: 0, Expectation: int64(1),
		},
		{
			Code:        "muser.dict.listInt.where(x: x == 2)",
			ResultIndex: 0, Expectation: []any{int64(2)},
		},
	})
}

func TestNullString(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "muser.nullstring.contains('123')",
			ResultIndex: 0,
			Expectation: false,
		},
	})
}

func TestDictContains(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "muser.dict.nonexisting.contains('abc')",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			Code:        "muser.dict.string.contains(muser.dict.string2)",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			Code:        "muser.dict.string.contains(muser.dict.string)",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "'<< hello world >>'.contains(muser.dict.string)",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "'<< hello + world >>'.contains(muser.dict.string)",
			ResultIndex: 1,
			Expectation: false,
		},
		{
			Code:        "'<< hello world >>'.contains([muser.dict.string])",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "'<< hello + world >>'.contains([muser.dict.string])",
			ResultIndex: 1,
			Expectation: false,
		},
	})
}

func TestBuiltinFunctionOverride(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		// This access the resource length property,
		// which overrides the builtin function `length`
		{
			Code:        "mos.groups.length",
			ResultIndex: 0, Expectation: int64(5),
		},
		// This calls the native builtin `length` function
		{
			Code:        "mos.groups.list.length",
			ResultIndex: 0, Expectation: int64(7),
		},
		// Same here, builtin `length` function
		{
			Code:        "muser.groups.length",
			ResultIndex: 0, Expectation: int64(2),
		},
	})
}

func TestArrayConcat(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "[] + []",
			ResultIndex: 0,
			Expectation: []any{},
		},
		{
			Code:        "[] + ['a']",
			ResultIndex: 0,
			Expectation: []any{"a"},
		},
		{
			Code:        "['a'] + []",
			ResultIndex: 0,
			Expectation: []any{"a"},
		},
		{
			Code:        "['a'] + ['b']",
			ResultIndex: 0,
			Expectation: []any{"a", "b"},
		},
		{
			Code:        "['a'] + ['b', 'c']",
			ResultIndex: 0,
			Expectation: []any{"a", "b", "c"},
		},
		{
			Code:        "['a', 'b'] + ['c']",
			ResultIndex: 0,
			Expectation: []any{"a", "b", "c"},
		},
		{
			Code:        "['a', 'b'] + [] + ['c']",
			ResultIndex: 0,
			Expectation: []any{"a", "b", "c"},
		},
	})
}

func TestAndShortCircuiting(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			// The value asserted here is the statement's own. What the case
			// proves is the absence next to it: `muser.error` errors whenever it
			// runs, and TestSimple requires no error, so a right side that ran
			// would fail this. It used to read the null that the executor seeds
			// in place of the skipped operand's datapoint; the operands of a
			// combinator are no longer collected at all (issue 10723).
			Code:        "false && muser.error",
			Expectation: false,
		},
		{
			Code:  "true && muser.error",
			Error: "this is an error from the mockprovider",
		},
	})
}

func TestResource_Empty_Panic_Issue6017(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "customGroups == empty || true",
			ResultIndex: 1,
			Expectation: true,
		},
		{
			Code:        "customGroups != empty || true",
			ResultIndex: 1,
			Expectation: true,
		},
	})
}

func TestMapRefLookup(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code: `
				x = {"foo": "bar"}
				y = "foo"; z = y;
				x[z] == "bar"
			`,
			ResultIndex: 2,
			Expectation: true,
		},
	})
}

func TestArrayMapMissingFileContent(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code: `
				["a"].map(file(_).content)
			`,
			ResultIndex: 0,
			Expectation: []any{nil},
		},
	})
}
