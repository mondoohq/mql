// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package printer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/utils/sortx"
)

var x = testutils.InitTester(testutils.LinuxMock())

func init() {
	logger.InitTestEnv()
}

func testQuery(t *testing.T, query string) (*llx.CodeBundle, map[string]*llx.RawResult) {
	codeBundle, err := x.Compile(query)
	require.NoError(t, err)

	results, err := x.ExecuteCode(codeBundle, nil)
	require.NoError(t, err)

	return codeBundle, results
}

type simpleTest struct {
	code     string
	expected string
	results  []string
}

func runSimpleTests(t *testing.T, tests []simpleTest) {
	for i := range tests {
		cur := tests[i]
		t.Run(cur.code, func(t *testing.T) {
			bundle, results := testQuery(t, cur.code)

			s := DefaultPrinter.CodeBundle(bundle)
			if cur.expected != "" {
				assert.Equal(t, cur.expected, s)
			}

			length := len(results)

			assert.Equal(t, length, len(cur.results), "make sure the right number of results are returned")

			keys := sortx.Keys(results)
			for idx, id := range keys {
				result := results[id]
				s = DefaultPrinter.Result(result, bundle)
				assert.Equal(t, cur.results[idx], s)
			}
		})
	}
}

type assessmentTest struct {
	code   string
	result string
}

func runAssessmentTests(t *testing.T, tests []assessmentTest) {
	schemaPrinter := DefaultPrinter
	schema := x.Runtime.Schema()
	schemaPrinter.SetSchema(schema)
	for i := range tests {
		cur := tests[i]
		t.Run(cur.code, func(t *testing.T) {
			bundle, resultsMap := testQuery(t, cur.code)

			raw := schemaPrinter.Results(bundle, resultsMap)
			assert.Equal(t, cur.result, raw)
		})
	}
}

func TestPrinter(t *testing.T) {
	runSimpleTests(t, []simpleTest{
		{
			"if ( mondoo.version != null ) { mondoo.build }",
			"", // ignore
			[]string{
				"mondoo.version: \"v14.0.0+rolling\"",
				"if: {\n" +
					"  mondoo.build: \"development\"\n" +
					"}",
			},
		},
		{
			"file('zzz') { content }",
			"",
			[]string{
				"file: {\n  content: null\n}",
			},
		},
		{
			"[]",
			"", // ignore
			[]string{
				"[]",
			},
		},
		{
			"{}",
			"", // ignore
			[]string{
				"{}",
			},
		},
		{
			"['1-2'] { _.split('-') }",
			"", // ignore
			[]string{
				"[\n" +
					"  0: {\n" +
					"    split: [\n" +
					"      0: \"1\"\n" +
					"      1: \"2\"\n" +
					"    ]\n" +
					"  }\n" +
					"]",
			},
		},
		{
			"mondoo { version }",
			"-> block 1\n   entrypoints: [<1,2>]\n   1: mondoo \n   2: {} bind: <1,1> type:block (=> <2,0>)\n-> block 2\n   entrypoints: [<2,2>]\n   1: context\n   2: version bind: <2,1> type:string\n",
			[]string{
				"mondoo: {\n  version: \"v14.0.0+rolling\"\n}",
			},
		},
		{
			"mondoo { _.version }",
			"-> block 1\n   entrypoints: [<1,2>]\n   1: mondoo \n   2: {} bind: <1,1> type:block (=> <2,0>)\n-> block 2\n   entrypoints: [<2,2>]\n   1: context\n   2: version bind: <2,1> type:string\n",
			[]string{
				"mondoo: {\n  version: \"v14.0.0+rolling\"\n}",
			},
		},
		{
			"[1].where( _ > 0 )",
			"-> block 1\n   entrypoints: [<1,2>]\n   1: [\n     0: 1\n   ]\n   2: where bind: <1,1> type:[]int (ref<1,1>, => <2,0>)\n-> block 2\n   entrypoints: [<2,2>]\n   1: _\n   2: >\005 bind: <2,1> type:bool (0)\n",
			[]string{
				"where: [\n  0: 1\n]",
			},
		},
		{
			"a = 3\n if(true) {\n a == 3 \n}",
			"-> block 1\n   entrypoints: [<1,2>]\n   1: 3\n   2: if bind: <0,0> type:block (true, => <2,0>, [\n     0: ref<1,1>\n   ])\n-> block 2\n   entrypoints: [<2,2>] datapoints: [<2,1>]\n   1: ref<1,1>\n   2: ==\x05 bind: <2,1> type:bool (3)\n",
			[]string{"if: {\n  a == 3: true\n}"},
		},
		{
			"mondoo",
			"", // ignore
			[]string{
				"mondoo: version=\"v14.0.0+rolling\"",
			},
		},
		{
			"users",
			"", // ignore
			[]string{
				"users.list: [\n" +
					"  0: name=\"root\" uid=0 gid=0\n" +
					"  1: name=\"bin\" uid=1 gid=1\n" +
					"  2: name=\"chris\" uid=1000 gid=1000\n" +
					"  3: name=\"christopher\" uid=1001 gid=1000\n" +
					"]",
			},
		},
		{
			"ip(\"\")",
			"", // ignore
			[]string{
				"ip: null",
			},
		},
		{
			"ip(\"1.2.3.4\")",
			"", // ignore
			[]string{
				"ip: 1.2.3.4",
			},
		},
	})
}

func TestPrinter_Assessment(t *testing.T) {
	runAssessmentTests(t, []assessmentTest{
		{
			// [dom] This query caused a crash in the assessment generation
			"parse.json(\"/dummy.json\").params.f.where(ff == 3) != empty\nparse.json(\"/dummy.json\").params.f.where(ff == 3).all(ff < 0)",
			strings.Join([]string{
				"[failed] parse.json(\"/dummy.json\").params.f.where(ff == 3) != empty",
				"parse.json(\"/dummy.json\").params.f.where(ff == 3).all(ff < 0)",
				"  [ok] value: [",
				"    0: {",
				"      ff: 3.000000",
				"    }",
				"  ]",
				"  [failed] [].all()",
				"    actual:   [",
				"      0: {",
				"        ff: 3.000000",
				"      }",
				"    ]",
				"",
			}, "\n"),
		},
		{
			// mixed use: assertion and erroneous data field
			"mondoo.build == 1; user(name: 'notthere').authorizedkeys.file",
			strings.Join([]string{
				"[failed] mondoo.build == 1; user(name: 'notthere').authorizedkeys.file",
				"  [failed] mondoo.build == 1",
				"    expected: == 1",
				"    actual:   \"development\"",
				"  [failed] user.authorizedkeys.file",
				"    error: cannot find user with name 'notthere'",
				"",
			}, "\n"),
		},
		{
			// mixed use: assertion and working data field
			"mondoo.build == 1; mondoo.version",
			strings.Join([]string{
				"[failed] mondoo.build == 1; mondoo.version",
				"  [failed] mondoo.build == 1",
				"    expected: == 1",
				"    actual:   \"development\"",
				"  [ok] value: \"v14.0.0+rolling\"",
				"",
			}, "\n"),
		},
		{
			"[1,2,3].\n" +
				"# @msg Found ${length} numbers\n" +
				"none( _ > 1 )",
			strings.Join([]string{
				"[failed] Found 2 numbers",
				"",
			}, "\n"),
		},
		{
			"# @msg Expected ${$expected.length} users but got ${length}\n" +
				"users.none( uid == 0 )",
			strings.Join([]string{
				"[failed] Expected 4 users but got 1",
				"",
			}, "\n"),
		},
		{
			"mondoo.build == 1",
			strings.Join([]string{
				"[failed] mondoo.build == 1",
				"  expected: == 1",
				"  actual:   \"development\"",
				"",
			}, "\n"),
		},
		{
			// same at the top level: the label carries the statement, and there
			// is nothing measured to put around the operator
			"mondoo.build == 1 || mondoo.version == 1",
			strings.Join([]string{
				"[failed] mondoo.build == 1 || <ref>",
				"",
			}, "\n"),
		},
		{
			"sshd.config { params['test'] }",
			strings.Join([]string{
				"sshd.config: {",
				"  params[test]: null",
				"}",
			}, "\n"),
		},
		{
			"mondoo.build == 1;mondoo.version =='v14.0.0+rolling';",
			strings.Join([]string{
				"[failed] mondoo.build == 1;mondoo.version =='v14.0.0+rolling';",
				"  [failed] mondoo.build == 1",
				"    expected: == 1",
				"    actual:   \"development\"",
				"  [ok] value: \"v14.0.0+rolling\"",
				"",
			}, "\n"),
		},
		{
			"if(true) {\n" +
				"  # @msg Expected ${$expected.length} users but got ${length}\n" +
				"  users.none( uid == 0 )\n" +
				"}",
			strings.Join([]string{
				"if: {",
				"  [failed] Expected 4 users but got 1",
				"  users.where.list: [",
				"    0: name=\"root\" uid=0 gid=0",
				"  ]",
				"}",
			}, "\n"),
		},
		{
			"users.list.duplicates(gid).none()\n",
			strings.Join([]string{
				"[failed] [].none()",
				"  actual:   [",
				"    0: user name=\"christopher\" gid=1000 uid=1001 ",
				"    1: user name=\"chris\" gid=1000 uid=1000 ",
				"  ]",
				"",
			}, "\n"),
		},
		{
			"users.all( uid < 1000 )\n",
			strings.Join([]string{
				"[failed] users.all()",
				"  actual:   [",
				"    0: user uid=1000 gid=1000 name=\"chris\" ",
				"    1: user uid=1001 gid=1000 name=\"christopher\" ",
				"  ]",
				"",
			}, "\n"),
		},
		{
			"users.all( 1000 > uid )\n",
			strings.Join([]string{
				"[failed] users.all()",
				"  actual:   [",
				"    0: user name=\"chris\" uid=1000 gid=1000 ",
				"    1: user name=\"christopher\" uid=1001 gid=1000 ",
				"  ]",
				"",
			}, "\n"),
		},
		{
			"users.all( uid == 0 && enabled == true )\n",
			strings.Join([]string{
				"[failed] users.all()",
				"  actual:   [",
				"    0: user gid=0 name=\"root\" uid=0 {",
				"      [failed] enabled",
				"        expected: == true",
				"        actual:   false",
				"    }",
				"    1: user gid=1 name=\"bin\" uid=1 {",
				"      [failed] enabled",
				"        expected: == true",
				"        actual:   false",
				"    }",
				"    2: user gid=1000 name=\"chris\" uid=1000 {",
				"      [failed] enabled",
				"        expected: == true",
				"        actual:   false",
				"    }",
				"    3: user gid=1000 name=\"christopher\" uid=1001 {",
				"      [failed] enabled",
				"        expected: == true",
				"        actual:   false",
				"    }",
				"  ]",
				"",
			}, "\n"),
		},
		{
			"users.none( '/root' == home ); users.all( name != 'root' )\n",
			strings.Join([]string{
				"[failed] users.none( '/root' == home ); users.all( name != 'root' )",
				"",
				"  [failed] users.none()",
				"    actual:   [",
				"      0: user gid=0 name=\"root\" uid=0 {",
				"        home: \"/root\"",
				"      }",
				"    ]",
				"  [failed] users.all()",
				"    actual:   [",
				"      0: user name=\"root\" uid=0 gid=0 ",
				"    ]",
				"",
			}, "\n"),
		},
		// FIXME: these tests aren't working right in the current iteration.
		// There is also something else a bit weird, namely it uses `groups`
		// which is not a child field of the `user` resource. I'd love to restore
		// these.
		// {
		// 	"users.all(groups.none(gid==0))\n",
		// 	strings.Join([]string{
		// 		"[failed] users.all()",
		// 		"  actual:   [",
		// 		"    0: user uid=0 gid=0 name=\"root\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"    1: user uid=1000 gid=1001 name=\"chris\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"    2: user uid=1000 gid=1001 name=\"christopher\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"    3: user uid=1002 gid=1003 name=\"chris\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"    4: user uid=1 gid=1 name=\"bin\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"  ]",
		// 		"",
		// 	}, "\n"),
		// },
		// {
		// 	"users.all(groups.all(name == 'root'))\n",
		// 	strings.Join([]string{
		// 		"[failed] users.all()",
		// 		"  actual:   [",
		// 		"    0: user uid=0 gid=0 name=\"root\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"    1: user uid=1000 gid=1001 name=\"chris\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"    2: user uid=1000 gid=1001 name=\"christopher\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"    3: user uid=1002 gid=1003 name=\"chris\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"    4: user uid=1 gid=1 name=\"bin\" {",
		// 		"      groups.list: [",
		// 		"        0: user group id = group/0/root",
		// 		"        1: user group id = group/1001/chris",
		// 		"        2: user group id = group/90/network",
		// 		"        3: user group id = group/998/wheel",
		// 		"        4: user group id = group/5/tty",
		// 		"        5: user group id = group/2/daemon",
		// 		"      ]",
		// 		"      groups: groups id = groups",
		// 		"    }",
		// 		"  ]",
		// 		"",
		// 	}, "\n"),
		// },
		{
			"users.all(sshkeys.length > 2)\n",
			strings.Join([]string{
				"[failed] users.all()",
				"  actual:   [",
				"    0: user name=\"root\" gid=0 uid=0 {",
				"      sshkeys: []",
				"      sshkeys.length: 0",
				"    }",
				"    1: user name=\"bin\" gid=1 uid=1 {",
				"      sshkeys: []",
				"      sshkeys.length: 0",
				"    }",
				"    2: user name=\"chris\" gid=1000 uid=1000 {",
				"      sshkeys: []",
				"      sshkeys.length: 0",
				"    }",
				"    3: user name=\"christopher\" gid=1000 uid=1001 {",
				"      sshkeys: []",
				"      sshkeys.length: 0",
				"    }",
				"  ]",
				"",
			}, "\n"),
		},
	})
}

func TestPrinter_Blocks(t *testing.T) {
	runSimpleTests(t, []simpleTest{
		{
			"['a', 'b'] { x=_ \n x }",
			"", // ignore
			[]string{
				strings.Join([]string{
					"[",
					"  0: {",
					"    x: \"a\"",
					"  }",
					"  1: {",
					"    x: \"b\"",
					"  }",
					"]",
				}, "\n"),
			},
		},
		{
			"['a', 'b'] { x=_ \n x == 'a' }",
			"", // ignore
			[]string{
				strings.Join([]string{
					"[",
					"  0: {",
					"    x == \"a\": true",
					"  }",
					"  1: {",
					"    [failed] x == \"a\"",
					"      expected: == \"a\"",
					"      actual:   \"b\"",
					"  }",
					"]",
				}, "\n"),
			},
		},
		{
			// A combinator reports only its own value. Its operands are whole
			// statements, and the right one may never have run, so there is no
			// pair of values to put on either side of the operator. Reporting
			// them used to cost the short circuit its guarantee (issue 10723).
			"['a', 'b'] { x=_ \n x == 'a' || x == 'c' }",
			"", // ignore
			[]string{
				strings.Join([]string{
					"[",
					"  0: {",
					"    x == \"a\" || <ref>: true",
					"  }",
					"  1: {",
					"    [failed] x == \"a\" || <ref>",
					"  }",
					"]",
				}, "\n"),
			},
		},
	})
}

func TestPrinter_Buggy(t *testing.T) {
	runSimpleTests(t, []simpleTest{
		{
			"mondoo",
			"", // ignore
			[]string{
				"mondoo: version=\"v14.0.0+rolling\"",
			},
		},
	})
}
