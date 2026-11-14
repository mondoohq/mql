// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package format

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormat(t *testing.T) {
	cases := []struct {
		name, in, out string
	}{
		{
			"chained calls indent under their resource",
			"github.repository.branches\n.where( isDefault == true )\n.all( isProtected == true )",
			"github.repository.branches\n  .where(isDefault == true)\n  .all(isProtected == true)",
		},
		{
			"operator spacing",
			"a==1&&b!=  2||c<=3",
			"a == 1 && b != 2 || c <= 3",
		},
		{
			"split operators merge like the parser reads them",
			"a = = 1 & & b ! = 2",
			"a == 1 && b != 2",
		},
		{
			"unary minus stays attached, binary minus spaced",
			"a.where(x == -1) && b-1 > [1, -2][0]",
			"a.where(x == -1) && b - 1 > [1, -2][0]",
		},
		{
			"blocks get inner padding",
			"users.where(name == 'root'){name   uid}",
			"users.where(name == 'root') { name uid }",
		},
		{
			"empty literals stay tight",
			"x == [] && y == {} && f( )",
			"x == [] && y == {} && f()",
		},
		{
			"nested brackets indent one level per line",
			"terraform.resources(\"x\").all(\nblocks.where( type == \"a\" ).all(\nblocks.where( type == \"b\" ).all( arguments.k != empty )\n)\n)",
			"terraform.resources(\"x\").all(\n  blocks.where(type == \"a\").all(\n    blocks.where(type == \"b\").all(arguments.k != empty)\n  )\n)",
		},
		{
			"trailing && keeps its place",
			"x.all(\n  a != empty &&\n      b != empty\n)",
			"x.all(\n  a != empty &&\n  b != empty\n)",
		},
		{
			"comments are kept and blank lines collapse",
			"# check users\n\n\n\nusers.all( uid > 0 ) // non-root\n\n# done",
			"# check users\n\nusers.all(uid > 0) // non-root\n\n# done",
		},
		{
			"a group on its own line stays a group",
			"x\n(y)",
			"x\n(y)",
		},
		{
			"a group after a comment stays a group",
			"x // note\n(y)",
			"x // note\n(y)",
		},
		{
			"regex and string tokens are untouched",
			"name == /^foo(  bar )$/i && path == 'C:\\  x\\' && s == \"a  ( b\"",
			"name == /^foo(  bar )$/i && path == 'C:\\  x\\' && s == \"a  ( b\"",
		},
		{
			"conditional chains",
			"a ?.b? [ \"k\" ] ?. c",
			"a?.b?[\"k\"]?.c",
		},
		{
			"named arguments and maps",
			"f( name : \"x\" , n:1 ) && m == {a :1,\"b\": 2}",
			"f(name: \"x\", n: 1) && m == { a: 1, \"b\": 2 }",
		},
		{
			"if and return read as keywords",
			"if(a.length > 0) {\n  return[1, 2]\n}\nreturn -1",
			"if (a.length > 0) {\n  return [1, 2]\n}\nreturn -1",
		},
		{
			"a chain with trailing dots indents like one with leading dots",
			"dns.mx.where(domainName == /x/).\nmap(domainName.downcase).\ncontainsOnly([\"a\"])",
			"dns.mx.where(domainName == /x/).\n  map(domainName.downcase).\n  containsOnly([\"a\"])",
		},
		{
			"switch",
			"switch {\ncase a == 1 :\n  b\ndefault :\n  c\n}",
			"switch {\n  case a == 1:\n    b\n  default:\n    c\n}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Format(c.in)
			require.NoError(t, err)
			assert.Equal(t, c.out, got)

			again, err := Format(got)
			require.NoError(t, err)
			assert.Equal(t, got, again, "formatting is not idempotent")
		})
	}
}

func TestFormatBreaksLongLines(t *testing.T) {
	cases := []struct {
		name, in, out string
	}{
		{
			"long chain breaks into links, then the widest argument opens",
			`terraform.plan.resourceChanges.where( type == "aws_security_group" && change.after.ingress.contains( to_port == 22 )).none( change.after.ingress.where(to_port == 22).any(cidr_blocks.contains("0.0.0.0/0") || cidr_blocks.contains("::/0")))`,
			`terraform.plan.resourceChanges
  .where(type == "aws_security_group" && change.after.ingress.contains(to_port == 22))
  .none(
    change.after.ingress
      .where(to_port == 22)
      .any(cidr_blocks.contains("0.0.0.0/0") || cidr_blocks.contains("::/0"))
  )`,
		},
		{
			"top-level && breaks first, operator stays at the end",
			`aws.ec2.instances.where(state == "running").all(monitoringState == "enabled") && aws.ec2.volumes.all(encrypted == true)`,
			`aws.ec2.instances.where(state == "running").all(monitoringState == "enabled") &&
aws.ec2.volumes.all(encrypted == true)`,
		},
		{
			"a short head keeps its first call",
			`terraform.resources("aws_db_instance").all(arguments.storage_encrypted == true && arguments.kms_key_id != empty && arguments.deletion_protection == true)`,
			`terraform.resources("aws_db_instance").all(
  arguments.storage_encrypted == true &&
  arguments.kms_key_id != empty &&
  arguments.deletion_protection == true
)`,
		},
		{
			"arguments break after commas",
			`x.in(["aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccc", "dddddddddddddddddddddd"])`,
			`x.in(
  [
    "aaaaaaaaaaaaaaaaaaaa",
    "bbbbbbbbbbbbbbbbbbbbbbbb",
    "cccccccccccccccccccccc",
    "dddddddddddddddddddddd"
  ]
)`,
		},
		{
			"a block opens; its fields stay together once they fit",
			`users.where(name != "root" && shell != "/sbin/nologin") { name uid gid home shell enabled authorizedkeys }`,
			`users.where(name != "root" && shell != "/sbin/nologin") {
  name uid gid home shell enabled authorizedkeys
}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Format(c.in)
			require.NoError(t, err)
			assert.Equal(t, c.out, got)

			again, err := Format(got)
			require.NoError(t, err)
			assert.Equal(t, got, again, "formatting is not idempotent")
		})
	}
}

func TestFormatKeepsUnparseableInput(t *testing.T) {
	in := "users.where( name == "
	got, err := Format(in)
	assert.Error(t, err)
	assert.Equal(t, in, got)
}
