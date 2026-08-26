// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// relatedLabels returns the label tuples of a block's related() list, so tests
// can assert on the graph without caring about ordering.
func relatedLabels(t *testing.T, b *mqlTerraformBlock) map[string]bool {
	t.Helper()
	related, err := b.related()
	require.NoError(t, err)
	out := map[string]bool{}
	for i := range related {
		rb := related[i].(*mqlTerraformBlock)
		key := rb.Type.Data
		for _, l := range rb.Labels.Data {
			key += "." + l.(string)
		}
		out[key] = true
	}
	return out
}

// TestRelated_ResolvesPrefixedReferences is a regression test for related()
// only ever resolving managed-resource references.
//
// The lookup joined refs[0:2], which forms a valid key only for
// `<type>.<name>`. A `data.aws_ami.ubuntu.id` reference produced the key
// `data\x00aws_ami` while the data block's own id is `aws_ami\x00ubuntu`, so
// data sources, modules and variables never appeared in the graph at all.
func TestRelated_ResolvesPrefixedReferences(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
variable "instance_type" { default = "t3.micro" }

data "aws_ami" "ubuntu" { most_recent = true }

module "vpc" { source = "./modules/vpc" }

resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  subnet_id     = module.vpc.subnet_id
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	web := blockInDir(t, blocks, dir, ".", "aws_instance", "web")

	got := relatedLabels(t, web)
	assert.True(t, got["data.aws_ami.ubuntu"], "data.* reference must resolve, got: %v", got)
	assert.True(t, got["variable.instance_type"], "var.* reference must resolve, got: %v", got)
	assert.True(t, got["module.vpc"], "module.* reference must resolve, got: %v", got)

	// The inverse edges must be there too.
	ami := blockInDir(t, blocks, dir, ".", "aws_ami", "ubuntu")
	assert.True(t, relatedLabels(t, ami)["resource.aws_instance.web"],
		"the data source must relate back to the resource that uses it")
}

// TestRelated_ResolvesReferencesInsideNestedBlocks is a regression test for
// related() walking only body.Attributes. A reference written inside a nested
// block — the standard shape for a security-group rule — was never seen.
func TestRelated_ResolvesReferencesInsideNestedBlocks(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
resource "aws_security_group" "bastion" {
  name = "bastion"
}

resource "aws_security_group" "app" {
  name = "app"

  ingress {
    from_port       = 22
    to_port         = 22
    security_groups = [aws_security_group.bastion.id]
  }
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	app := blockInDir(t, blocks, dir, ".", "aws_security_group", "app")

	assert.True(t, relatedLabels(t, app)["resource.aws_security_group.bastion"],
		"a reference inside a nested block must be part of the related graph")
}

// TestRelated_ResolvesReferencesInsideExpressions is a regression test for
// getReferences() handling only bare ScopeTraversalExpr. References buried in a
// template, a list, a conditional or a function call were invisible.
func TestRelated_ResolvesReferencesInsideExpressions(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

resource "aws_s3_bucket" "data" {
  bucket = "data"
}

resource "aws_s3_bucket_policy" "p" {
  bucket    = "x-${aws_s3_bucket.logs.id}"
  targets   = [aws_s3_bucket.data.arn]
  encoded   = jsonencode({ b = aws_s3_bucket.logs.arn })
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	policy := blockInDir(t, blocks, dir, ".", "aws_s3_bucket_policy", "p")

	got := relatedLabels(t, policy)
	assert.True(t, got["resource.aws_s3_bucket.logs"],
		"a reference inside a template/function must resolve, got: %v", got)
	assert.True(t, got["resource.aws_s3_bucket.data"],
		"a reference inside a list must resolve, got: %v", got)
}

// TestRelated_DeduplicatesRepeatedReferences keeps the graph free of duplicate
// edges now that every traversal in an expression tree is walked: a block
// referenced twice must appear once.
func TestRelated_DeduplicatesRepeatedReferences(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "b" {
  bucket = "b"
}

resource "aws_s3_bucket_policy" "p" {
  bucket = aws_s3_bucket.b.id
  policy = aws_s3_bucket.b.arn
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	policy := blockInDir(t, blocks, dir, ".", "aws_s3_bucket_policy", "p")

	related, err := policy.related()
	require.NoError(t, err)
	assert.Len(t, related, 1, "a block referenced twice must produce one related edge")
}
