// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"strings"
	"testing"

	"go.mondoo.com/mql/types"
)

// ref builds an absolute ref from a 1-based block and chunk index.
func ref(block, chunk uint32) uint64 {
	return (uint64(block) << 32) | uint64(chunk)
}

func testExecutor() *blockExecutor {
	code := &CodeV2{
		Id: "testcode",
		Blocks: []*Block{
			{Chunks: []*Chunk{
				{Call: Chunk_FUNCTION, Id: "aws.ec2.instances", Function: &Function{Type: string(types.Array(types.Resource("aws.ec2.instance")))}},
				{Call: Chunk_FUNCTION, Id: "where", Function: &Function{Type: string(types.Array(types.Resource("aws.ec2.instance"))), Binding: ref(1, 1)}},
				{Call: Chunk_FUNCTION, Id: "==", Function: &Function{Type: string(types.Bool), Binding: ref(1, 2)}},
			}},
		},
		Checksums: map[uint64]string{
			ref(1, 3): "abc123",
		},
	}
	exec := &MQLExecutorV2{id: "exec-id", code: code}
	return &blockExecutor{id: "exec-id/1", blockRef: ref(1, 0), ctx: exec}
}

func TestRefContext(t *testing.T) {
	b := testExecutor()
	got := b.refContext(ref(1, 3))

	for _, want := range []string{
		"ref=1:3",
		"codeID=testcode",
		"checksum=abc123",
		"expr=aws.ec2.instances.where.==",
		"executor=exec-id/1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("refContext() = %q, missing %q", got, want)
		}
	}
}

func TestRefContextDefensive(t *testing.T) {
	b := testExecutor()
	// A ref pointing at a block that doesn't exist must not panic; it should
	// still return the coordinates plus a graceful note.
	got := b.refContext(ref(9, 9))

	if !strings.Contains(got, "ref=9:9") {
		t.Errorf("refContext() = %q, missing coordinates", got)
	}
	if !strings.Contains(got, "further context unavailable") {
		t.Errorf("refContext() = %q, expected graceful recovery note", got)
	}
}

func TestDescribeRefDepthBound(t *testing.T) {
	b := testExecutor()
	// maxDepth of 1 should stop before resolving the full chain.
	got := b.describeRef(ref(1, 3), 1)
	if !strings.Contains(got, "==") || !strings.Contains(got, "…") {
		t.Errorf("describeRef(depth=1) = %q, expected truncated chain ending in '=='", got)
	}
}
