// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

// contextChecksums are the synthetic checksum->label mappings used to build
// hand-crafted assessments for the tests below.
const (
	csContext = "ctx"
	csPath    = "p"
	csRange   = "r"
	csContent = "c"
	csType    = "t"
)

func testContextBundle() *CodeBundle {
	return &CodeBundle{
		Labels: &Labels{Labels: map[string]string{
			csContext: "context",
			csPath:    "path",
			csRange:   "range",
			csContent: "content",
			csType:    "type",
		}},
	}
}

// resourceBlock builds a resource block primitive carrying an auto-expanded
// context sub-block, mirroring what the engine collects for a failing resource.
func resourceBlock(path string, rng Range, content string) *Primitive {
	ctxBlock := &Primitive{
		Type: string(types.Block),
		Map: map[string]*Primitive{
			csPath:    StringPrimitive(path),
			csRange:   RangePrimitive(rng),
			csContent: StringPrimitive(content),
		},
	}
	return &Primitive{
		Type: string(types.Block),
		Map: map[string]*Primitive{
			csType:    StringPrimitive("resource"),
			csContext: ctxBlock,
		},
	}
}

func TestFailingResourceContexts(t *testing.T) {
	bundle := testContextBundle()
	rng := NewRange().AddLineColumnRange(12, 18, 1, 2)

	t.Run("nil inputs", func(t *testing.T) {
		assert.Nil(t, bundle.FailingResourceContexts(nil))
		assert.Nil(t, (*CodeBundle)(nil).FailingResourceContexts(&Assessment{}))
	})

	t.Run("single failing resource", func(t *testing.T) {
		a := &Assessment{Results: []*AssessmentItem{
			{Success: false, Actual: resourceBlock("main.tf", rng, "resource {}")},
		}}
		got := bundle.FailingResourceContexts(a)
		require.Len(t, got, 1)
		assert.Equal(t, "main.tf", got[0].Path)
		assert.Equal(t, "resource {}", got[0].Content)
		assert.Equal(t, rng.String(), got[0].Range.String())
	})

	t.Run("successful items are skipped", func(t *testing.T) {
		a := &Assessment{Results: []*AssessmentItem{
			{Success: true, Actual: resourceBlock("main.tf", rng, "resource {}")},
		}}
		assert.Empty(t, bundle.FailingResourceContexts(a))
	})

	t.Run("array of failing resources", func(t *testing.T) {
		arr := ArrayPrimitive([]*Primitive{
			resourceBlock("a.tf", rng, "a {}"),
			resourceBlock("b.tf", rng, "b {}"),
		}, types.Resource("terraform.block"))
		a := &Assessment{Results: []*AssessmentItem{
			{Success: false, Actual: arr},
		}}
		got := bundle.FailingResourceContexts(a)
		require.Len(t, got, 2)
		paths := []string{got[0].Path, got[1].Path}
		assert.ElementsMatch(t, []string{"a.tf", "b.tf"}, paths)
	})

	t.Run("multiple assertions each with its own resource", func(t *testing.T) {
		a := &Assessment{Results: []*AssessmentItem{
			{Success: false, Actual: resourceBlock("net.tf", rng, "net {}")},
			{Success: false, Actual: resourceBlock("iam.tf", rng, "iam {}")},
		}}
		got := bundle.FailingResourceContexts(a)
		require.Len(t, got, 2)
		assert.ElementsMatch(t, []string{"net.tf", "iam.tf"},
			[]string{got[0].Path, got[1].Path})
	})

	t.Run("context found in @msg data", func(t *testing.T) {
		a := &Assessment{Results: []*AssessmentItem{
			{Success: false, Data: []*Primitive{resourceBlock("msg.tf", rng, "x {}")}},
		}}
		got := bundle.FailingResourceContexts(a)
		require.Len(t, got, 1)
		assert.Equal(t, "msg.tf", got[0].Path)
	})

	t.Run("resource without context yields nothing", func(t *testing.T) {
		plain := &Primitive{Type: string(types.Block), Map: map[string]*Primitive{
			csType: StringPrimitive("resource"),
		}}
		a := &Assessment{Results: []*AssessmentItem{{Success: false, Actual: plain}}}
		assert.Empty(t, bundle.FailingResourceContexts(a))
	})
}

func TestParseSourceContext(t *testing.T) {
	bundle := testContextBundle()
	rng := NewRange().AddLine(7)

	t.Run("full context", func(t *testing.T) {
		block := map[string]any{
			csPath:    StringData("x.tf"),
			csRange:   &RawData{Type: types.Range, Value: rng},
			csContent: StringData("body"),
		}
		sc, ok := bundle.ParseSourceContext(block)
		require.True(t, ok)
		assert.Equal(t, "x.tf", sc.Path)
		assert.Equal(t, "body", sc.Content)
		assert.Equal(t, rng.String(), sc.Range.String())
	})

	t.Run("empty block", func(t *testing.T) {
		_, ok := bundle.ParseSourceContext(map[string]any{})
		assert.False(t, ok)
	})

	t.Run("non-map", func(t *testing.T) {
		_, ok := bundle.ParseSourceContext("not a map")
		assert.False(t, ok)
	})
}
