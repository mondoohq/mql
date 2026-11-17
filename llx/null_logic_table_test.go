// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

// logicSamples are values of one type for the two sides of && and ||: some
// truthy, some falsy, and null.
func logicSamples(typ types.Type) []*RawData {
	now := time.Unix(1700000000, 0).UTC()
	switch typ {
	case types.Bool:
		return []*RawData{BoolData(true), BoolData(false), {Type: types.Bool}}
	case types.Int:
		return []*RawData{IntData(1), IntData(0), {Type: types.Int}}
	case types.Float:
		return []*RawData{FloatData(1.5), FloatData(0), {Type: types.Float}}
	case types.String:
		return []*RawData{StringData("a"), StringData(""), {Type: types.String}}
	case types.Regex:
		return []*RawData{RegexData("a"), RegexData(""), {Type: types.Regex}}
	case types.Time:
		return []*RawData{TimeData(now), {Type: types.Time}}
	case types.Dict:
		return []*RawData{
			DictData(true), DictData(false), DictData(int64(1)), DictData(int64(0)),
			DictData("a"), DictData(""), DictData([]any{int64(1)}), DictData([]any{}),
			DictData(map[string]any{"a": int64(1)}), DictData(map[string]any{}), {Type: types.Dict},
		}
	case types.ArrayLike:
		// No empty list: whether one is truthy differs between the builtins
		// today (it is next to a bool, it is not next to a number), and is
		// not what this test is about.
		return []*RawData{ArrayData([]any{int64(1)}, types.Int), {Type: types.Array(types.Int)}}
	case types.MapLike:
		typ := types.Map(types.String, types.Int)
		return []*RawData{
			MapData(map[string]any{"a": int64(1)}, types.Int), MapData(map[string]any{}, types.Int), {Type: typ},
		}
	}
	return nil
}

// logicTruthy is what one side of && or || counts as: null is falsy, a number
// is truthy unless it is zero, a string, list or map unless it is empty, and
// a time always.
func logicTruthy(value any) bool {
	switch x := value.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) != 0
	case map[string]any:
		return len(x) != 0
	case *time.Time:
		return x != nil
	}
	return false
}

// A null side of && or || is falsy, whatever the types of the two sides. This
// goes through every && and || in the table of builtins and holds each to the
// truthiness of its two sides: `a && b` is true exactly if both are truthy,
// `a || b` if either is.
func TestLogicFollowsTruthinessForEveryPairOfTypes(t *testing.T) {
	var lefts []types.Type
	for typ := range BuiltinFunctionsV2 {
		lefts = append(lefts, typ)
	}
	sort.Slice(lefts, func(i, j int) bool { return lefts[i] < lefts[j] })

	handlers := 0
	for _, lt := range lefts {
		var ids []string
		for id := range BuiltinFunctionsV2[lt] {
			if strings.Contains(id, "&&") || strings.Contains(id, "||") {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)

		for _, id := range ids {
			handler := BuiltinFunctionsV2[lt][id]
			if handler.f == nil {
				// An entry that only redirects the compiler to another one.
				continue
			}
			// The id is the operator and the type of the right side. For a
			// list it starts with the type of the list's items.
			at := strings.Index(id, "&&")
			if at < 0 {
				at = strings.Index(id, "||")
			}
			op, rt := id[at:at+2], types.Type(id[at+2:])
			leftSamples, rightSamples := logicSamples(lt), logicSamples(rt)
			require.NotEmpty(t, leftSamples, "no samples for the left type %s", lt.Label())
			require.NotEmpty(t, rightSamples, "no samples for the right type %s", rt.Label())
			handlers++

			t.Run(lt.Label()+" "+op+" "+rt.Label()+" ("+types.Type(id[:at]).Label()+")", func(t *testing.T) {
				for _, left := range leftSamples {
					for _, right := range rightSamples {
						want := logicTruthy(left.Value) && logicTruthy(right.Value)
						if op == "||" {
							want = logicTruthy(left.Value) || logicTruthy(right.Value)
						}

						chunk := &Chunk{Function: &Function{Args: []*Primitive{right.Result().Data}}}
						text := fmt.Sprintf("%v %s %v", left.Value, op, right.Value)
						require.NotPanics(t, func() {
							res, _, err := handler.f(newTestBlockExecutor(), left, chunk, 0)
							require.NoError(t, err)
							require.NoError(t, res.Error)
							assert.Equal(t, want, res.Value, text)
						}, text)
					}
				}
			})
		}
	}
	// Guards against the walk above silently finding nothing.
	assert.Greater(t, handlers, 100)
}
