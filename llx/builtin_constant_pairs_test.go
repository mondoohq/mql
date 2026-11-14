// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/types"
)

// Some pairs of types can never be equal, or always are, and the table of
// builtins answers `==` and `!=` between them with a constant. The two
// constants have to be opposites: if `a == b` is always false, `a != b` is
// always true.
func TestConstantEqualityHasTheOppositeInequality(t *testing.T) {
	name := func(f any) string {
		if f == nil || reflect.ValueOf(f).IsNil() {
			return ""
		}
		switch reflect.ValueOf(f).Pointer() {
		case reflect.ValueOf(chunkEqTrueV2).Pointer():
			return "always true"
		case reflect.ValueOf(chunkEqFalseV2).Pointer():
			return "always false"
		case reflect.ValueOf(chunkNeqTrueV2).Pointer():
			return "always true"
		case reflect.ValueOf(chunkNeqFalseV2).Pointer():
			return "always false"
		}
		return "computed"
	}

	checked := 0
	var wrong []string
	for typ, handlers := range BuiltinFunctionsV2 {
		for id, eq := range handlers {
			if !strings.HasPrefix(id, "==") {
				continue
			}
			ne, ok := handlers["!="+strings.TrimPrefix(id, "==")]
			if !ok {
				continue
			}
			is, isNot := name(eq.f), name(ne.f)
			if is == "computed" || isNot == "computed" || is == "" || isNot == "" {
				continue
			}
			checked++
			if is == isNot {
				other := strings.TrimPrefix(id, "==")
				wrong = append(wrong, typ.Label()+" == and != "+types.Type(other).Label()+" are both "+is)
			}
		}
	}
	sort.Strings(wrong)
	assert.Empty(t, wrong)
	assert.Greater(t, checked, 20, "the table has constant pairs")
}
