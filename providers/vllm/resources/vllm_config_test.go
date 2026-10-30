// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func isNull(state plugin.State) bool {
	return state&plugin.StateIsNull != 0 && state&plugin.StateIsSet != 0
}

// A value the server never reported must render as null. MQL evaluates
// `null && null` to true, so a fabricated false on a posture field would turn
// an unobserved server into a passing assertion.
func TestFieldRenderersKeepUnreportedValuesNull(t *testing.T) {
	t.Run("bool", func(t *testing.T) {
		field := plugin.TValue[bool]{}
		got, err := boolField(&field, nil)
		if err != nil || got {
			t.Fatalf("got (%v,%v)", got, err)
		}
		if !isNull(field.State) {
			t.Fatalf("state got %v, want resolved-and-null", field.State)
		}

		set := plugin.TValue[bool]{}
		value := true
		if got, _ := boolField(&set, &value); !got {
			t.Fatal("a reported true must render as true")
		}
		if isNull(set.State) {
			t.Fatal("a reported value must not render as null")
		}
	})

	t.Run("string", func(t *testing.T) {
		field := plugin.TValue[string]{}
		if got, _ := stringField(&field, nil); got != "" || !isNull(field.State) {
			t.Fatalf("got %q state %v", got, field.State)
		}
		// An empty string is the same absence as a missing key: vLLM writes an
		// unset quantization or tokenizer as null, and some renderings write it
		// as "".
		empty := ""
		blank := plugin.TValue[string]{}
		if got, _ := stringField(&blank, &empty); got != "" || !isNull(blank.State) {
			t.Fatalf("got %q state %v", got, blank.State)
		}
	})

	t.Run("int", func(t *testing.T) {
		field := plugin.TValue[int64]{}
		if got, _ := intField(&field, nil); got != 0 || !isNull(field.State) {
			t.Fatalf("got %d state %v", got, field.State)
		}
	})

	t.Run("dict", func(t *testing.T) {
		field := plugin.TValue[any]{}
		if got, _ := dictField(&field, nil); got != nil || !isNull(field.State) {
			t.Fatalf("got %v state %v", got, field.State)
		}
	})
}

// An unread list and a list that was read and came back empty are different
// answers. "The metrics endpoint refused me" must not render the same as
// "the metrics endpoint disclosed no adapters".
func TestStringListFieldSeparatesUnreadFromEmpty(t *testing.T) {
	unread := plugin.TValue[[]any]{}
	got, err := stringListField(&unread, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("got %v want nil", got)
	}
	if !isNull(unread.State) {
		t.Fatalf("an unread list must render as null, state %v", unread.State)
	}

	empty := plugin.TValue[[]any]{}
	got, err = stringListField(&empty, []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("got %v want an empty list", got)
	}
	if isNull(empty.State) {
		t.Fatal("an observed empty list must not render as null")
	}

	filled := plugin.TValue[[]any]{}
	got, err = stringListField(&filled, []string{"alpha", "beta"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("got %v", got)
	}
}

// A name/value set that was never read renders as null, and one that was read
// and carried nothing renders as an empty map. Collapsing the two would report
// "the engine discloses no cache settings" for a server nobody could scrape.
func TestStringMapFieldSeparatesUnreadFromEmpty(t *testing.T) {
	unread := plugin.TValue[map[string]any]{}
	got, err := stringMapField(&unread, nil)
	if err != nil || got != nil {
		t.Fatalf("got (%v,%v), want (nil,nil)", got, err)
	}
	if !isNull(unread.State) {
		t.Fatalf("state got %v, want resolved-and-null", unread.State)
	}

	empty := plugin.TValue[map[string]any]{}
	got, err = stringMapField(&empty, map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("got %v, want an empty map", got)
	}
	if isNull(empty.State) {
		t.Fatal("a scrape that answered must not render as null")
	}

	filled := plugin.TValue[map[string]any]{}
	got, err = stringMapField(&filled, map[string]string{"block_size": "16"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["block_size"] != "16" {
		t.Fatalf("got %v, want block_size 16", got)
	}
	if isNull(filled.State) {
		t.Fatal("a reported value must not render as null")
	}
}
