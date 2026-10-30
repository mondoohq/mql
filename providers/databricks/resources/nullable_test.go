// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/databricks/databricks-sdk-go/service/settings"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The nullable helpers are what stand between "the API did not answer" and a
// fabricated zero value. A toggle that reads false when nothing was read makes
// `enableResultsDownloading == false` pass on a workspace nobody looked at, so
// each helper is pinned on both the absent and the present case, including the
// present-but-false case, which must stay a real false rather than becoming
// null.

func TestNullableBool(t *testing.T) {
	tr, fa := true, false

	tests := []struct {
		name      string
		in        *bool
		wantNull  bool
		wantValue bool
	}{
		{name: "absent is null, not false", in: nil, wantNull: true},
		{name: "false stays false", in: &fa, wantValue: false},
		{name: "true stays true", in: &tr, wantValue: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var state plugin.State
			got, err := nullableBool(tc.in, &state)
			if err != nil {
				t.Fatalf("nullableBool() error = %v", err)
			}
			isNull := state&plugin.StateIsNull != 0
			if isNull != tc.wantNull {
				t.Fatalf("nullableBool() null = %v, want %v", isNull, tc.wantNull)
			}
			if tc.wantNull {
				if state&plugin.StateIsSet == 0 {
					t.Fatal("a null field must also be marked set, or the runtime recomputes it")
				}
				return
			}
			if state != 0 {
				t.Fatalf("nullableBool() touched state = %v for a present value", state)
			}
			if got != tc.wantValue {
				t.Fatalf("nullableBool() = %v, want %v", got, tc.wantValue)
			}
		})
	}
}

func TestNullableString(t *testing.T) {
	empty := ""
	value := "RESTRICT_TOKENS_AND_JOB_RUN_AS"

	tests := []struct {
		name      string
		in        *string
		wantNull  bool
		wantValue string
	}{
		{name: "absent is null", in: nil, wantNull: true},
		// An empty string the API actually returned is a value, not an absence.
		{name: "empty string stays empty", in: &empty, wantValue: ""},
		{name: "value is passed through", in: &value, wantValue: value},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var state plugin.State
			got, err := nullableString(tc.in, &state)
			if err != nil {
				t.Fatalf("nullableString() error = %v", err)
			}
			isNull := state&plugin.StateIsNull != 0
			if isNull != tc.wantNull {
				t.Fatalf("nullableString() null = %v, want %v", isNull, tc.wantNull)
			}
			if tc.wantNull {
				return
			}
			if got != tc.wantValue {
				t.Fatalf("nullableString() = %q, want %q", got, tc.wantValue)
			}
		})
	}
}

func TestNullableList(t *testing.T) {
	t.Run("nil slice is null", func(t *testing.T) {
		var state plugin.State
		got, err := nullableList(nil, &state)
		if err != nil {
			t.Fatalf("nullableList() error = %v", err)
		}
		if state&plugin.StateIsNull == 0 || state&plugin.StateIsSet == 0 {
			t.Fatalf("nullableList() state = %v, want set and null", state)
		}
		if got != nil {
			t.Fatalf("nullableList() = %v, want nil", got)
		}
	})

	// An allocated but empty slice is a real answer: the setting was read and
	// holds no entries. Turning it into null would lose that.
	t.Run("empty slice stays empty", func(t *testing.T) {
		var state plugin.State
		got, err := nullableList([]any{}, &state)
		if err != nil {
			t.Fatalf("nullableList() error = %v", err)
		}
		if state != 0 {
			t.Fatalf("nullableList() touched state = %v for a present empty list", state)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("nullableList() = %v, want an empty non-nil slice", got)
		}
	})

	t.Run("values pass through", func(t *testing.T) {
		var state plugin.State
		got, err := nullableList([]any{"HIPAA", "PCI_DSS"}, &state)
		if err != nil {
			t.Fatalf("nullableList() error = %v", err)
		}
		if len(got) != 2 || got[0] != "HIPAA" || got[1] != "PCI_DSS" {
			t.Fatalf("nullableList() = %v, want [HIPAA PCI_DSS]", got)
		}
	})
}

func TestBoolMessageValue(t *testing.T) {
	t.Run("absent message is null", func(t *testing.T) {
		if got := boolMessageValue(nil); got != nil {
			t.Fatalf("boolMessageValue(nil) = %v, want nil", *got)
		}
	})

	// The distinction this protects: a workspace that explicitly turned results
	// downloading off, versus a settings call that never answered. The first is
	// a false, the second has to stay null.
	t.Run("explicit false is a real false", func(t *testing.T) {
		got := boolMessageValue(&settings.BooleanMessage{Value: false})
		if got == nil {
			t.Fatal("boolMessageValue({false}) = nil, want a pointer to false")
		}
		if *got {
			t.Fatalf("boolMessageValue({false}) = %v, want false", *got)
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		got := boolMessageValue(&settings.BooleanMessage{Value: true})
		if got == nil || !*got {
			t.Fatalf("boolMessageValue({true}) = %v, want a pointer to true", got)
		}
	})

	// The returned pointer must not alias the caller's message, or a later
	// reuse of that message would rewrite an already-reported value.
	t.Run("does not alias its argument", func(t *testing.T) {
		msg := settings.BooleanMessage{Value: true}
		got := boolMessageValue(&msg)
		msg.Value = false
		if got == nil || !*got {
			t.Fatalf("boolMessageValue() aliased its argument: got %v", got)
		}
	})
}
