// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

func TestExpandTargets(t *testing.T) {
	t.Run("explicit list passes through", func(t *testing.T) {
		in := []string{DiscoveryServers, DiscoveryRedis}
		if got := expandTargets(in); !reflect.DeepEqual(got, in) {
			t.Fatalf("got %#v, want %#v", got, in)
		}
	})
	t.Run("all expands to every target", func(t *testing.T) {
		if got := expandTargets([]string{DiscoveryServers, DiscoveryAll}); !reflect.DeepEqual(got, AllDiscoveryTargets) {
			t.Fatalf("got %#v, want AllDiscoveryTargets", got)
		}
	})
	t.Run("auto expands to every target", func(t *testing.T) {
		if got := expandTargets([]string{DiscoveryAuto}); !reflect.DeepEqual(got, AllDiscoveryTargets) {
			t.Fatalf("got %#v, want AllDiscoveryTargets", got)
		}
	})
}

func TestMapToStringString(t *testing.T) {
	if got := mapToStringString(nil); got != nil {
		t.Fatalf("nil input: got %#v, want nil", got)
	}
	in := map[string]any{"a": "x", "n": 1, "b": "y"}
	got := mapToStringString(in)
	want := map[string]string{"a": "x", "b": "y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
