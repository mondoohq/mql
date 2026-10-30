// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// kmsKey builds a bare key resource the way a listing would, without needing a
// runtime: the index only ever reads Id.
func kmsKey(id, keyRingId string) *mqlStackitKmsKey {
	return &mqlStackitKmsKey{
		Id:        plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
		KeyRingId: plugin.TValue[string]{Data: keyRingId, State: plugin.StateIsSet},
	}
}

func kmsKeyVersion(number int64) *mqlStackitKmsKeyVersion {
	return &mqlStackitKmsKeyVersion{
		Number: plugin.TValue[int64]{Data: number, State: plugin.StateIsSet},
	}
}

func iamRole(name string) *mqlStackitIamRole {
	return &mqlStackitIamRole{
		Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
	}
}

// setList marks a []any field as already computed so the generated getter
// returns it without reaching for a connection.
func setList(items []any) plugin.TValue[[]any] {
	return plugin.TValue[[]any]{Data: items, State: plugin.StateIsSet}
}

func TestIndexKmsKeysByID(t *testing.T) {
	const (
		ringA = "ring-a"
		ringB = "ring-b"
		keyA  = "11111111-1111-1111-1111-111111111111"
		keyB  = "22222222-2222-2222-2222-222222222222"
	)

	t.Run("keys from several rings land in one index", func(t *testing.T) {
		a := kmsKey(keyA, ringA)
		b := kmsKey(keyB, ringB)
		idx := indexKmsKeysByID([]any{a, b})

		if len(idx) != 2 {
			t.Fatalf("index size = %d, want 2", len(idx))
		}
		// a volume records only the bare UUID, so the ring-qualified key must
		// still be reachable by that UUID alone
		if got := idx[keyB]; got != b {
			t.Fatalf("idx[%q] = %v, want the ring-b key", keyB, got)
		}
		if got := idx[keyB]; got != nil && got.KeyRingId.Data != ringB {
			t.Fatalf("idx[%q].KeyRingId = %q, want %q", keyB, got.KeyRingId.Data, ringB)
		}
	})

	t.Run("miss returns nothing", func(t *testing.T) {
		idx := indexKmsKeysByID([]any{kmsKey(keyA, ringA)})
		if got, ok := idx["33333333-3333-3333-3333-333333333333"]; ok || got != nil {
			t.Fatalf("lookup of an unknown key = (%v, %v), want (nil, false)", got, ok)
		}
	})

	t.Run("empty ids, nils, and foreign entries are skipped", func(t *testing.T) {
		idx := indexKmsKeysByID([]any{
			kmsKey("", ringA),
			(*mqlStackitKmsKey)(nil),
			iamRole("some.role"),
			"not a resource",
			nil,
			kmsKey(keyA, ringA),
		})
		if len(idx) != 1 {
			t.Fatalf("index size = %d, want 1 (only the well-formed key)", len(idx))
		}
		if _, ok := idx[""]; ok {
			t.Fatal("index holds an entry under the empty key id")
		}
	})

	t.Run("first key wins on a duplicate uuid", func(t *testing.T) {
		first := kmsKey(keyA, ringA)
		idx := indexKmsKeysByID([]any{first, kmsKey(keyA, ringB)})
		if idx[keyA] != first {
			t.Fatalf("idx[%q] = %v, want the first key seen", keyA, idx[keyA])
		}
	})

	t.Run("empty listing yields an empty index, not nil", func(t *testing.T) {
		if idx := indexKmsKeysByID(nil); idx == nil {
			t.Fatal("indexKmsKeysByID(nil) = nil, want an empty map")
		}
	})
}

func TestKeyIndexByID(t *testing.T) {
	const (
		ringA = "ring-a"
		keyA  = "11111111-1111-1111-1111-111111111111"
		keyB  = "22222222-2222-2222-2222-222222222222"
	)

	t.Run("walks every ring once", func(t *testing.T) {
		a := kmsKey(keyA, ringA)
		b := kmsKey(keyB, "ring-b")
		k := &mqlStackitKms{
			KeyRings: setList([]any{
				&mqlStackitKmsKeyRing{Keys: setList([]any{a})},
				&mqlStackitKmsKeyRing{Keys: setList([]any{b})},
				"not a key ring",
			}),
		}

		idx, err := k.keyIndexByID()
		if err != nil {
			t.Fatalf("keyIndexByID() error = %v", err)
		}
		if idx[keyA] != a || idx[keyB] != b {
			t.Fatalf("index = %v, want both keys", idx)
		}

		// the memo has to survive: mutating the source listing must not change
		// what a second caller sees
		k.KeyRings = setList(nil)
		idx2, err := k.keyIndexByID()
		if err != nil {
			t.Fatalf("second keyIndexByID() error = %v", err)
		}
		if len(idx2) != 2 {
			t.Fatalf("second call rebuilt the index (size %d), want the memoized one", len(idx2))
		}
	})

	t.Run("an errored ring listing is memoized, not retried", func(t *testing.T) {
		boom := errors.New("key rings unreadable")
		k := &mqlStackitKms{
			KeyRings: plugin.TValue[[]any]{Error: boom, State: plugin.StateIsSet | plugin.StateIsNull},
		}

		idx, err := k.keyIndexByID()
		if !errors.Is(err, boom) {
			t.Fatalf("keyIndexByID() error = %v, want %v", err, boom)
		}
		if idx != nil {
			t.Fatalf("keyIndexByID() index = %v, want nil on error", idx)
		}

		// a second reference must get the same failure without a fresh read
		k.KeyRings = setList([]any{&mqlStackitKmsKeyRing{Keys: setList([]any{kmsKey(keyA, ringA)})}})
		if _, err := k.keyIndexByID(); !errors.Is(err, boom) {
			t.Fatalf("second keyIndexByID() error = %v, want the memoized %v", err, boom)
		}
	})

	t.Run("an errored key listing inside a ring surfaces", func(t *testing.T) {
		boom := errors.New("keys unreadable")
		k := &mqlStackitKms{
			KeyRings: setList([]any{
				&mqlStackitKmsKeyRing{Keys: plugin.TValue[[]any]{Error: boom, State: plugin.StateIsSet | plugin.StateIsNull}},
			}),
		}
		if _, err := k.keyIndexByID(); !errors.Is(err, boom) {
			t.Fatalf("keyIndexByID() error = %v, want %v", err, boom)
		}
	})

	t.Run("concurrent readers share one index", func(t *testing.T) {
		k := &mqlStackitKms{
			KeyRings: setList([]any{
				&mqlStackitKmsKeyRing{Keys: setList([]any{kmsKey(keyA, ringA)})},
			}),
		}

		var wg sync.WaitGroup
		got := make([]map[string]*mqlStackitKmsKey, 8)
		for i := range got {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				idx, err := k.keyIndexByID()
				if err != nil {
					t.Errorf("keyIndexByID() error = %v", err)
					return
				}
				got[i] = idx
			}(i)
		}
		wg.Wait()

		for i, idx := range got {
			if idx == nil {
				t.Fatalf("goroutine %d got a nil index", i)
			}
			if len(idx) != 1 {
				t.Fatalf("goroutine %d index size = %d, want 1", i, len(idx))
			}
		}
	})
}

func TestFindKmsKeyVersion(t *testing.T) {
	v1 := kmsKeyVersion(1)
	v3 := kmsKeyVersion(3)
	items := []any{v1, "junk", (*mqlStackitKmsKeyVersion)(nil), v3}

	if got := findKmsKeyVersion(items, 3); got != v3 {
		t.Fatalf("findKmsKeyVersion(3) = %v, want version 3", got)
	}
	if got := findKmsKeyVersion(items, 2); got != nil {
		t.Fatalf("findKmsKeyVersion(2) = %v, want nil", got)
	}
	if got := findKmsKeyVersion(nil, 1); got != nil {
		t.Fatalf("findKmsKeyVersion over an empty list = %v, want nil", got)
	}
}

func TestIndexIamRolesByName(t *testing.T) {
	t.Run("hit and miss", func(t *testing.T) {
		reader := iamRole("reader")
		idx := indexIamRolesByName([]any{reader, iamRole("editor")})
		if idx["reader"] != reader {
			t.Fatalf("idx[reader] = %v, want the reader role", idx["reader"])
		}
		if got, ok := idx["owner"]; ok || got != nil {
			t.Fatalf("lookup of an unbound role = (%v, %v), want (nil, false)", got, ok)
		}
	})

	t.Run("empty names, nils, and foreign entries are skipped", func(t *testing.T) {
		idx := indexIamRolesByName([]any{
			iamRole(""),
			(*mqlStackitIamRole)(nil),
			kmsKey("some-key", "some-ring"),
			42,
			iamRole("reader"),
		})
		if len(idx) != 1 {
			t.Fatalf("index size = %d, want 1 (only the well-formed role)", len(idx))
		}
	})

	t.Run("first role wins on a duplicate name", func(t *testing.T) {
		first := iamRole("reader")
		idx := indexIamRolesByName([]any{first, iamRole("reader")})
		if idx["reader"] != first {
			t.Fatalf("idx[reader] = %v, want the first role seen", idx["reader"])
		}
	})

	t.Run("empty catalog yields an empty index, not nil", func(t *testing.T) {
		if idx := indexIamRolesByName(nil); idx == nil {
			t.Fatal("indexIamRolesByName(nil) = nil, want an empty map")
		}
	})
}

func TestRoleIndexByName(t *testing.T) {
	t.Run("built once and memoized", func(t *testing.T) {
		reader := iamRole("reader")
		i := &mqlStackitIam{Roles: setList([]any{reader})}

		idx, err := i.roleIndexByName()
		if err != nil {
			t.Fatalf("roleIndexByName() error = %v", err)
		}
		if idx["reader"] != reader {
			t.Fatalf("idx[reader] = %v, want the reader role", idx["reader"])
		}

		i.Roles = setList(nil)
		idx2, err := i.roleIndexByName()
		if err != nil {
			t.Fatalf("second roleIndexByName() error = %v", err)
		}
		if len(idx2) != 1 {
			t.Fatalf("second call rebuilt the index (size %d), want the memoized one", len(idx2))
		}
	})

	t.Run("an errored catalog listing is memoized, not retried", func(t *testing.T) {
		boom := errors.New("role catalog unreadable")
		i := &mqlStackitIam{
			Roles: plugin.TValue[[]any]{Error: boom, State: plugin.StateIsSet | plugin.StateIsNull},
		}

		if _, err := i.roleIndexByName(); !errors.Is(err, boom) {
			t.Fatalf("roleIndexByName() error = %v, want %v", err, boom)
		}

		i.Roles = setList([]any{iamRole("reader")})
		if _, err := i.roleIndexByName(); !errors.Is(err, boom) {
			t.Fatalf("second roleIndexByName() error = %v, want the memoized %v", err, boom)
		}
	})

	t.Run("concurrent readers share one index", func(t *testing.T) {
		i := &mqlStackitIam{Roles: setList([]any{iamRole("reader")})}

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				idx, err := i.roleIndexByName()
				if err != nil {
					t.Errorf("roleIndexByName() error = %v", err)
					return
				}
				if len(idx) != 1 {
					t.Errorf("index size = %d, want 1", len(idx))
				}
			})
		}
		wg.Wait()
	})
}
