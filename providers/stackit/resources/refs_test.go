// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stackitcloud/stackit-sdk-go/core/oapierror"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// fakeRefTarget registers a throwaway resource whose init answers each id
// from the given table: a nil error builds a volume with that id, a non-nil
// error is returned as the lookup failure. It stands in for an init that calls
// the STACKIT API, so the reference helpers can be driven without a client.
func fakeRefTarget(t *testing.T, answers map[string]error) (string, *plugin.Runtime) {
	t.Helper()
	const name = "stackit.test.refTarget"
	resourceFactories[name] = plugin.ResourceFactory{
		Init: func(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
			id, _ := idArg(args, "id")
			if err := answers[id]; err != nil {
				return nil, nil, err
			}
			v := &mqlStackitVolume{MqlRuntime: runtime, __id: "stackit.volume/" + id}
			v.Id = plugin.TValue[string]{Data: id, State: plugin.StateIsSet}
			return nil, v, nil
		},
	}
	t.Cleanup(func() { delete(resourceFactories, name) })
	return name, &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

func apiError(status int) error {
	return &oapierror.GenericOpenAPIError{StatusCode: status, ErrorMessage: http.StatusText(status)}
}

func TestRefByKeyNotFoundIsNull(t *testing.T) {
	name, runtime := fakeRefTarget(t, map[string]error{"gone": apiError(http.StatusNotFound)})
	var field plugin.TValue[*mqlStackitVolume]
	got, err := refByKey(runtime, name, "id", "gone", &field)
	if err != nil {
		t.Fatalf("a 404 on the referenced object must read as null, got error %v", err)
	}
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
	if field.State != plugin.StateIsSet|plugin.StateIsNull {
		t.Fatalf("field state = %v, want set and null", field.State)
	}
}

func TestRefByKeyEmptyIsNull(t *testing.T) {
	name, runtime := fakeRefTarget(t, nil)
	var field plugin.TValue[*mqlStackitVolume]
	got, err := refByKey(runtime, name, "id", "", &field)
	if err != nil || got != nil {
		t.Fatalf("empty id: got (%v, %v), want (nil, nil)", got, err)
	}
	if field.State != plugin.StateIsSet|plugin.StateIsNull {
		t.Fatalf("field state = %v, want set and null", field.State)
	}
}

func TestRefByKeyRefusalAndFailureAreErrors(t *testing.T) {
	transport := errors.New("dial tcp: connection refused")
	name, runtime := fakeRefTarget(t, map[string]error{
		"denied": apiError(http.StatusForbidden),
		"broken": apiError(http.StatusInternalServerError),
		"down":   transport,
	})
	for _, id := range []string{"denied", "broken", "down"} {
		var field plugin.TValue[*mqlStackitVolume]
		got, err := refByKey(runtime, name, "id", id, &field)
		if err == nil {
			t.Fatalf("%s: got (%v, nil), want an error; only a 404 reads as null", id, got)
		}
		if field.State&plugin.StateIsNull != 0 {
			t.Fatalf("%s: field marked null on a failed lookup", id)
		}
	}
}

func TestRefByKeyResolves(t *testing.T) {
	name, runtime := fakeRefTarget(t, map[string]error{})
	var field plugin.TValue[*mqlStackitVolume]
	got, err := refByKey(runtime, name, "id", "vol-1", &field)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Id.Data != "vol-1" {
		t.Fatalf("got %v, want the volume vol-1", got)
	}
}

func TestRefsByIDSkipsDeletedKeepsRest(t *testing.T) {
	name, runtime := fakeRefTarget(t, map[string]error{"gone": apiError(http.StatusNotFound)})
	got, err := refsByID(runtime, name, []string{"a", "", "gone", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d refs, want 2 (a, b)", len(got))
	}
	for i, want := range []string{"a", "b"} {
		if v := got[i].(*mqlStackitVolume); v.Id.Data != want {
			t.Fatalf("ref %d = %q, want %q", i, v.Id.Data, want)
		}
	}
}

func TestRefsByIDFailsOnRefusal(t *testing.T) {
	name, runtime := fakeRefTarget(t, map[string]error{"denied": apiError(http.StatusForbidden)})
	if _, err := refsByID(runtime, name, []string{"a", "denied"}); err == nil {
		t.Fatal("a refused lookup must fail the list, not shorten it")
	}
}
