// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"strings"
	"testing"

	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/jobs"
	"github.com/databricks/databricks-sdk-go/service/pipelines"
)

// The Databricks SDK models several of its structures as unions: a struct in
// which exactly one member is populated and the populated member is the
// discriminator. Every function that flattens one of those unions ends in a
// default branch that reports the entry as unknown, so that a member this SDK
// version does not model still appears rather than vanishing from the list.
//
// That default branch is also a trap. When the SDK is upgraded and a union gains
// a member, the flattener keeps compiling and keeps returning results, and the
// only symptom is that some entries quietly report an empty type. The tests
// below walk each union's members through reflection and fail when one is not
// classified, which turns that silent under-report into a build failure at
// upgrade time.

// unionMembers returns the members of a union struct: every exported field
// except the SDK's ForceSendFields bookkeeping slice.
func unionMembers(t *testing.T, typ reflect.Type) []reflect.StructField {
	t.Helper()
	if typ.Kind() != reflect.Struct {
		t.Fatalf("%s is not a struct", typ)
	}

	out := []reflect.StructField{}
	for f := range typ.Fields() {
		f := f
		if !f.IsExported() || f.Name == "ForceSendFields" {
			continue
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		t.Fatalf("%s has no union members, the reflection filter is wrong", typ)
	}
	return out
}

// withOnlyMember builds a value of the union struct in which exactly the given
// member is populated. Pointer members get a zero value of their element type;
// string members get a sentinel, since an empty string reads as unset.
func withOnlyMember(t *testing.T, typ reflect.Type, f reflect.StructField) reflect.Value {
	t.Helper()
	v := reflect.New(typ).Elem()
	field := v.FieldByIndex(f.Index)

	switch f.Type.Kind() {
	case reflect.Pointer:
		field.Set(reflect.New(f.Type.Elem()))
	case reflect.String:
		field.SetString("sentinel")
	default:
		t.Fatalf("union member %s.%s has unsupported kind %s, extend this helper",
			typ.Name(), f.Name, f.Type.Kind())
	}
	return v
}

func TestTaskTypeOfHandlesEverySdkTaskKind(t *testing.T) {
	typ := reflect.TypeFor[jobs.Task]()
	for _, f := range unionMembers(t, typ) {
		// A job task carries plenty of non-discriminating configuration
		// (dependencies, retries, notifications). Only the pointer fields whose
		// name ends in Task select the kind of work.
		if f.Type.Kind() != reflect.Pointer || !strings.HasSuffix(f.Name, "Task") {
			continue
		}

		t.Run(f.Name, func(t *testing.T) {
			task := withOnlyMember(t, typ, f).Interface().(jobs.Task)
			if got := taskTypeOf(task); got == "" {
				t.Fatalf("taskTypeOf() returned empty for jobs.Task.%s.\n"+
					"The SDK models a task kind that taskTypeOf does not classify, so every task "+
					"of that kind reports an empty taskType. Add a case for it.", f.Name)
			}
		})
	}
}

func TestTriggerTypeOfHandlesEverySdkTriggerKind(t *testing.T) {
	// A trigger configuration carries members that are not the discriminator:
	// PauseStatus is a plain string, and SqlCondition gates a trigger of any
	// kind rather than selecting one. Everything else is a pointer to a
	// *TriggerConfiguration struct and names a kind.
	notAKind := map[string]bool{"PauseStatus": true, "SqlCondition": true}

	typ := reflect.TypeFor[jobs.TriggerConfiguration]()
	for _, f := range unionMembers(t, typ) {
		if f.Type.Kind() != reflect.Pointer || notAKind[f.Name] {
			continue
		}

		t.Run(f.Name, func(t *testing.T) {
			trigger := withOnlyMember(t, typ, f).Interface().(jobs.TriggerConfiguration)
			if got := triggerTypeOf(trigger); got == "unknown" || got == "" {
				t.Fatalf("triggerTypeOf() returned %q for jobs.TriggerConfiguration.%s.\n"+
					"The SDK models a trigger kind that triggerTypeOf does not classify, so every "+
					"trigger of that kind reports an unknown triggerType and none of its "+
					"configuration is mapped. Add a case for it in triggerTypeOf and in triggers().",
					got, f.Name)
			}
		})
	}
}

func TestJobLibrariesToDictHandlesEverySdkLibraryKind(t *testing.T) {
	typ := reflect.TypeFor[compute.Library]()
	for _, f := range unionMembers(t, typ) {
		t.Run(f.Name, func(t *testing.T) {
			lib := withOnlyMember(t, typ, f).Interface().(compute.Library)
			got := jobLibrariesToDict([]compute.Library{lib})
			if len(got) != 1 {
				t.Fatalf("jobLibrariesToDict() returned %d entries, want 1", len(got))
			}
			entry, ok := got[0].(map[string]any)
			if !ok {
				t.Fatalf("entry is %T, want map[string]any", got[0])
			}
			if entry["type"] == "" {
				t.Fatalf("jobLibrariesToDict() returned an unknown type for compute.Library.%s.\n"+
					"The SDK models a library source that the flattener does not classify, so those "+
					"libraries report an empty type. Add a case for it.", f.Name)
			}
		})
	}
}

func TestPipelineLibraryToDictHandlesEverySdkLibraryKind(t *testing.T) {
	typ := reflect.TypeFor[pipelines.PipelineLibrary]()
	for _, f := range unionMembers(t, typ) {
		t.Run(f.Name, func(t *testing.T) {
			lib := withOnlyMember(t, typ, f).Interface().(pipelines.PipelineLibrary)
			got := pipelineLibraryToDict([]pipelines.PipelineLibrary{lib})
			if len(got) != 1 {
				t.Fatalf("pipelineLibraryToDict() returned %d entries, want 1", len(got))
			}
			entry, ok := got[0].(map[string]any)
			if !ok {
				t.Fatalf("entry is %T, want map[string]any", got[0])
			}
			if entry["type"] == "" {
				t.Fatalf("pipelineLibraryToDict() returned an unknown type for pipelines.PipelineLibrary.%s.\n"+
					"The SDK models a library source that the flattener does not classify, so those "+
					"libraries report an empty type. Add a case for it.", f.Name)
			}
		})
	}
}

func TestInitScriptsToDictHandlesEverySdkStorageKind(t *testing.T) {
	typ := reflect.TypeFor[compute.InitScriptInfo]()
	for _, f := range unionMembers(t, typ) {
		t.Run(f.Name, func(t *testing.T) {
			info := withOnlyMember(t, typ, f).Interface().(compute.InitScriptInfo)
			got := initScriptsToDict([]compute.InitScriptInfo{info})
			if len(got) != 1 {
				t.Fatalf("initScriptsToDict() returned %d entries, want 1", len(got))
			}
			entry, ok := got[0].(map[string]any)
			if !ok {
				t.Fatalf("entry is %T, want map[string]any", got[0])
			}
			if entry["type"] == "" {
				t.Fatalf("initScriptsToDict() returned an unknown type for compute.InitScriptInfo.%s.\n"+
					"The SDK models an init script storage backend that the flattener does not "+
					"classify, so those scripts report an empty type. Add a case for it.", f.Name)
			}
		})
	}
}
