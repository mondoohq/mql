// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/terraform/connection"
	"go.mondoo.com/mql/types"
)

func (t *mqlTerraformState) id() (string, error) {
	return "terraform.state", nil
}

func initTerraformState(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.Connection)

	state, err := conn.State()
	if err != nil {
		return nil, nil, err
	}
	if state == nil {
		return nil, nil, errors.New("cannot find state")
	}

	args["formatVersion"] = llx.StringData(state.FormatVersion)
	args["terraformVersion"] = llx.StringData(state.TerraformVersion)

	return args, nil, nil
}

// errNoState is returned by the terraform.state accessors on an asset that
// carries no state (an HCL or plan asset). conn.State() returns (nil, nil)
// there, and every accessor below used to check only state.Values — so a
// terraform.state.* query against such an asset dereferenced a nil state and
// took the provider down.
var errNoState = errors.New("cannot find state: this asset does not carry terraform state")

func (t *mqlTerraformState) outputs() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)
	state, err := conn.State()
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errNoState
	}

	if state.Values == nil {
		return nil, nil
	}

	var list []any
	for k := range state.Values.Outputs {
		output := state.Values.Outputs[k]

		r, err := CreateResource(t.MqlRuntime, "terraform.state.output", map[string]*llx.RawData{
			"identifier": llx.StringData(k),
			"sensitive":  llx.BoolData(output.Sensitive),
		})
		if err != nil {
			return nil, err
		}
		so := r.(*mqlTerraformStateOutput)
		so.output.Store(output)
		list = append(list, r)
	}

	return list, nil
}

func (t *mqlTerraformState) rootModule() (*mqlTerraformStateModule, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)
	state, err := conn.State()
	if err != nil {
		return nil, err
	}

	if state == nil {
		return nil, errNoState
	}

	// A state with `values` present but no `root_module` (e.g. outputs-only or
	// a trimmed state) decodes to a non-nil Values with a nil RootModule;
	// guard both so we don't dereference nil.
	if state.Values == nil || state.Values.RootModule == nil {
		t.RootModule.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	r, err := newMqlModule(t.MqlRuntime, state.Values.RootModule)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (t *mqlTerraformState) modules() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)
	state, err := conn.State()
	if err != nil {
		return nil, err
	}

	if state == nil {
		return nil, errNoState
	}

	if state.Values == nil || state.Values.RootModule == nil {
		return []any{}, nil
	}

	// resolve all tfstate modules
	moduleList := []*connection.Module{}
	moduleList = append(moduleList, state.Values.RootModule)
	state.Values.RootModule.WalkChildModules(func(m *connection.Module) {
		moduleList = append(moduleList, m)
	})

	// convert module list to mql resources
	list := []any{}
	for i := range moduleList {
		r, err := newMqlModule(t.MqlRuntime, moduleList[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}

	return list, nil
}

func (t *mqlTerraformState) resources() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)
	providerState, err := conn.State()
	if err != nil {
		return nil, err
	}

	if providerState == nil {
		return nil, errNoState
	}

	if providerState.Values == nil || providerState.Values.RootModule == nil {
		return []any{}, nil
	}

	// resolve all tfstate resources, to achieve this we need to walk all modules
	resourceList := []*connection.Resource{}

	resourceList = append(resourceList, providerState.Values.RootModule.Resources...)
	providerState.Values.RootModule.WalkChildModules(func(m *connection.Module) {
		resourceList = append(resourceList, m.Resources...)
	})

	// convert module list to mql resources
	list := []any{}
	for i := range resourceList {
		r, err := newMqlResource(t.MqlRuntime, resourceList[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}

	return list, nil
}

type mqlTerraformStateOutputInternal struct {
	// output is stamped after CreateResource, which hands back the ALREADY
	// CACHED instance when the __id matches. plugin.GetOrCompute is
	// unsynchronized, so two goroutines resolving terraform.state.outputs both
	// miss its IsSet check, both run the accessor and both reach this write
	// while value() and compute_type() read it.
	//
	// An atomic rather than a sync.Once around the write: the runtime caches
	// the instance BEFORE the stamp runs, so a reader that picks it up from
	// that cache has no happens-before edge to the stamp and a write-side
	// guard alone would leave it racing.
	output atomic.Pointer[connection.Output]
}

func initTerraformStateOutput(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	// check if identifier is there
	nameRaw := args["identifier"]
	if nameRaw != nil {
		// RawData.Value is nil for a null argument, and a bare `.(string)`
		// assertion on that panics — which crashes the whole scan, since query
		// blocks run in goroutines.
		name, ok := nameRaw.Value.(string)
		if !ok {
			return nil, nil, errors.New("terraform.state.output requires a string identifier")
		}
		// NewResource, not CreateResource: only NewResource runs
		// initTerraformState, whose "cannot find state" guard is what keeps this
		// from walking a nil state on an HCL or plan asset. CreateResource also
		// registered an uninitialized instance under terraform.state's constant
		// id, so a later correct lookup returned that husk and
		// terraform.state.formatVersion read as unset.
		obj, err := NewResource(runtime, "terraform.state", map[string]*llx.RawData{})
		if err != nil {
			return nil, nil, err
		}
		tfstate := obj.(*mqlTerraformState)

		outputs := tfstate.GetOutputs()
		if outputs.Error != nil {
			return nil, nil, outputs.Error
		}
		for i := range outputs.Data {
			o := outputs.Data[i].(*mqlTerraformStateOutput)
			id := o.Identifier.Data
			if id == name {
				return nil, o, nil
			}
		}

		// Falling through here would have the runtime build an output with no
		// value and no type, whose id collides with nothing useful; report the
		// miss instead.
		return nil, nil, fmt.Errorf("terraform.state.output with identifier %q not found", name)
	}

	return args, nil, nil
}

func (t *mqlTerraformStateOutput) id() (string, error) {
	id := t.Identifier
	return "terraform.state.output/identifier/" + id.Data, nil
}

func (t *mqlTerraformStateOutput) value() (any, error) {
	output := t.output.Load()
	if output == nil {
		return nil, nil
	}

	var value any
	if err := json.Unmarshal(output.Value, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func (t *mqlTerraformStateOutput) compute_type() (any, error) {
	output := t.output.Load()
	if output == nil {
		return nil, nil
	}

	var typ any
	if err := json.Unmarshal([]byte(output.Type), &typ); err != nil {
		return nil, err
	}
	return typ, nil
}

func (t *mqlTerraformStateModule) id() (string, error) {
	address := t.Address

	// A state root module omits its address, so it needs an id of its own. The
	// previous bare "terraform.module" was also whatever a blank, lookup-miss
	// module computed, so the two shared a cache key.
	name := "terraform.state.module/root"
	if address.Data != "" {
		name = "terraform.state.module/address/" + address.Data
	}

	return name, nil
}

func initTerraformStateModule(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	// check if identifier is there
	nameRaw := args["address"]
	if nameRaw != nil {
		return args, nil, nil
	}

	idRaw := args["identifier"]
	if idRaw != nil {
		identifier, ok := idRaw.Value.(string)
		if !ok {
			return nil, nil, errors.New("terraform.state.module requires a string identifier")
		}
		// See initTerraformStateOutput: NewResource runs initTerraformState,
		// which both guards the nil state and keeps the terraform.state
		// singleton from being cached uninitialized.
		obj, err := NewResource(runtime, "terraform.state", map[string]*llx.RawData{})
		if err != nil {
			return nil, nil, err
		}
		tfstate := obj.(*mqlTerraformState)

		modules := tfstate.GetModules()
		if modules.Error != nil {
			return nil, nil, modules.Error
		}
		for i := range modules.Data {
			o := modules.Data[i].(*mqlTerraformStateModule)
			id := o.Address.Data
			if id == identifier {
				return nil, o, nil
			}
		}

		// Dropping the identifier and falling through built a module with no
		// address, whose id was the ROOT module's id — so a typo'd address
		// silently resolved to the root module's contents.
		return nil, nil, fmt.Errorf("terraform.state.module with address %q not found", identifier)
	}

	return args, nil, nil
}

type mqlTerraformStateModuleInternal struct {
	// module is stamped after CreateResource, which hands back the ALREADY
	// CACHED instance when the __id matches. The same module is reachable
	// three ways -- terraform.state.modules walks the whole tree,
	// terraform.state.rootModule takes the root and rootModule.childModules
	// takes each child -- and each is a separate field resolution that runs in
	// its own goroutine, so both this write and the reads below cross
	// goroutines.
	//
	// An atomic rather than a sync.Once around the write, for the reason given
	// on mqlTerraformStateOutputInternal.output.
	module atomic.Pointer[connection.Module]
}

func (t *mqlTerraformStateModule) resources() ([]any, error) {
	module := t.module.Load()
	if module == nil {
		return nil, nil
	}

	var list []any
	for i := range module.Resources {
		resource := module.Resources[i]
		r, err := newMqlResource(t.MqlRuntime, resource)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}

	return list, nil
}

func newMqlModule(runtime *plugin.Runtime, module *connection.Module) (*mqlTerraformStateModule, error) {
	r, err := CreateResource(runtime, "terraform.state.module", map[string]*llx.RawData{
		"address": llx.StringData(module.Address),
	})
	if err != nil {
		return nil, err
	}

	tmr := r.(*mqlTerraformStateModule)
	tmr.module.Store(module)

	return tmr, nil
}

func newMqlResource(runtime *plugin.Runtime, resource *connection.Resource) (plugin.Resource, error) {
	r, err := CreateResource(runtime, "terraform.state.resource", map[string]*llx.RawData{
		"address":       llx.StringData(resource.Address),
		"name":          llx.StringData(resource.Name),
		"mode":          llx.StringData(resource.Mode),
		"type":          llx.StringData(resource.Type),
		"providerName":  llx.StringData(resource.ProviderName),
		"schemaVersion": llx.IntData(int64(resource.SchemaVersion)),
		"values":        llx.MapData(resource.AttributeValues, types.Any),
		"dependsOn":     llx.ArrayData(convert.SliceAnyToInterface[string](resource.DependsOn), types.String),
		"tainted":       llx.BoolData(resource.Tainted),
		"deposedKey":    llx.StringData(resource.DeposedKey),
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (t *mqlTerraformStateModule) childModules() ([]any, error) {
	module := t.module.Load()
	if module == nil {
		return nil, nil
	}

	var list []any
	for i := range module.ChildModules {
		r, err := newMqlModule(t.MqlRuntime, module.ChildModules[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}

	return list, nil
}

func (t *mqlTerraformStateResource) id() (string, error) {
	address := t.Address

	name := "terraform.state.resource"
	if address.Data != "" {
		name += "/address/" + address.Data
	}

	// Terraform records a deposed object as a separate entry carrying the SAME
	// address, distinguished only by deposed_key. Without it both entries hash
	// to one cache key and the deposed object is invisible while the list still
	// reports two.
	if t.DeposedKey.Data != "" {
		name += "/deposed/" + t.DeposedKey.Data
	}

	return name, nil
}
