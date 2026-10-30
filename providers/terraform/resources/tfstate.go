// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"

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

func (t *mqlTerraformState) outputs() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.Connection)
	state, err := conn.State()
	if err != nil {
		return nil, err
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
		so.output = output
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
	output *connection.Output
}

func initTerraformStateOutput(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	// check if identifier is there
	nameRaw := args["identifier"]
	if nameRaw != nil {
		name := nameRaw.Value.(string)
		obj, err := CreateResource(runtime, "terraform.state", nil)
		if err != nil {
			return nil, nil, err
		}
		tfstate := obj.(*mqlTerraformState)

		outputs := tfstate.GetOutputs()
		for i := range outputs.Data {
			o := outputs.Data[i].(*mqlTerraformStateOutput)
			id := o.Identifier.Data
			if id == name {
				return nil, o, nil
			}
		}
	}

	return args, nil, nil
}

func (t *mqlTerraformStateOutput) id() (string, error) {
	id := t.Identifier
	return "terraform.state.output/identifier/" + id.Data, nil
}

func (t *mqlTerraformStateOutput) value() (any, error) {
	if t.output == nil {
		return nil, nil
	}

	var value any
	if err := json.Unmarshal(t.output.Value, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func (t mqlTerraformStateOutput) compute_type() (any, error) {
	if t.output == nil {
		return nil, nil
	}

	var typ any
	if err := json.Unmarshal([]byte(t.output.Type), &typ); err != nil {
		return nil, err
	}
	return typ, nil
}

func (t *mqlTerraformStateModule) id() (string, error) {
	address := t.Address

	name := "terraform.module"
	if address.Data != "" {
		name += "/address/" + address.Data
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
		identifier := idRaw.Value.(string)
		obj, err := CreateResource(runtime, "terraform.state", nil)
		if err != nil {
			return nil, nil, err
		}
		tfstate := obj.(*mqlTerraformState)

		modules := tfstate.GetModules()
		for i := range modules.Data {
			o := modules.Data[i].(*mqlTerraformStateModule)
			id := o.Address.Data
			if id == identifier {
				return nil, o, nil
			}
		}
		delete(args, "identifier")
	}

	return args, nil, nil
}

type mqlTerraformStateModuleInternal struct {
	module *connection.Module
}

func (t *mqlTerraformStateModule) resources() ([]any, error) {
	if t.module == nil {
		return nil, nil
	}

	var list []any
	for i := range t.module.Resources {
		resource := t.module.Resources[i]
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
	tmr.module = module

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
	if t.module == nil {
		return nil, nil
	}

	var list []any
	for i := range t.module.ChildModules {
		r, err := newMqlModule(t.MqlRuntime, t.module.ChildModules[i])
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

	return name, nil
}
