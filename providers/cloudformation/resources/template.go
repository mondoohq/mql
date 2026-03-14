// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/aws-cloudformation/rain/cft"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/cloudformation/connection"
	"go.mondoo.com/mql/v13/types"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"gopkg.in/yaml.v3"
)

func initCloudformationTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()

	args["version"] = llx.StringData("")
	args["description"] = llx.StringData("")
	args["transform"] = llx.NilData

	version, err := template.GetSection(cft.AWSTemplateFormatVersion)
	if err == nil {
		args["version"] = llx.StringData(version.Value)
	}

	desc, err := template.GetSection(cft.Description)
	if err == nil {
		args["description"] = llx.StringData(desc.Value)
	}

	transform, err := template.GetSection(cft.Transform)
	if err == nil && len(transform.Content) > 0 {
		var entries []string
		for _, entry := range transform.Content {
			entries = append(entries, entry.Value)
		}
		args["transform"] = llx.ArrayData(convert.SliceAnyToInterface(entries), types.String)
	}

	return args, nil, nil
}

func (r *mqlCloudformationTemplate) id() (string, error) {
	return "cloudformation", nil
}

func (r *mqlCloudformationTemplate) extractDict(section cft.Section) (map[string]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()

	if template.Node == nil || len(template.Node.Content) == 0 {
		return nil, nil
	}

	_, parameters, err := gatherMapValue(template.Node.Content[0], string(section))
	if err != nil && status.Code(err) == codes.NotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	result := make(map[string]any)
	for i := 0; i < len(parameters.Content); i += 2 {
		keyNode := parameters.Content[i]
		valueNode := parameters.Content[i+1]

		dict, err := convertYamlToDict(valueNode)
		if err != nil {
			return nil, err
		}

		result[keyNode.Value] = dict
	}

	return result, nil
}

func (r *mqlCloudformationTemplate) mappings() (map[string]any, error) {
	return r.extractDict(cft.Mappings)
}

var Globals cft.Section = "Globals"

// Reads the Globals section of the SAM template.
// see https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification-template-anatomy.html
func (r *mqlCloudformationTemplate) globals() (map[string]any, error) {
	return r.extractDict(Globals)
}

func (r *mqlCloudformationTemplate) parameters() (map[string]any, error) {
	return r.extractDict(cft.Parameters)
}

func (r *mqlCloudformationTemplate) metadata() (map[string]any, error) {
	return r.extractDict(cft.Metadata)
}

func (r *mqlCloudformationTemplate) conditions() (map[string]any, error) {
	return r.extractDict(cft.Conditions)
}

func (r *mqlCloudformationTemplate) rules() (map[string]any, error) {
	return r.extractDict(cft.Rules)
}

func (x *mqlCloudformationResource) id() (string, error) {
	return x.Name.Data, nil
}

func (r *mqlCloudformationTemplate) resources() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()
	_, resources, err := gatherMapValue(template.Node.Content[0], string(cft.Resources))
	if err != nil && status.Code(err) == codes.NotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	result := make([]any, 0)
	for i := 0; i < len(resources.Content); i += 2 {
		keyNode := resources.Content[i]
		valueNode := resources.Content[i+1]

		resourceType := ""
		resourceCondition := ""
		resourceDocumentation := ""

		_, val, err := gatherMapValue(valueNode, "Type")
		if err == nil {
			resourceType = val.Value
		}
		_, val, err = gatherMapValue(valueNode, "Condition")
		if err == nil {
			resourceCondition = val.Value
		}
		_, val, err = gatherMapValue(valueNode, "Documentation")
		if err == nil {
			resourceDocumentation = val.Value
		}

		attrs := make(map[string](any))
		_, val, err = gatherMapValue(valueNode, "Attributes")
		if err == nil {
			attrs, err = convertYamlToDict(val)
			if err != nil {
				return nil, err
			}
		}

		props := make(map[string](any))
		_, val, err = gatherMapValue(valueNode, "Properties")
		if err == nil {
			props, err = convertYamlToDict(val)
			if err != nil {
				return nil, err
			}
		}

		var dependsOn []any
		_, val, err = gatherMapValue(valueNode, "DependsOn")
		if err == nil {
			switch val.Kind {
			case yaml.ScalarNode:
				dependsOn = []any{val.Value}
			case yaml.SequenceNode:
				for _, item := range val.Content {
					dependsOn = append(dependsOn, item.Value)
				}
			}
		}

		pkg, err := CreateResource(r.MqlRuntime, "cloudformation.resource", map[string]*llx.RawData{
			"name":          llx.StringData(keyNode.Value),
			"type":          llx.StringData(resourceType),
			"condition":     llx.StringData(resourceCondition),
			"documentation": llx.StringData(resourceDocumentation),
			"attributes":    llx.MapData(attrs, types.Dict),
			"properties":    llx.MapData(props, types.Dict),
			"dependsOn":     llx.ArrayData(dependsOn, types.String),
		})
		if err != nil {
			return nil, err
		}

		s := pkg.(*mqlCloudformationResource)
		result = append(result, s)
	}

	return result, nil
}

func (x *mqlCloudformationOutput) id() (string, error) {
	return x.Name.Data, nil
}

func (r *mqlCloudformationTemplate) outputs() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()

	_, outputs, err := gatherMapValue(template.Node.Content[0], string(cft.Outputs))
	if err != nil && status.Code(err) == codes.NotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	result := make([]any, 0)
	for i := 0; i < len(outputs.Content); i += 2 {
		keyNode := outputs.Content[i]
		valueNode := outputs.Content[i+1]

		dict, err := convertYamlToDict(valueNode)
		if err != nil {
			return nil, err
		}

		pkg, err := CreateResource(r.MqlRuntime, "cloudformation.output", map[string]*llx.RawData{
			"name":       llx.StringData(keyNode.Value),
			"properties": llx.DictData(dict),
		})
		if err != nil {
			return nil, err
		}

		s := pkg.(*mqlCloudformationOutput)
		result = append(result, s)
	}

	return result, nil
}

func (r *mqlCloudformationTemplate) types() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()

	list, err := template.GetTypes()
	if err != nil {
		return nil, err
	}

	return convert.SliceAnyToInterface(list), nil
}
