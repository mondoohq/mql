// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws-cloudformation/rain/cft"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudformation/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"gopkg.in/yaml.v3"
)

// parseCfnBool interprets the boolean spellings CloudFormation accepts.
// CloudFormation parses templates as YAML 1.1, so `yes`/`on`/`1` are true in
// addition to `true` (any case). Anything else is false. This matters for
// NoEcho: a `NoEcho: yes` credential parameter must not read as unmasked.
func parseCfnBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

// isEvenMappingNode reports whether n is a YAML mapping with an even number of
// content nodes — i.e. safe to iterate two-at-a-time (key, value). A template
// section written as a sequence (or with odd content) would otherwise index
// out of range in the stride-2 loops below and panic the whole scan.
func isEvenMappingNode(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.MappingNode && len(n.Content)%2 == 0
}

func initCloudformationTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()

	args["version"] = llx.StringData("")
	args["description"] = llx.StringData("")
	args["transform"] = llx.NilData

	// cft.Template.GetSection dereferences Node.Content[0] without a guard, so
	// short-circuit on a degenerate template (empty file, comments only).
	if template.Node == nil || len(template.Node.Content) == 0 {
		return args, nil, nil
	}

	version, err := template.GetSection(cft.AWSTemplateFormatVersion)
	if err == nil {
		args["version"] = llx.StringData(version.Value)
	}

	desc, err := template.GetSection(cft.Description)
	if err == nil {
		args["description"] = llx.StringData(desc.Value)
	}

	transform, err := template.GetSection(cft.Transform)
	if err == nil && transform != nil {
		// Transform is commonly a single scalar (the canonical SAM header
		// `Transform: AWS::Serverless-2016-10-31`), but may also be a list.
		// A scalar YAML node has no Content, so handle both shapes.
		var entries []string
		if transform.Kind == yaml.ScalarNode {
			if transform.Value != "" {
				entries = append(entries, transform.Value)
			}
		} else {
			for _, entry := range transform.Content {
				entries = append(entries, entry.Value)
			}
		}
		if len(entries) > 0 {
			args["transform"] = llx.ArrayData(convert.SliceAnyToInterface(entries), types.String)
		}
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
	if !isEvenMappingNode(parameters) {
		return nil, nil
	}

	result := make(map[string]any)
	for i := 0; i < len(parameters.Content); i += 2 {
		keyNode := parameters.Content[i]
		valueNode := parameters.Content[i+1]

		// A section member's value need not be a mapping — a Metadata entry
		// like `License: Apache-2.0` is a scalar, and Metadata is free-form.
		// convertYamlNodeToValue accepts scalars, sequences, and mappings, so
		// one scalar member no longer fails the whole section. A member we
		// still cannot read is dropped on its own rather than taking every
		// other member of the section with it.
		val, err := convertYamlNodeToValue(valueNode)
		if err != nil {
			log.Warn().Err(err).Str("section", string(section)).Str("member", keyNode.Value).
				Msg("cloudformation: unreadable section member; skipping it")
			continue
		}

		result[keyNode.Value] = val
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

// sectionMemberID builds the cache key for a member of a template section.
// YAML preserves duplicate mapping keys, so a template can declare two
// resources (or outputs, or parameters) under the same logical ID. Keying the
// resource on the logical ID alone makes the second one collide with the first
// in the runtime cache, and the query then reports the first one's data twice
// while the second is invisible. `contentIndex` is the member's position in the
// section's Content slice, which is stable for a given template.
func sectionMemberID(name string, contentIndex int) string {
	return fmt.Sprintf("%s/%d", name, contentIndex/2)
}

func (x *mqlCloudformationResource) id() (string, error) {
	return x.Name.Data, nil
}

func (r *mqlCloudformationTemplate) resources() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()
	if template.Node == nil || len(template.Node.Content) == 0 {
		return nil, nil
	}
	_, resources, err := gatherMapValue(template.Node.Content[0], string(cft.Resources))
	if err != nil && status.Code(err) == codes.NotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if !isEvenMappingNode(resources) {
		return nil, nil
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
			resourceType = scalarValue(val)
		}
		_, val, err = gatherMapValue(valueNode, "Condition")
		if err == nil {
			resourceCondition = scalarValue(val)
		}
		_, val, err = gatherMapValue(valueNode, "Documentation")
		if err == nil {
			resourceDocumentation = scalarValue(val)
		}

		// Attributes/Properties are objects in valid CloudFormation. A
		// malformed (scalar/sequence) body shouldn't sink every other resource
		// in the template — leave the field empty and keep going.
		attrs := make(map[string](any))
		if _, val, gerr := gatherMapValue(valueNode, "Attributes"); gerr == nil {
			if converted, cerr := convertYamlToDict(val); cerr == nil {
				attrs = converted
			} else {
				log.Warn().Err(cerr).Str("resource", keyNode.Value).Msg("cloudformation: Attributes is not an object; leaving empty")
			}
		}

		props := make(map[string](any))
		if _, val, gerr := gatherMapValue(valueNode, "Properties"); gerr == nil {
			if converted, cerr := convertYamlToDict(val); cerr == nil {
				props = converted
			} else {
				log.Warn().Err(cerr).Str("resource", keyNode.Value).Msg("cloudformation: Properties is not an object; leaving empty")
			}
		}

		// DependsOn is either one logical ID or a list of them. Only scalars
		// name a logical ID: a mapping or nested list entry has no Value, and
		// appending it would report a dependency on the empty logical ID "".
		var dependsOn []any
		_, val, err = gatherMapValue(valueNode, "DependsOn")
		if err == nil {
			val = resolveAlias(val)
			switch {
			case val == nil:
			case val.Kind == yaml.SequenceNode:
				for _, item := range val.Content {
					if entry := scalarValue(item); entry != "" {
						dependsOn = append(dependsOn, entry)
					}
				}
			default:
				if entry := scalarValue(val); entry != "" {
					dependsOn = []any{entry}
				}
			}
		}

		deletionPolicy := ""
		_, val, err = gatherMapValue(valueNode, "DeletionPolicy")
		if err == nil {
			deletionPolicy = scalarValue(val)
		}

		updateReplacePolicy := ""
		_, val, err = gatherMapValue(valueNode, "UpdateReplacePolicy")
		if err == nil {
			updateReplacePolicy = scalarValue(val)
		}

		creationPolicy := optionalDict(valueNode, "CreationPolicy", keyNode.Value)
		updatePolicy := optionalDict(valueNode, "UpdatePolicy", keyNode.Value)
		resourceMetadata := optionalDict(valueNode, "Metadata", keyNode.Value)

		ctx, err := r.nodeContext(keyNode, valueNode)
		if err != nil {
			return nil, err
		}

		pkg, err := CreateResource(r.MqlRuntime, "cloudformation.resource", map[string]*llx.RawData{
			"__id":                llx.StringData(sectionMemberID(keyNode.Value, i)),
			"name":                llx.StringData(keyNode.Value),
			"type":                llx.StringData(resourceType),
			"condition":           llx.StringData(resourceCondition),
			"documentation":       llx.StringData(resourceDocumentation),
			"attributes":          llx.MapData(attrs, types.Dict),
			"properties":          llx.MapData(props, types.Dict),
			"dependsOn":           llx.ArrayData(dependsOn, types.String),
			"deletionPolicy":      llx.StringData(deletionPolicy),
			"updateReplacePolicy": llx.StringData(updateReplacePolicy),
			"creationPolicy":      llx.DictData(creationPolicy),
			"updatePolicy":        llx.DictData(updatePolicy),
			"resourceMetadata":    llx.DictData(resourceMetadata),
			"context":             llx.ResourceData(ctx, "cloudformation.context"),
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

func (x *mqlCloudformationParameter) id() (string, error) {
	return x.Name.Data, nil
}

// nodeEndLine returns the last source line spanned by a YAML node, computed as
// the maximum start line over the node and all of its descendants. yaml.v3
// records only the start position of each node, so this approximates the end
// of a multi-line block from its deepest child.
func nodeEndLine(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	end := n.Line
	for _, c := range n.Content {
		if e := nodeEndLine(c); e > end {
			end = e
		}
	}
	return end
}

// nodeContext builds a cloudformation.context spanning the source lines a
// template block occupies. keyNode is the block's logical-name key (its start
// line); valueNode is the block body (its end line is the deepest child).
func (r *mqlCloudformationTemplate) nodeContext(keyNode, valueNode *yaml.Node) (*mqlCloudformationContext, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)

	start := uint32(keyNode.Line)
	end := max(uint32(nodeEndLine(valueNode)), start)
	rnge := llx.NewRange().AddLineRange(start, end)
	content := rnge.ExtractString(conn.Content(), llx.DefaultExtractConfig)

	cobj, err := CreateResource(r.MqlRuntime, "cloudformation.context", map[string]*llx.RawData{
		"path":    llx.StringData(conn.Path()),
		"range":   llx.RangeData(rnge),
		"content": llx.StringData(content),
	})
	if err != nil {
		return nil, err
	}
	return cobj.(*mqlCloudformationContext), nil
}

func (r *mqlCloudformationContext) id() (string, error) {
	if r.Path.Data == "" {
		return "", errors.New("need path to exist for cloudformation.context ID")
	}
	return r.Path.Data + ":" + r.Range.Data.String(), nil
}

func (r *mqlCloudformationContext) content(path string, rnge llx.Range) (string, error) {
	if path == "" {
		return "", errors.New("no path information for cloudformation.context")
	}
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	return rnge.ExtractString(conn.Content(), llx.DefaultExtractConfig), nil
}

// context is populated at creation for each block, so these fallback resolvers
// only run if a resource was built without one.
func (x *mqlCloudformationResource) context() (*mqlCloudformationContext, error) {
	return nil, errors.New("context was not provided for cloudformation.resource")
}

func (x *mqlCloudformationOutput) context() (*mqlCloudformationContext, error) {
	return nil, errors.New("context was not provided for cloudformation.output")
}

func (x *mqlCloudformationParameter) context() (*mqlCloudformationContext, error) {
	return nil, errors.New("context was not provided for cloudformation.parameter")
}

func (r *mqlCloudformationTemplate) outputs() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()
	if template.Node == nil || len(template.Node.Content) == 0 {
		return nil, nil
	}

	_, outputs, err := gatherMapValue(template.Node.Content[0], string(cft.Outputs))
	if err != nil && status.Code(err) == codes.NotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if !isEvenMappingNode(outputs) {
		return nil, nil
	}

	result := make([]any, 0)
	for i := 0; i < len(outputs.Content); i += 2 {
		keyNode := outputs.Content[i]
		valueNode := outputs.Content[i+1]

		// An output body is an object in valid CloudFormation; degrade rather
		// than fail every output if one is malformed.
		dict := map[string]any{}
		if converted, cerr := convertYamlToDict(valueNode); cerr == nil {
			dict = converted
		} else {
			log.Warn().Err(cerr).Str("output", keyNode.Value).Msg("cloudformation: output body is not an object; leaving empty")
		}

		value := optionalDict(valueNode, "Value", keyNode.Value)

		description := ""
		if _, n, err := gatherMapValue(valueNode, "Description"); err == nil {
			description = scalarValue(n)
		}

		condition := ""
		if _, n, err := gatherMapValue(valueNode, "Condition"); err == nil {
			condition = scalarValue(n)
		}

		exportName := ""
		if _, exportNode, err := gatherMapValue(valueNode, "Export"); err == nil {
			if _, n, err := gatherMapValue(exportNode, "Name"); err == nil {
				exportName = scalarValue(n)
			}
		}

		ctx, err := r.nodeContext(keyNode, valueNode)
		if err != nil {
			return nil, err
		}

		pkg, err := CreateResource(r.MqlRuntime, "cloudformation.output", map[string]*llx.RawData{
			"__id":        llx.StringData(sectionMemberID(keyNode.Value, i)),
			"name":        llx.StringData(keyNode.Value),
			"properties":  llx.DictData(dict),
			"value":       llx.DictData(value),
			"description": llx.StringData(description),
			"exportName":  llx.StringData(exportName),
			"condition":   llx.StringData(condition),
			"context":     llx.ResourceData(ctx, "cloudformation.context"),
		})
		if err != nil {
			return nil, err
		}

		s := pkg.(*mqlCloudformationOutput)
		result = append(result, s)
	}

	return result, nil
}

func (r *mqlCloudformationTemplate) parameterList() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()

	if template.Node == nil || len(template.Node.Content) == 0 {
		return nil, nil
	}
	_, params, err := gatherMapValue(template.Node.Content[0], string(cft.Parameters))
	if err != nil && status.Code(err) == codes.NotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if !isEvenMappingNode(params) {
		return nil, nil
	}

	result := make([]any, 0)
	for i := 0; i < len(params.Content); i += 2 {
		keyNode := params.Content[i]
		valueNode := params.Content[i+1]

		paramType := ""
		if _, n, err := gatherMapValue(valueNode, "Type"); err == nil {
			paramType = scalarValue(n)
		}

		description := ""
		if _, n, err := gatherMapValue(valueNode, "Description"); err == nil {
			description = scalarValue(n)
		}

		allowedPattern := ""
		if _, n, err := gatherMapValue(valueNode, "AllowedPattern"); err == nil {
			allowedPattern = scalarValue(n)
		}

		constraintDescription := ""
		if _, n, err := gatherMapValue(valueNode, "ConstraintDescription"); err == nil {
			constraintDescription = scalarValue(n)
		}

		noEcho := false
		if _, n, err := gatherMapValue(valueNode, "NoEcho"); err == nil {
			noEcho = parseCfnBool(scalarValue(n))
		}

		// A constraint we can't represent degrades that single field to null.
		// Propagating the error would erase EVERY parameter in the template —
		// including the unrelated NoEcho credential parameters a policy is
		// looking for — over one bound on one parameter.
		minLength := optionalIntConstraint(valueNode, "MinLength", keyNode.Value)
		maxLength := optionalIntConstraint(valueNode, "MaxLength", keyNode.Value)
		minValue := optionalIntConstraint(valueNode, "MinValue", keyNode.Value)
		maxValue := optionalIntConstraint(valueNode, "MaxValue", keyNode.Value)

		defaultDict := optionalDict(valueNode, "Default", keyNode.Value)
		allowedValues := optionalDictList(valueNode, "AllowedValues", keyNode.Value)

		ctx, err := r.nodeContext(keyNode, valueNode)
		if err != nil {
			return nil, err
		}

		pkg, err := CreateResource(r.MqlRuntime, "cloudformation.parameter", map[string]*llx.RawData{
			"__id":                  llx.StringData(sectionMemberID(keyNode.Value, i)),
			"name":                  llx.StringData(keyNode.Value),
			"type":                  llx.StringData(paramType),
			"default":               llx.DictData(defaultDict),
			"description":           llx.StringData(description),
			"allowedValues":         llx.ArrayData(allowedValues, types.Dict),
			"allowedPattern":        llx.StringData(allowedPattern),
			"noEcho":                llx.BoolData(noEcho),
			"minLength":             llx.IntDataPtr(minLength),
			"maxLength":             llx.IntDataPtr(maxLength),
			"minValue":              llx.IntDataPtr(minValue),
			"maxValue":              llx.IntDataPtr(maxValue),
			"constraintDescription": llx.StringData(constraintDescription),
			"context":               llx.ResourceData(ctx, "cloudformation.context"),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, pkg)
	}

	return result, nil
}

func (r *mqlCloudformationTemplate) types() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CloudformationConnection)
	template := conn.CftTemplate()
	if template.Node == nil || len(template.Node.Content) == 0 {
		return nil, nil
	}
	// GetTypes iterates the Resources section assuming an even mapping and
	// dereferences Content[0]; skip when the template/Resources body is
	// degenerate or malformed so the upstream stride-2 access can't panic. A
	// missing Resources section is a valid empty state, but any other
	// gatherMapValue error is a real parse failure and must surface rather than
	// be swallowed as "no types."
	_, body, err := gatherMapValue(template.Node.Content[0], string(cft.Resources))
	if err != nil && status.Code(err) == codes.NotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if !isEvenMappingNode(body) {
		return nil, nil
	}

	// Collect the types locally rather than through cft.GetTypes, which fails
	// the whole call on the first resource without a literal Type (a
	// work-in-progress entry, or one whose Type arrives through a merge key
	// it does not resolve). One such entry must not empty the list.
	result := make([]any, 0, len(body.Content)/2)
	seen := make(map[string]struct{}, len(body.Content)/2)
	for i := 0; i < len(body.Content); i += 2 {
		_, typeNode, err := gatherMapValue(body.Content[i+1], "Type")
		if err != nil {
			continue
		}
		resourceType := scalarValue(typeNode)
		if resourceType == "" {
			continue
		}
		if _, ok := seen[resourceType]; ok {
			continue
		}
		seen[resourceType] = struct{}{}
		result = append(result, resourceType)
	}

	return result, nil
}
