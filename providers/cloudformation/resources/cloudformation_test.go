// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudformation/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
)

// loadTemplateFromString writes content to a temp .yaml file and loads it as a
// cloudformation.template, so tests can exercise the parse paths without a
// committed fixture per case.
func loadTemplateFromString(t *testing.T, content string) *mqlCloudformationTemplate {
	t.Helper()
	path := filepath.Join(t.TempDir(), "template.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	tpl, err := loadTemplate(path)
	require.NoError(t, err)
	return tpl
}

func TestParseCfnBool(t *testing.T) {
	for _, s := range []string{"true", "True", "TRUE", "yes", "Yes", "on", "1", " true "} {
		assert.True(t, parseCfnBool(s), "%q should parse true", s)
	}
	for _, s := range []string{"false", "False", "no", "off", "0", "", "maybe"} {
		assert.False(t, parseCfnBool(s), "%q should parse false", s)
	}
}

// A scalar top-level Metadata member (Metadata is free-form) must not make the
// whole metadata() call error out and drop every member.
func TestMetadataScalarMemberDoesNotFail(t *testing.T) {
	tpl := loadTemplateFromString(t, `AWSTemplateFormatVersion: "2010-09-09"
Metadata:
  License: Apache-2.0
  Interface:
    ParameterGroups: []
Resources:
  Bucket:
    Type: AWS::S3::Bucket
`)
	md := tpl.GetMetadata()
	require.NoError(t, md.Error)
	assert.Equal(t, "Apache-2.0", md.Data["License"])
	assert.Contains(t, md.Data, "Interface")
}

// A resource with a malformed (scalar) Properties body must not sink the other
// valid resources in the template.
func TestResourcesMalformedPropertiesDegrades(t *testing.T) {
	tpl := loadTemplateFromString(t, `Resources:
  GoodBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
  BadBucket:
    Type: AWS::S3::Bucket
    Properties: "oops-this-is-a-string"
`)
	res := tpl.GetResources()
	require.NoError(t, res.Error)
	assert.Equal(t, 2, len(res.Data), "a malformed Properties must not drop sibling resources")
}

// An absent numeric constraint must resolve to null, distinct from an explicit
// MinValue: 0 (a legitimate CloudFormation value).
func TestParameterConstraintsNullable(t *testing.T) {
	tpl := loadTemplateFromString(t, `Parameters:
  WithMin:
    Type: Number
    MinValue: 0
  WithoutMin:
    Type: Number
`)
	params := tpl.GetParameterList()
	require.NoError(t, params.Error)

	byName := map[string]*mqlCloudformationParameter{}
	for _, p := range params.Data {
		mp := p.(*mqlCloudformationParameter)
		byName[mp.Name.Data] = mp
	}

	withMin := byName["WithMin"]
	require.NotNil(t, withMin)
	assert.Equal(t, int64(0), withMin.MinValue.Data)
	assert.Zero(t, withMin.MinValue.State&plugin.StateIsNull, "explicit MinValue: 0 must not be null")

	withoutMin := byName["WithoutMin"]
	require.NotNil(t, withoutMin)
	assert.NotZero(t, withoutMin.MinValue.State&plugin.StateIsNull, "absent MinValue must be null")

	// A null int field must serialize as a typed nil primitive (types.Nil),
	// NOT an untyped one — otherwise MQL surfaces "primitive with no type
	// information" when the field is queried. This is the full getter path a
	// `cloudformation.template.parameterList { minValue }` query exercises.
	dr := withoutMin.MinValue.ToDataRes(types.Int)
	require.Empty(t, dr.Error)
	require.NotNil(t, dr.Data)
	assert.Equal(t, string(types.Nil), dr.Data.Type, "null int must carry the nil type, not an empty type")
}

func TestNoEchoBooleanSpellings(t *testing.T) {
	tpl := loadTemplateFromString(t, `Parameters:
  Secret:
    Type: String
    NoEcho: yes
  Plain:
    Type: String
`)
	params := tpl.GetParameterList()
	require.NoError(t, params.Error)
	byName := map[string]*mqlCloudformationParameter{}
	for _, p := range params.Data {
		mp := p.(*mqlCloudformationParameter)
		byName[mp.Name.Data] = mp
	}
	assert.True(t, byName["Secret"].NoEcho.Data, "NoEcho: yes must parse true")
	assert.False(t, byName["Plain"].NoEcho.Data)
}

func loadTemplate(path string) (*mqlCloudformationTemplate, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	conn, err := connection.NewCloudformationConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{
					"path": path,
				},
			},
		},
	}, nil)
	if err != nil {
		return nil, err
	}

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	obj, err := NewResource(
		runtime,
		"cloudformation.template",
		map[string]*llx.RawData{},
	)
	if err != nil {
		return nil, err
	}

	tpl, ok := obj.(*mqlCloudformationTemplate)
	if !ok {
		return nil, errors.New("unexpected type")
	}
	return tpl, nil
}

func TestCloudformationResources(t *testing.T) {
	t.Run("cloudformation json template", func(t *testing.T) {
		path := "../testdata/cloudformation.json"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		assert.Equal(t, "2010-09-09", tpl.Version.Data)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 3, len(res.Data))

		params := tpl.GetParameters()
		require.NoError(t, params.Error)
		assert.Equal(t, 1, len(params.Data))
	})

	t.Run("cloudformation yaml template", func(t *testing.T) {
		path := "../testdata/cloudformation.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		assert.Equal(t, "2010-09-09", tpl.Version.Data)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 3, len(res.Data))

		params := tpl.GetParameters()
		require.NoError(t, params.Error)
		assert.Equal(t, 1, len(params.Data))
	})

	t.Run("cloudformation conditions", func(t *testing.T) {
		path := "../testdata/conditions.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetConditions()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
		val := res.Data["CreateProdResources"]
		assert.NotNil(t, val)
	})

	t.Run("sam globals", func(t *testing.T) {
		path := "../testdata/globals.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetGlobals()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
		val := res.Data["Function"]
		assert.NotNil(t, val)

		entries := val.(map[string]any)
		assert.Equal(t, "nodejs12.x", entries["Runtime"])
	})

	t.Run("cloudformation mappings", func(t *testing.T) {
		path := "../testdata/mappings.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetMappings()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
		val := res.Data["RegionMap"]
		assert.NotNil(t, val)

		entries := val.(map[string]any)
		entry := entries["us-east-1"].(map[string]any)
		assert.Equal(t, "ami-0ff8a91507f77f867", entry["HVM64"])
	})

	t.Run("cloudformation outputs", func(t *testing.T) {
		path := "../testdata/outputs.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetOutputs()
		require.NoError(t, res.Error)
		assert.Equal(t, 2, len(res.Data))

		found := false
		for i := range res.Data {
			assert.NotNil(t, res.Data[i])
			output := res.Data[i].(*mqlCloudformationOutput)
			if output.Name.Data == "BackupLoadBalancerDNSName" {
				props := output.Properties
				assert.Equal(t, "The DNSName of the backup load balancer", props.Data["Description"])
				found = true
			}
		}
		assert.Equal(t, true, found)
	})

	t.Run("cloudformation parameters", func(t *testing.T) {
		path := "../testdata/parameters.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetParameters()
		require.NoError(t, res.Error)
		assert.Equal(t, 2, len(res.Data))
	})

	t.Run("cloudformation resources", func(t *testing.T) {
		path := "../testdata/resources.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 3, len(res.Data))

		count := 0
		for i := range res.Data {
			assert.NotNil(t, res.Data[i])
			resource := res.Data[i].(*mqlCloudformationResource)
			if resource.Name.Data == "MyInstance" {
				props := resource.Properties
				assert.Equal(t, "ami-0ff8a91507f77f867", props.Data["ImageId"])
				count++
			}

			if resource.Name.Data == "HTTPlistener" {
				props := resource.Properties
				assert.Equal(t, float64(80), props.Data["Port"])
				count++
			}
		}
		assert.Equal(t, 2, count)
	})

	t.Run("cloudformation resources-custom", func(t *testing.T) {
		path := "../testdata/resources-custom.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
	})

	t.Run("cloudformation dependsOn", func(t *testing.T) {
		path := "../testdata/dependson.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 4, len(res.Data))

		for i := range res.Data {
			resource := res.Data[i].(*mqlCloudformationResource)
			switch resource.Name.Data {
			case "MySubnet":
				// single string DependsOn
				assert.Equal(t, []any{"MyVPC"}, resource.DependsOn.Data)
			case "MyInstance":
				// list DependsOn
				assert.Equal(t, []any{"MyVPC", "MySubnet"}, resource.DependsOn.Data)
			case "MyVPC", "MyQueue":
				// no DependsOn
				assert.Empty(t, resource.DependsOn.Data)
			}
		}
	})

	t.Run("cloudformation rules", func(t *testing.T) {
		path := "../testdata/rules.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetRules()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
		val := res.Data["ProdInstanceType"]
		assert.NotNil(t, val)
	})

	t.Run("cloudformation transform", func(t *testing.T) {
		path := "../testdata/transform.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		assert.Equal(t, []any{"MyMacro", "AWS::Serverless"}, tpl.Transform.Data)
	})

	t.Run("cloudformation scalar transform (SAM)", func(t *testing.T) {
		// The canonical SAM header `Transform: AWS::Serverless-2016-10-31` is a
		// scalar YAML node (no Content). It must surface as a single-element
		// list rather than null.
		path := "../testdata/transform-scalar.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		assert.Equal(t, []any{"AWS::Serverless-2016-10-31"}, tpl.Transform.Data)
	})

	t.Run("cloudformation resource policies + metadata", func(t *testing.T) {
		tpl, err := loadTemplate("../testdata/policies.yaml")
		require.NoError(t, err)

		res := tpl.GetResources()
		require.NoError(t, res.Error)

		byName := map[string]*mqlCloudformationResource{}
		for _, r := range res.Data {
			rr := r.(*mqlCloudformationResource)
			byName[rr.Name.Data] = rr
		}

		bucket := byName["RetainedBucket"]
		require.NotNil(t, bucket)
		assert.Equal(t, "Retain", bucket.DeletionPolicy.Data)
		assert.Equal(t, "Retain", bucket.UpdateReplacePolicy.Data)
		require.NotNil(t, bucket.ResourceMetadata.Data)
		require.NotEmpty(t, bucket.ResourceMetadata.Data)

		asg := byName["ASG"]
		require.NotNil(t, asg)
		require.NotNil(t, asg.CreationPolicy.Data)
		cp := asg.CreationPolicy.Data.(map[string]any)
		require.Contains(t, cp, "ResourceSignal")
		require.NotNil(t, asg.UpdatePolicy.Data)
		up := asg.UpdatePolicy.Data.(map[string]any)
		require.Contains(t, up, "AutoScalingRollingUpdate")

		// Resources without policies expose empty strings / nil dicts so
		// queries can distinguish "explicit Delete" from "unset".
		assert.Equal(t, "", asg.DeletionPolicy.Data)
		assert.Equal(t, "", asg.UpdateReplacePolicy.Data)
	})

	t.Run("cloudformation typed outputs", func(t *testing.T) {
		tpl, err := loadTemplate("../testdata/policies.yaml")
		require.NoError(t, err)

		res := tpl.GetOutputs()
		require.NoError(t, res.Error)

		byName := map[string]*mqlCloudformationOutput{}
		for _, o := range res.Data {
			oo := o.(*mqlCloudformationOutput)
			byName[oo.Name.Data] = oo
		}

		bucket := byName["BucketArn"]
		require.NotNil(t, bucket)
		assert.Equal(t, "ARN of the retained bucket", bucket.Description.Data)
		assert.Equal(t, "my-stack-BucketArn", bucket.ExportName.Data)
		assert.Equal(t, "", bucket.Condition.Data)
		require.NotNil(t, bucket.Value.Data)

		port := byName["DBPortValue"]
		require.NotNil(t, port)
		assert.Equal(t, "HasDB", port.Condition.Data)
		assert.Equal(t, "", port.ExportName.Data)
	})

	t.Run("cloudformation empty template guard", func(t *testing.T) {
		// A template carrying one section and no resources. Every lazy
		// accessor (resources, outputs, parameterList, etc.) must report
		// nothing rather than erroring or dereferencing a member that is not
		// there.
		//
		// This used to be a comments-only file, which reached the accessors
		// with an empty Node.Content. The connection now refuses a document
		// declaring no CloudFormation section at all, so that shape no longer
		// reaches here -- see TestCloudformationRejectsForeignDocuments, which
		// covers the empty and comment-only cases at the connection.
		tpl, err := loadTemplate("../testdata/empty.yaml")
		require.NoError(t, err)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Empty(t, res.Data)

		outs := tpl.GetOutputs()
		require.NoError(t, outs.Error)
		assert.Empty(t, outs.Data)

		params := tpl.GetParameterList()
		require.NoError(t, params.Error)
		assert.Empty(t, params.Data)
	})

	t.Run("cloudformation typed parameters", func(t *testing.T) {
		tpl, err := loadTemplate("../testdata/policies.yaml")
		require.NoError(t, err)

		res := tpl.GetParameterList()
		require.NoError(t, res.Error)
		require.Equal(t, 3, len(res.Data))

		byName := map[string]*mqlCloudformationParameter{}
		for _, p := range res.Data {
			pp := p.(*mqlCloudformationParameter)
			byName[pp.Name.Data] = pp
		}

		pw := byName["DBPassword"]
		require.NotNil(t, pw)
		assert.Equal(t, "String", pw.Type.Data)
		assert.True(t, pw.NoEcho.Data)
		assert.Equal(t, int64(8), pw.MinLength.Data)
		assert.Equal(t, int64(41), pw.MaxLength.Data)
		assert.Equal(t, "^[a-zA-Z0-9]*$", pw.AllowedPattern.Data)
		assert.Equal(t, "Must contain only alphanumeric characters.", pw.ConstraintDescription.Data)

		port := byName["DBPort"]
		require.NotNil(t, port)
		assert.Equal(t, "Number", port.Type.Data)
		assert.False(t, port.NoEcho.Data)
		assert.Equal(t, int64(1150), port.MinValue.Data)
		assert.Equal(t, int64(65535), port.MaxValue.Data)
		// Numeric defaults arrive as float64 because the dict primitive uses
		// JSON-style numeric typing.
		require.Equal(t, float64(3306), port.Default.Data)

		env := byName["Environment"]
		require.NotNil(t, env)
		require.Equal(t, []any{"production", "staging", "dev"}, env.AllowedValues.Data)
	})
}
