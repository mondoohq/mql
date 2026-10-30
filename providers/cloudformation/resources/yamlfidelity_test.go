// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resourcesByName(t *testing.T, tpl *mqlCloudformationTemplate) map[string]*mqlCloudformationResource {
	t.Helper()
	res := tpl.GetResources()
	require.NoError(t, res.Error)
	out := map[string]*mqlCloudformationResource{}
	for _, r := range res.Data {
		rr := r.(*mqlCloudformationResource)
		out[rr.Name.Data] = rr
	}
	return out
}

func outputsByName(t *testing.T, tpl *mqlCloudformationTemplate) map[string]*mqlCloudformationOutput {
	t.Helper()
	res := tpl.GetOutputs()
	require.NoError(t, res.Error)
	out := map[string]*mqlCloudformationOutput{}
	for _, r := range res.Data {
		rr := r.(*mqlCloudformationOutput)
		out[rr.Name.Data] = rr
	}
	return out
}

func parametersByName(t *testing.T, tpl *mqlCloudformationTemplate) map[string]*mqlCloudformationParameter {
	t.Helper()
	res := tpl.GetParameterList()
	require.NoError(t, res.Error)
	out := map[string]*mqlCloudformationParameter{}
	for _, r := range res.Data {
		rr := r.(*mqlCloudformationParameter)
		out[rr.Name.Data] = rr
	}
	return out
}

// BUG 1: a YAML alias in a resource's Properties must resolve to the anchored
// mapping. Blanking it makes a policy that asserts every bucket blocks public
// access pass vacuously on the aliased bucket.
func TestAliasInResourceProperties(t *testing.T) {
	tpl := loadTemplateFromString(t, `Resources:
  A:
    Type: AWS::S3::Bucket
    Properties: &p
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
  B:
    Type: AWS::S3::Bucket
    Properties: *p
`)
	byName := resourcesByName(t, tpl)
	require.Len(t, byName, 2)
	for _, name := range []string{"A", "B"} {
		props := byName[name].Properties.Data
		require.Contains(t, props, "PublicAccessBlockConfiguration", "%s must carry the anchored properties", name)
		pab := props["PublicAccessBlockConfiguration"].(map[string]any)
		assert.Equal(t, true, pab["BlockPublicAcls"])
	}
}

// BUG 1: an alias inside an output Value erased every output in the template.
func TestAliasInOutputValue(t *testing.T) {
	tpl := loadTemplateFromString(t, `Resources:
  A:
    Type: AWS::S3::Bucket
Outputs:
  First:
    Value: &v
      Fn::GetAtt: [A, Arn]
  Second:
    Value: *v
`)
	byName := outputsByName(t, tpl)
	require.Len(t, byName, 2, "an aliased output Value must not erase the outputs list")
	for _, name := range []string{"First", "Second"} {
		val, ok := byName[name].Value.Data.(map[string]any)
		require.True(t, ok, "%s Value must resolve to a mapping", name)
		assert.Contains(t, val, "Fn::GetAtt")
	}
}

// BUG 1: an alias inside a parameter Default erased every parameter.
func TestAliasInParameterDefault(t *testing.T) {
	tpl := loadTemplateFromString(t, `Parameters:
  A:
    Type: String
    Default: &d "hello"
  B:
    Type: String
    Default: *d
  Secret:
    Type: String
    NoEcho: true
`)
	byName := parametersByName(t, tpl)
	require.Len(t, byName, 3, "an aliased Default must not erase the parameter list")
	assert.Equal(t, "hello", byName["A"].Default.Data)
	assert.Equal(t, "hello", byName["B"].Default.Data)
	assert.True(t, byName["Secret"].NoEcho.Data)
}

// BUG 1: an alias inside Mappings erased the whole section.
func TestAliasInMappings(t *testing.T) {
	tpl := loadTemplateFromString(t, `Mappings:
  Base:
    Config: &c
      Instances: 3
  Prod:
    Config: *c
`)
	m := tpl.GetMappings()
	require.NoError(t, m.Error)
	require.Len(t, m.Data, 2, "an aliased mapping member must not erase the section")
	prod := m.Data["Prod"].(map[string]any)
	cfg := prod["Config"].(map[string]any)
	assert.Equal(t, float64(3), cfg["Instances"])
}

// BUG 1: an alias inside Conditions erased the whole section.
func TestAliasInConditions(t *testing.T) {
	tpl := loadTemplateFromString(t, `Conditions:
  IsProd: &prod
    Fn::Equals: [prod, prod]
  AlsoProd: *prod
`)
	c := tpl.GetConditions()
	require.NoError(t, c.Error)
	require.Len(t, c.Data, 2, "an aliased condition must not erase the section")
	assert.NotNil(t, c.Data["AlsoProd"])
}

// BUG 2: a merge key must contribute Type (and the other scalar attributes) to
// the merged resource, or every type-scoped control silently skips it.
func TestMergeKeyResolvesResourceAttributes(t *testing.T) {
	tpl := loadTemplateFromString(t, `Base: &base
  Type: AWS::S3::Bucket
  DeletionPolicy: Retain
Resources:
  A:
    <<: *base
    Properties:
      BucketName: x
  B:
    Type: AWS::SQS::Queue
`)
	byName := resourcesByName(t, tpl)
	require.Len(t, byName, 2)
	assert.Equal(t, "AWS::S3::Bucket", byName["A"].Type.Data, "merge key must supply Type")
	assert.Equal(t, "Retain", byName["A"].DeletionPolicy.Data, "merge key must supply DeletionPolicy")

	types := tpl.GetTypes()
	require.NoError(t, types.Error)
	assert.ElementsMatch(t, []any{"AWS::S3::Bucket", "AWS::SQS::Queue"}, types.Data)
}

// BUG 2: an explicit key must win over the same key coming from a merge.
func TestMergeKeyExplicitKeyWins(t *testing.T) {
	tpl := loadTemplateFromString(t, `Base: &base
  Type: AWS::S3::Bucket
Resources:
  A:
    <<: *base
    Type: AWS::SQS::Queue
`)
	byName := resourcesByName(t, tpl)
	assert.Equal(t, "AWS::SQS::Queue", byName["A"].Type.Data)
}

// BUG 3: a null resource body (routine work-in-progress) erased every resource.
func TestNullResourceBodyKeepsSiblings(t *testing.T) {
	tpl := loadTemplateFromString(t, `Resources:
  MyBucket:
  MyQueue:
    Type: AWS::SQS::Queue
`)
	byName := resourcesByName(t, tpl)
	require.Len(t, byName, 2, "a null resource body must not erase its siblings")
	assert.Equal(t, "AWS::SQS::Queue", byName["MyQueue"].Type.Data)
	assert.Equal(t, "", byName["MyBucket"].Type.Data)
}

// BUG 3: a null output body erased every output.
func TestNullOutputBodyKeepsSiblings(t *testing.T) {
	tpl := loadTemplateFromString(t, `Outputs:
  Empty:
  Real:
    Value: hello
`)
	byName := outputsByName(t, tpl)
	require.Len(t, byName, 2, "a null output body must not erase its siblings")
	assert.Equal(t, "hello", byName["Real"].Value.Data)
}

// BUG 3: a scalar parameter body erased every parameter, including the NoEcho
// credential parameter a policy hunts for.
func TestScalarParameterBodyKeepsSiblings(t *testing.T) {
	tpl := loadTemplateFromString(t, `Parameters:
  Foo: bar
  Secret:
    Type: String
    NoEcho: true
`)
	byName := parametersByName(t, tpl)
	require.Len(t, byName, 2, "a scalar parameter body must not erase its siblings")
	assert.True(t, byName["Secret"].NoEcho.Data)
}

// BUG 3: AllowedValues written as a scalar instead of a list erased every
// parameter.
func TestScalarAllowedValuesKeepsParameters(t *testing.T) {
	tpl := loadTemplateFromString(t, `Parameters:
  Env:
    Type: String
    AllowedValues: prod
  Secret:
    Type: String
    NoEcho: true
`)
	byName := parametersByName(t, tpl)
	require.Len(t, byName, 2, "a scalar AllowedValues must not erase the parameter list")
	assert.True(t, byName["Secret"].NoEcho.Data)
	assert.Empty(t, byName["Env"].AllowedValues.Data)
}

// BUG 4: YAML keeps duplicate mapping keys, so two resources can share a
// logical ID. They must not collapse onto the first one's data.
func TestDuplicateLogicalIdsAreDistinct(t *testing.T) {
	tpl := loadTemplateFromString(t, `Resources:
  Dup:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: first
  Dup:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: second
`)
	res := tpl.GetResources()
	require.NoError(t, res.Error)
	require.Len(t, res.Data, 2)

	seen := map[string]bool{}
	for _, r := range res.Data {
		seen[r.(*mqlCloudformationResource).Type.Data] = true
	}
	assert.True(t, seen["AWS::S3::Bucket"], "the first duplicate must be reported")
	assert.True(t, seen["AWS::SQS::Queue"], "the second duplicate must not alias to the first")
}

func TestDuplicateOutputAndParameterIdsAreDistinct(t *testing.T) {
	tpl := loadTemplateFromString(t, `Parameters:
  Dup:
    Type: String
  Dup:
    Type: Number
Outputs:
  Dup:
    Value: first
  Dup:
    Value: second
`)
	params := tpl.GetParameterList()
	require.NoError(t, params.Error)
	require.Len(t, params.Data, 2)
	paramTypes := map[string]bool{}
	for _, p := range params.Data {
		paramTypes[p.(*mqlCloudformationParameter).Type.Data] = true
	}
	assert.True(t, paramTypes["String"])
	assert.True(t, paramTypes["Number"], "the second duplicate parameter must not alias to the first")

	outs := tpl.GetOutputs()
	require.NoError(t, outs.Error)
	require.Len(t, outs.Data, 2)
	outValues := map[any]bool{}
	for _, o := range outs.Data {
		outValues[o.(*mqlCloudformationOutput).Value.Data] = true
	}
	assert.True(t, outValues["first"])
	assert.True(t, outValues["second"], "the second duplicate output must not alias to the first")
}

// BUG 5: a bool/number/null mapping key made the whole section fail to
// serialize, taking every other mapping with it.
func TestNonStringMappingKeys(t *testing.T) {
	tpl := loadTemplateFromString(t, `Mappings:
  EnableByEnv:
    true:
      Instances: 3
    false:
      Instances: 1
  RegionMap:
    us-east-1:
      HVM64: ami-1234
`)
	m := tpl.GetMappings()
	require.NoError(t, m.Error)
	require.Len(t, m.Data, 2, "a non-string mapping key must not erase the section")

	byEnv := m.Data["EnableByEnv"].(map[string]any)
	on := byEnv["true"].(map[string]any)
	assert.Equal(t, float64(3), on["Instances"])
	off := byEnv["false"].(map[string]any)
	assert.Equal(t, float64(1), off["Instances"])
}

// BUG 6: one resource without a literal Type emptied the whole types() list.
func TestTypesSkipsResourceWithoutType(t *testing.T) {
	tpl := loadTemplateFromString(t, `Resources:
  Good:
    Type: AWS::S3::Bucket
  AlsoGood:
    Type: AWS::SQS::Queue
  Bad:
    Properties:
      Foo: bar
`)
	types := tpl.GetTypes()
	require.NoError(t, types.Error, "a resource without Type must not empty the type list")
	assert.ElementsMatch(t, []any{"AWS::S3::Bucket", "AWS::SQS::Queue"}, types.Data)
}

// BUG 7: a non-scalar DependsOn entry became a phantom "" dependency.
func TestDependsOnSkipsNonScalarEntries(t *testing.T) {
	tpl := loadTemplateFromString(t, `Resources:
  A:
    Type: AWS::S3::Bucket
  B:
    Type: AWS::SQS::Queue
    DependsOn:
      - A
      - Nested: thing
`)
	byName := resourcesByName(t, tpl)
	assert.Equal(t, []any{"A"}, byName["B"].DependsOn.Data, "a mapping entry must not become an empty dependency")
}

// BUG 8: the test harness dropped the connection error, so an unparseable
// template nil-dereferenced instead of reporting the parse failure.
func TestLoadTemplateReportsParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.yaml")
	require.NoError(t, os.WriteFile(path, []byte("Resources:\n\tBucket: oops\n"), 0o600))
	_, err := loadTemplate(path)
	require.Error(t, err, "an unparseable template must surface the parse error")
}
