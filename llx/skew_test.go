// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
)

const osProviderID = "go.mondoo.com/mql/providers/os"

func TestSkewPolicy(t *testing.T) {
	policy := llx.NewSkewPolicy(map[string]string{"os": "requires the os provider >= 99.0.0"})

	assert.NotEmpty(t, policy.Reason(osProviderID))
	assert.NotEmpty(t, policy.Reason("os"))
	// A schema whose provider id predates the current one still has to match.
	assert.NotEmpty(t, policy.Reason("go.mondoo.com/cnquery/v9/providers/os"))
	assert.Empty(t, policy.Reason("go.mondoo.com/mql/providers/aws"))
	assert.Empty(t, policy.Reason(""))

	// Nothing to excuse means no policy at all, and a nil policy excuses nothing.
	var nilPolicy *llx.SkewPolicy
	assert.Nil(t, llx.NewSkewPolicy(nil))
	assert.Nil(t, llx.NewSkewPolicy(map[string]string{}))
	assert.Empty(t, nilPolicy.Reason(osProviderID))
}

func TestIsUnavailable(t *testing.T) {
	assert.False(t, llx.IsUnavailable(nil))
	assert.False(t, llx.IsUnavailable(errors.New("something else")))
	assert.False(t, llx.IsUnavailable(&llx.ErrFieldNotFound{Resource: "a", Field: "b"}),
		"a field the reader never heard of is not by itself a skew excuse")
}

// writerSchema returns a copy of the runtime's schema carrying one field the
// runtime does not have: the writer-newer-than-reader case, in one process.
func writerSchema(t *testing.T, runtime llx.Runtime, field string, minVersion string) *resources.Schema {
	t.Helper()
	schema := &resources.Schema{
		Resources:    map[string]*resources.ResourceInfo{},
		Dependencies: map[string]*resources.ProviderInfo{},
	}
	schema.Add(runtime.Schema())

	cfg := schema.Resources["sshd.config"]
	require.NotNil(t, cfg)
	cfg.Fields[field] = &resources.Field{
		Name: field, Type: string(types.Bool),
		Provider: osProviderID, MinProviderVersion: minVersion,
	}
	if minVersion != "" {
		schema.ProviderVersions = map[string]string{osProviderID: minVersion}
	}
	return schema
}

func resultsOf(t *testing.T, runtime llx.Runtime, bundle *llx.CodeBundle) []*llx.RawResult {
	t.Helper()
	raw, err := exec.ExecuteCode(runtime, bundle, nil, mql.Features{})
	require.NoError(t, err)
	return llx.ReturnValuesV2(bundle, func(checksum string) (*llx.RawResult, bool) {
		res, ok := raw[checksum]
		return res, ok
	})
}

// A bundle compiled against a newer provider drops the fields this build could
// never have had, and runs everything else (ADR 040 part 4).
func TestUnavailableFieldDegradesInsteadOfFailingTheQuery(t *testing.T) {
	runtime := testutils.LinuxMock()

	// The reader declares an os version older than the field requires. This is
	// the evidence: without it a missing field is a bug, not skew.
	providers.Coordinator.Schema().(providers.ExtensibleSchema).Add("skew-test-reader", &resources.Schema{
		Resources:        map[string]*resources.ResourceInfo{},
		Dependencies:     map[string]*resources.ProviderInfo{},
		ProviderVersions: map[string]string{osProviderID: "13.0.0"},
	})

	writer := writerSchema(t, runtime, "futureField", "99.0.0")

	t.Run("the dropped field says why, and keeps its type", func(t *testing.T) {
		bundle, err := mqlc.Compile(`sshd.config.futureField`, nil, mqlc.NewConfig(writer, mql.Features{}))
		require.NoError(t, err)
		require.Equal(t, "99.0.0", bundle.MinProviderVersions["os"])

		results := resultsOf(t, runtime, bundle)
		require.Len(t, results, 1)
		data := results[0].Data

		assert.True(t, llx.IsUnavailable(data.Error), "got %v", data.Error)
		assert.Contains(t, data.Error.Error(), "requires the os provider >= 99.0.0")
		assert.Contains(t, data.Error.Error(), "13.0.0 is installed")
		assert.Nil(t, data.Value)
		// The reader's schema has no definition to take a type from, but the
		// compiler baked the writer's type into the chunk, so the stand-in is
		// still a bool rather than an untyped null.
		assert.Equal(t, types.Bool, data.Type)
	})

	t.Run("the rest of the query still runs", func(t *testing.T) {
		bundle, err := mqlc.Compile(`sshd.config { futureField ciphers }`, nil,
			mqlc.NewConfig(writer, mql.Features{}))
		require.NoError(t, err)

		results := resultsOf(t, runtime, bundle)
		require.NotEmpty(t, results)

		block, ok := results[0].Data.Value.(map[string]any)
		require.True(t, ok, "expected a block result")

		var sawCiphers, sawUnavailable bool
		for _, v := range block {
			field, ok := v.(*llx.RawData)
			if !ok {
				continue
			}
			if llx.IsUnavailable(field.Error) {
				sawUnavailable = true
			}
			if list, ok := field.Value.([]any); ok && len(list) > 0 {
				sawCiphers = true
			}
		}
		assert.True(t, sawUnavailable, "the missing field must be marked unavailable")
		assert.True(t, sawCiphers, "a field the reader does have must still resolve")
	})
}

// Absent provenance is absent information, not permission to drop fields. A
// missing field with nothing saying the bundle is newer stays a hard failure,
// because that is what a typo and a compiler defect look like.
func TestMissingFieldWithoutSkewEvidenceStillFails(t *testing.T) {
	runtime := testutils.LinuxMock()
	writer := writerSchema(t, runtime, "typoField", "")

	bundle, err := mqlc.Compile(`sshd.config.typoField`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)

	results := resultsOf(t, runtime, bundle)
	require.Len(t, results, 1)
	data := results[0].Data

	require.Error(t, data.Error)
	assert.False(t, llx.IsUnavailable(data.Error), "a field nothing excuses must not be excused")
	assert.Contains(t, data.Error.Error(), "cannot find field 'typoField'")
}

// Strict mode (ADR 043) turns a null binding into an error unless the author
// marked the link optional. An unavailable field must keep reporting the skew
// reason under strict rather than being replaced by the generic strict-mode
// message: the two say different things, and only one of them tells the reader
// their provider is too old.
//
// It holds because resolveNullBinding declines a binding that already carries
// an error, so the skew reason passes through untouched.
func TestUnavailableFieldKeepsItsReasonUnderStrictMode(t *testing.T) {
	runtime := testutils.LinuxMock()
	providers.Coordinator.Schema().(providers.ExtensibleSchema).Add("skew-test-strict", &resources.Schema{
		Resources:        map[string]*resources.ResourceInfo{},
		Dependencies:     map[string]*resources.ProviderInfo{},
		ProviderVersions: map[string]string{osProviderID: "13.0.0"},
	})
	writer := writerSchema(t, runtime, "futureField", "99.0.0")

	for _, strict := range []bool{false, true} {
		name := "non-strict"
		if strict {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			conf := mqlc.NewConfig(writer, mql.Features{})
			conf.Strict = strict

			bundle, err := mqlc.Compile(`sshd.config.futureField`, nil, conf)
			require.NoError(t, err)

			results := resultsOf(t, runtime, bundle)
			require.Len(t, results, 1)

			assert.True(t, llx.IsUnavailable(results[0].Data.Error), "got %v", results[0].Data.Error)
			assert.Contains(t, results[0].Data.Error.Error(), "requires the os provider >= 99.0.0")
			assert.NotContains(t, results[0].Data.Error.Error(), "the value it reads from is null")
		})
	}
}

// A whole resource the reader does not have degrades like a missing field.
// Handling only fields would make the behaviour depend on how far into a chain
// the version gap happens to fall.
func TestUnavailableResourceDegradesLikeAField(t *testing.T) {
	runtime := testutils.LinuxMock()
	providers.Coordinator.Schema().(providers.ExtensibleSchema).Add("skew-test-resource", &resources.Schema{
		Resources:        map[string]*resources.ResourceInfo{},
		Dependencies:     map[string]*resources.ProviderInfo{},
		ProviderVersions: map[string]string{osProviderID: "13.0.0"},
	})

	writer := &resources.Schema{
		Resources:    map[string]*resources.ResourceInfo{},
		Dependencies: map[string]*resources.ProviderInfo{},
	}
	writer.Add(runtime.Schema())
	writer.Resources["sshd.futureThing"] = &resources.ResourceInfo{
		Id: "sshd.futureThing", Name: "sshd.futureThing",
		Provider: osProviderID, MinProviderVersion: "99.0.0",
		Fields: map[string]*resources.Field{
			"enabled": {Name: "enabled", Type: string(types.Bool), Provider: osProviderID},
		},
	}
	writer.ProviderVersions = map[string]string{osProviderID: "99.0.0"}

	bundle, err := mqlc.Compile(`sshd.futureThing.enabled`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)

	results := resultsOf(t, runtime, bundle)
	require.Len(t, results, 1)
	assert.True(t, llx.IsUnavailable(results[0].Data.Error), "got %v", results[0].Data.Error)
	assert.Contains(t, results[0].Data.Error.Error(), "sshd.futureThing")
	assert.Contains(t, results[0].Data.Error.Error(), "requires the os provider >= 99.0.0")
}

// "Cannot run this part, or anything that depends on it": an unavailable value
// has to reach every expression built on it, rather than collapsing into a
// plain false. A null and an unavailable value are different claims - one says
// the field was read and holds nothing, the other says it was never read - and
// only the second should suppress the checks downstream of it.
func TestUnavailabilityPropagatesToDependents(t *testing.T) {
	runtime := testutils.LinuxMock()
	providers.Coordinator.Schema().(providers.ExtensibleSchema).Add("skew-test-prop", &resources.Schema{
		Resources:        map[string]*resources.ResourceInfo{},
		Dependencies:     map[string]*resources.ProviderInfo{},
		ProviderVersions: map[string]string{osProviderID: "13.0.0"},
	})
	writer := writerSchema(t, runtime, "futureField", "99.0.0")

	for _, query := range []string{
		`sshd.config.futureField`,
		`sshd.config.futureField && true`,
		`sshd.config.futureField && sshd.config.futureField`,
		`sshd.config.futureField || true`,
		`sshd.config.futureField == true`,
	} {
		t.Run(query, func(t *testing.T) {
			bundle, err := mqlc.Compile(query, nil, mqlc.NewConfig(writer, mql.Features{}))
			require.NoError(t, err)

			results := resultsOf(t, runtime, bundle)
			require.Len(t, results, 1)
			assert.True(t, llx.IsUnavailable(results[0].Data.Error),
				"an expression built on an unavailable value must stay unavailable, got %v",
				results[0].Data.Error)
		})
	}
}
