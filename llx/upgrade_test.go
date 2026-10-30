// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
)

// A field whose type changed between the bundle and this build is the one skew
// that has no symptom of its own: the name resolves on both sides, so nothing
// errors. It has to be found by comparing the writer's baked-in type against
// the reader's schema.
func TestFindTypeDriftSpotsAChangedFieldType(t *testing.T) {
	runtime := testutils.LinuxMock()

	// The writer had ciphers as a scalar string; this build has []string.
	writer := &resources.Schema{
		Resources:    map[string]*resources.ResourceInfo{},
		Dependencies: map[string]*resources.ProviderInfo{},
	}
	writer.Add(runtime.Schema())
	writer.Resources["sshd.config"].Fields["ciphers"] = &resources.Field{
		Name: "ciphers", Type: string(types.String), Provider: osProviderID,
	}

	bundle, err := mqlc.Compile(`sshd.config.ciphers`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)

	drift := llx.FindTypeDrift(bundle.CodeV2, runtime.Schema())
	require.Len(t, drift, 1)
	assert.Equal(t, "sshd.config", drift[0].Resource)
	assert.Equal(t, "ciphers", drift[0].Field)
	assert.Equal(t, types.String, drift[0].Writer)
	assert.Equal(t, types.Array(types.String), drift[0].Reader)

	report := llx.ReportTypeDrift(drift)
	assert.Contains(t, report, "sshd.config.ciphers")
	assert.Contains(t, report, "compiled as string")
	assert.Contains(t, report, "this build has []string")
}

// A bundle compiled against the same schema the reader has must report nothing,
// or the warning is noise on every single execution.
func TestFindTypeDriftIsSilentWhenSchemasAgree(t *testing.T) {
	runtime := testutils.LinuxMock()

	for _, query := range []string{
		`sshd.config.ciphers`,
		`sshd.config.ciphers.length`,
		`sshd.config { ciphers params }`,
		`sshd.config.params["PermitRootLogin"]`,
	} {
		t.Run(query, func(t *testing.T) {
			bundle, err := mqlc.Compile(query, nil, mqlc.NewConfig(runtime.Schema(), mql.Features{}))
			require.NoError(t, err)
			assert.Empty(t, llx.FindTypeDrift(bundle.CodeV2, runtime.Schema()))
			assert.Empty(t, llx.ReportTypeDrift(nil))
		})
	}
}

// A field the reader does not have at all is a different condition with its own
// handling, and must not also be reported as drift.
func TestFindTypeDriftIgnoresMissingFields(t *testing.T) {
	runtime := testutils.LinuxMock()
	writer := writerSchema(t, runtime, "futureField", "99.0.0")

	bundle, err := mqlc.Compile(`sshd.config.futureField`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)
	assert.Empty(t, llx.FindTypeDrift(bundle.CodeV2, runtime.Schema()))
}

// A chunk a downgrade patch already replaced is running by construction, so it
// must not then be reported as drifting.
func TestFindTypeDriftIgnoresPatchedChunks(t *testing.T) {
	runtime := testutils.LinuxMock()
	writer := translatable(t, runtime)

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)
	targetRef, target := findChunk(t, bundle.CodeV2, "cipherCount")
	blockRef := addTranslationBlock(bundle.CodeV2, target.Function.Binding)

	patched, installed := llx.Patch(bundle.CodeV2, []*llx.TranslationRef{{
		Ref: targetRef, Provider: osProviderID, BelowVersion: "99.0.0", BlockRef: blockRef,
	}}, map[string]string{osProviderID: "13.0.0"})
	require.Len(t, installed, 1)

	assert.Empty(t, llx.FindTypeDrift(patched, runtime.Schema()))
}

func TestReportTypeDriftTruncates(t *testing.T) {
	var drift []llx.TypeDrift
	for range 7 {
		drift = append(drift, llx.TypeDrift{
			Resource: "r", Field: "f", Writer: types.String, Reader: types.Int,
		})
	}
	assert.Contains(t, llx.ReportTypeDrift(drift), "and 4 more")
}
