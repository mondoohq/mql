// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func testFineTuningJob(id, fineTunedModel string) *mqlOpenaiFineTuningJob {
	return &mqlOpenaiFineTuningJob{
		Id:             plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
		FineTunedModel: plugin.TValue[string]{Data: fineTunedModel, State: plugin.StateIsSet},
	}
}

// Synthetic: a succeeded job, a job still running and a second succeeded job;
// no live organization was checked.
func TestJobProducingModel(t *testing.T) {
	done := testFineTuningJob("ftjob-1", "ft:gpt-4o-mini:org:triage:abc123")
	running := testFineTuningJob("ftjob-2", "")
	other := testFineTuningJob("ftjob-3", "ft:gpt-4o-mini:org:triage:def456")
	jobs := []any{done, running, other}

	assert.Same(t, done, jobProducingModel(jobs, "ft:gpt-4o-mini:org:triage:abc123"))
	assert.Same(t, other, jobProducingModel(jobs, "ft:gpt-4o-mini:org:triage:def456"))
	// a checkpoint model or a model whose job is not listed has no producer
	assert.Nil(t, jobProducingModel(jobs, "ft:gpt-4o-mini:org:triage:abc123:ckpt-step-10"))
	// an empty id must not match a job that has not produced a model yet
	assert.Nil(t, jobProducingModel(jobs, ""))
}
