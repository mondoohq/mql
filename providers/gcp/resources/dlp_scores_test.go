// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"cloud.google.com/go/dlp/apiv2/dlppb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The shipped docs claimed the score dict carried HIGH / MEDIUM_LOW values and
// "numeric breakdowns". Neither is true: the message has exactly one field and
// the enum names are SENSITIVITY_*. A policy written against the documented
// names never matched anything.
func TestDlpSensitivityScoreArgs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		score *dlppb.SensitivityScore
		want  string
	}{
		{"high", &dlppb.SensitivityScore{Score: dlppb.SensitivityScore_SENSITIVITY_HIGH}, "SENSITIVITY_HIGH"},
		{"moderate", &dlppb.SensitivityScore{Score: dlppb.SensitivityScore_SENSITIVITY_MODERATE}, "SENSITIVITY_MODERATE"},
		{"low", &dlppb.SensitivityScore{Score: dlppb.SensitivityScore_SENSITIVITY_LOW}, "SENSITIVITY_LOW"},
		// DLP looked and could not tell. Distinct from no score at all, which
		// the caller reports by building no resource.
		{"unknown", &dlppb.SensitivityScore{Score: dlppb.SensitivityScore_SENSITIVITY_UNKNOWN}, "SENSITIVITY_UNKNOWN"},
		{"unspecified", &dlppb.SensitivityScore{}, "SENSITIVITY_SCORE_UNSPECIFIED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := dlpSensitivityScoreArgs("profiles/one", tc.score)
			assert.Equal(t, tc.want, args["score"].Value)
		})
	}
}

func TestDlpDataRiskLevelArgs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		level *dlppb.DataRiskLevel
		want  string
	}{
		{"high", &dlppb.DataRiskLevel{Score: dlppb.DataRiskLevel_RISK_HIGH}, "RISK_HIGH"},
		{"moderate", &dlppb.DataRiskLevel{Score: dlppb.DataRiskLevel_RISK_MODERATE}, "RISK_MODERATE"},
		{"low", &dlppb.DataRiskLevel{Score: dlppb.DataRiskLevel_RISK_LOW}, "RISK_LOW"},
		{"unknown", &dlppb.DataRiskLevel{Score: dlppb.DataRiskLevel_RISK_UNKNOWN}, "RISK_UNKNOWN"},
		{"unspecified", &dlppb.DataRiskLevel{}, "RISK_SCORE_UNSPECIFIED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := dlpDataRiskLevelArgs("profiles/one", tc.level)
			assert.Equal(t, tc.want, args["score"].Value)
		})
	}
}

// The same three resource types hang off a project, a table, a column and a
// file store profile, so the cache key has to carry the profile. Without it
// every profile in a scan would report the first one's scores.
func TestDlpScoreArgsScopeTheCacheKeyToTheProfile(t *testing.T) {
	a := dlpSensitivityScoreArgs("profiles/a", &dlppb.SensitivityScore{})
	b := dlpSensitivityScoreArgs("profiles/b", &dlppb.SensitivityScore{})
	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)

	// The three resources hanging off one profile also need distinct keys, or
	// the risk level resolves to the sensitivity score.
	sensitivity := dlpSensitivityScoreArgs("profiles/a", &dlppb.SensitivityScore{})
	risk := dlpDataRiskLevelArgs("profiles/a", &dlppb.DataRiskLevel{})
	status := dlpProfileStatusArgs("profiles/a", &dlppb.ProfileStatus{})
	assert.NotEqual(t, sensitivity["__id"].Value, risk["__id"].Value)
	assert.NotEqual(t, sensitivity["__id"].Value, status["__id"].Value)
	assert.NotEqual(t, risk["__id"].Value, status["__id"].Value)
}

// A failed regeneration is the difference between a current profile and a stale
// one, so the code, the message, and the time of the attempt all have to survive.
func TestDlpProfileStatusArgsFailedGeneration(t *testing.T) {
	when := time.Date(2024, 7, 4, 9, 30, 0, 0, time.UTC)
	args := dlpProfileStatusArgs("profiles/one", &dlppb.ProfileStatus{
		Status:    &status.Status{Code: 7, Message: "permission denied on the source table"},
		Timestamp: timestamppb.New(when),
	})

	assert.EqualValues(t, 7, args["statusCode"].Value)
	assert.Equal(t, "permission denied on the source table", args["statusMessage"].Value)
	got, ok := args["timestamp"].Value.(*time.Time)
	require.True(t, ok)
	assert.Equal(t, when, got.UTC())
}

// Code 0 is a successful generation. It has to read as 0, not as null, or a
// check for "the profile generated cleanly" cannot be written.
func TestDlpProfileStatusArgsSuccessIsZeroNotNull(t *testing.T) {
	args := dlpProfileStatusArgs("profiles/one", &dlppb.ProfileStatus{
		Status: &status.Status{Code: 0},
	})

	assert.EqualValues(t, 0, args["statusCode"].Value)
	assert.Equal(t, "", args["statusMessage"].Value)
}

// A status message with no rpc status must leave the code null rather than
// collapsing onto 0, which would report an unrun generation as a successful
// one. The timestamp must likewise stay null rather than becoming the zero time.
func TestDlpProfileStatusArgsPartial(t *testing.T) {
	partial := dlpProfileStatusArgs("profiles/one", &dlppb.ProfileStatus{Timestamp: timestamppb.Now()})
	assert.Nil(t, partial["statusCode"].Value)
	assert.Equal(t, "", partial["statusMessage"].Value)
	assert.NotNil(t, partial["timestamp"].Value)

	noTimestamp := dlpProfileStatusArgs("profiles/one", &dlppb.ProfileStatus{
		Status: &status.Status{Code: 2, Message: "unknown"},
	})
	assert.Nil(t, noTimestamp["timestamp"].Value)
}
