// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"cloud.google.com/go/dlp/apiv2/dlppb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	dlpSensitivityScoreResource = "gcp.project.dlpService.sensitivityScore"
	dlpDataRiskLevelResource    = "gcp.project.dlpService.dataRiskLevel"
	dlpProfileStatusResource    = "gcp.project.dlpService.profileStatus"
)

// dlpSensitivityScoreArgs maps a sensitivity score onto resource arguments.
//
// The shipped dict claimed values of HIGH / MEDIUM_LOW and "numeric
// breakdowns". Neither is true: dlppb.SensitivityScore has exactly one field
// and the enum names are SENSITIVITY_*, so a policy written against the
// documented names never matched. SENSITIVITY_UNKNOWN is DLP saying it looked
// and could not tell, which the caller keeps distinct from no score at all by
// building no resource in that case.
func dlpSensitivityScoreArgs(parentID string, s *dlppb.SensitivityScore) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":  llx.StringData(parentID + "/sensitivityScore"),
		"score": llx.StringData(s.GetScore().String()),
	}
}

// dlpDataRiskLevelArgs maps a data risk level onto resource arguments.
// dlppb.DataRiskLevel likewise carries exactly one field.
func dlpDataRiskLevelArgs(parentID string, l *dlppb.DataRiskLevel) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":  llx.StringData(parentID + "/dataRiskLevel"),
		"score": llx.StringData(l.GetScore().String()),
	}
}

// dlpProfileStatusArgs maps the status of the last profile-generation attempt
// onto resource arguments.
//
// A non-zero code means the profile in hand is stale: DLP failed to regenerate
// it and the sensitivity and risk scores describe the data as it was at
// `timestamp`, not as it is now. The code stays null when the message carries
// no status, so "generation succeeded" (code 0) and "no status" stay
// distinguishable.
func dlpProfileStatusArgs(parentID string, s *dlppb.ProfileStatus) map[string]*llx.RawData {
	var code *int32
	var message string
	var ts *time.Time

	if st := s.GetStatus(); st != nil {
		c := st.Code
		code = &c
		message = st.Message
	}
	ts = timestampAsTimePtr(s.GetTimestamp())

	return map[string]*llx.RawData{
		"__id":          llx.StringData(parentID + "/profileStatus"),
		"statusCode":    llx.IntDataPtr(code),
		"statusMessage": llx.StringData(message),
		"timestamp":     llx.TimeDataPtr(ts),
	}
}

// newMqlDlpProfileScores builds the sensitivity and risk resources shared by
// every DLP data profile.
//
// Each stays null when the profile reports nothing for it, so an audit can tell
// "DLP has not scored this" apart from "DLP scored it as unknown". The cache
// keys are scoped to the profile, because the same resource types hang off a
// project, a table, a column and a file store profile.
func newMqlDlpProfileScores(runtime *plugin.Runtime, parentID string, s *dlppb.SensitivityScore, l *dlppb.DataRiskLevel) (map[string]*llx.RawData, error) {
	args := map[string]*llx.RawData{
		"sensitivity": llx.NilData,
		"riskLevel":   llx.NilData,
	}

	if s != nil {
		res, err := CreateResource(runtime, dlpSensitivityScoreResource, dlpSensitivityScoreArgs(parentID, s))
		if err != nil {
			return nil, err
		}
		args["sensitivity"] = llx.ResourceData(res, dlpSensitivityScoreResource)
	}

	if l != nil {
		res, err := CreateResource(runtime, dlpDataRiskLevelResource, dlpDataRiskLevelArgs(parentID, l))
		if err != nil {
			return nil, err
		}
		args["riskLevel"] = llx.ResourceData(res, dlpDataRiskLevelResource)
	}

	return args, nil
}

// newMqlDlpProfileStatus builds the generation-status resource of a data
// profile. Null when the profile carries no status, which is a different claim
// from a generation that succeeded.
func newMqlDlpProfileStatus(runtime *plugin.Runtime, parentID string, status *dlppb.ProfileStatus) (*llx.RawData, error) {
	if status == nil {
		return llx.NilData, nil
	}

	res, err := CreateResource(runtime, dlpProfileStatusResource, dlpProfileStatusArgs(parentID, status))
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, dlpProfileStatusResource), nil
}
