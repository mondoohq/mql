// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/datasafe"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// The security assessment header says a database was assessed. The findings
// say what the assessment concluded, which is the half that carries the
// answer: an assessment exists and is ACTIVE whether every check passed or
// every one failed.

// ociDataSafeFindingID keys a finding by the assessment that produced it and
// the target database it was raised against, as well as by its own key.
//
// A finding key is unique within one assessment run against one target, and
// both dimensions repeat. A COMPARTMENT-type assessment covers every target in
// a compartment and reports the same check once per target; a LATEST and a
// SAVED assessment of the same target report the same key again. Keying on the
// finding alone would collide across both, and CreateResource answers a
// repeated id with the cached first instance - so the second database's
// finding would report the first one's severity, and
// `findings.none(severity == "HIGH")` would pass on a database that has one.
func ociDataSafeFindingID(assessmentID, targetID, key string) string {
	return assessmentID + "/" + targetID + "/" + key
}

// ociDataSafeFindingRiskAccepted reports whether an operator has waived the
// finding outright.
//
// Data Safe lets a user overwrite a finding's severity. Setting it to PASS
// makes a reported risk stop counting against the assessment even though
// nothing about the database changed, so the waiver is a finding in its own
// right. It requires both halves: a finding Data Safe itself graded PASS was
// never a risk, and reading it as an accepted one would report clean checks as
// suppressed ones.
func ociDataSafeFindingRiskAccepted(f datasafe.FindingSummary) bool {
	return boolValue(f.IsRiskModified) && f.Severity == datasafe.FindingSummarySeverityPass
}

// ociDataSafeFindingOpenDeferral reports whether the finding is suppressed by a
// deferral that has not yet lapsed.
//
// A deferral is a severity of DEFERRED with an optional end date. No end date
// means it never lapses, so it is open. Once the date has passed the
// suppression no longer applies even though the severity still reads DEFERRED,
// which is the case that makes this a computed field rather than a comparison
// a caller could write against severity.
func ociDataSafeFindingOpenDeferral(f datasafe.FindingSummary, now time.Time) bool {
	if f.Severity != datasafe.FindingSummarySeverityDeferred {
		return false
	}
	if f.TimeValidUntil == nil {
		return true
	}
	return f.TimeValidUntil.Time.After(now)
}

// ociDataSafeFindingDetails unwraps a finding's assessed values.
//
// Deliberately not routed through convert.JsonToDict. The SDK types this
// `*interface{}` because the shape varies by check, and in practice Data Safe
// answers with a plain multi-line string naming the accounts or parameters the
// check read - which JsonToDict rejects outright, since it unmarshals into a
// map. That failure took down the whole findings list for an assessment rather
// than one field of one finding.
//
// The value already comes out of encoding/json, so it holds only JSON-native
// types and needs no further conversion to be a dict.
func ociDataSafeFindingDetails(details *any) any {
	if details == nil {
		return nil
	}
	return *details
}

// ociDataSafeFindingReferences maps a finding onto the compliance sections it
// satisfies, keyed by the framework identifier the API reports.
//
// Empty entries are dropped rather than reported as empty strings: a framework
// the check does not map to should be absent from the map, so
// `references["gdpr"] != null` answers "does this check carry a GDPR section"
// rather than always being true.
func ociDataSafeFindingReferences(r *datasafe.References) map[string]any {
	out := map[string]any{}
	if r == nil {
		return out
	}
	add := func(key string, value *string) {
		if v := stringValue(value); v != "" {
			out[key] = v
		}
	}
	add("stig", r.Stig)
	add("cis", r.Cis)
	add("gdpr", r.Gdpr)
	add("obp", r.Obp)
	add("orp", r.Orp)
	return out
}

type mqlOciDataSafeFindingInternal struct {
	cacheAssessment *mqlOciDataSafeSecurityAssessment
	cacheTargetID   string
}

// findings lists the individual check results the assessment produced.
func (o *mqlOciDataSafeSecurityAssessment) findings() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// The assessment is regional, and its findings are served by the same
	// regional endpoint it was listed from.
	svc, err := conn.DataSafeClient(o.Region.Data)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]datasafe.FindingSummary, *string, error) {
		resp, err := svc.ListFindings(ctx, datasafe.ListFindingsRequest{
			SecurityAssessmentId: new(o.Id.Data),
			Page:                 page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		// Deliberately not swallowed. The sibling Data Safe listers tolerate a
		// per-region failure because a region without Data Safe is an expected
		// absence, but an assessment that was just listed exists by
		// construction - so a failure here is a real one, and answering it with
		// an empty list would report an assessment with failing checks as an
		// assessment with none.
		return nil, err
	}

	now := time.Now().UTC()
	res := make([]any, 0, len(items))
	for i := range items {
		f := items[i]

		targetID := stringValue(f.TargetId)
		args := map[string]*llx.RawData{
			"__id":                        llx.StringData(ociDataSafeFindingID(o.Id.Data, targetID, stringValue(f.Key))),
			"key":                         llx.StringDataPtr(f.Key),
			"title":                       llx.StringDataPtr(f.Title),
			"category":                    llx.StringDataPtr(f.Category),
			"severity":                    llx.StringData(string(f.Severity)),
			"oracleDefinedSeverity":       llx.StringData(string(f.OracleDefinedSeverity)),
			"isRiskModified":              llx.BoolData(boolValue(f.IsRiskModified)),
			"isRiskAccepted":              llx.BoolData(ociDataSafeFindingRiskAccepted(f)),
			"hasOpenDeferral":             llx.BoolData(ociDataSafeFindingOpenDeferral(f, now)),
			"hasTargetDbRiskLevelChanged": llx.BoolData(boolValue(f.HasTargetDbRiskLevelChanged)),
			"isTopFinding":                llx.BoolData(boolValue(f.IsTopFinding)),
			"justification":               llx.StringDataPtr(f.Justification),
			// Ptr rather than a zero time: a finding with no end date on its
			// severity change must not report 1 January year 1 as one.
			"validUntil":       sdkTimeData(f.TimeValidUntil),
			"summary":          llx.StringDataPtr(f.Summary),
			"remarks":          llx.StringDataPtr(f.Remarks),
			"oneline":          llx.StringDataPtr(f.Oneline),
			"details":          llx.DictData(ociDataSafeFindingDetails(f.Details)),
			"documentation":    llx.StringDataPtr(f.Doclink),
			"references":       llx.MapData(ociDataSafeFindingReferences(f.References), types.String),
			"lifecycleState":   llx.StringData(string(f.LifecycleState)),
			"lifecycleDetails": llx.StringDataPtr(f.LifecycleDetails),
			"timeUpdated":      sdkTimeData(f.TimeUpdated),
		}

		mqlFinding, err := CreateResource(o.MqlRuntime, "oci.dataSafe.finding", args)
		if err != nil {
			return nil, err
		}
		typed := mqlFinding.(*mqlOciDataSafeFinding)
		typed.cacheAssessment = o
		typed.cacheTargetID = targetID
		res = append(res, typed)
	}

	return res, nil
}

// assessment returns the assessment that produced the finding.
//
// Held as the resource itself rather than as an OCID to resolve later: the
// finding is only ever created from an assessment, so the answer is in hand
// and no lookup is needed.
func (o *mqlOciDataSafeFinding) assessment() (*mqlOciDataSafeSecurityAssessment, error) {
	if o.cacheAssessment == nil {
		o.Assessment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return o.cacheAssessment, nil
}

// targetDatabase resolves the database the finding was raised against.
//
// Matched against the already-fetched target listing rather than through
// NewResource, which would run an init before the runtime cache is consulted
// and so cost one API call per finding - thousands of them for one assessment,
// to answer with records already in hand.
func (o *mqlOciDataSafeFinding) targetDatabase() (*mqlOciDataSafeTargetDatabase, error) {
	if o.cacheTargetID == "" {
		o.TargetDatabase.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	obj, err := CreateResource(o.MqlRuntime, "oci.dataSafe", nil)
	if err != nil {
		return nil, err
	}
	targets := obj.(*mqlOciDataSafe).GetTargetDatabases()
	if targets.Error != nil {
		return nil, targets.Error
	}

	for _, raw := range targets.Data {
		t, ok := raw.(*mqlOciDataSafeTargetDatabase)
		if ok && t.Id.Data == o.cacheTargetID {
			return t, nil
		}
	}

	// A target in a compartment the caller cannot read, or one deregistered
	// since the assessment ran, lands here.
	o.TargetDatabase.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
