// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fex

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFexToDocument(t *testing.T) {
	f := &FindingExchange{Id: "finding-1"}

	doc := FexToDocument(f)

	require.NotNil(t, doc)
	require.Same(t, f, doc.GetFex())
	assert.Nil(t, doc.GetVex())
}

func TestFexToDocuments(t *testing.T) {
	fexes := []*FindingExchange{{Id: "a"}, {Id: "b"}}

	docs := FexToDocuments(fexes)

	require.Len(t, docs, 2)
	assert.Equal(t, "a", docs[0].GetFex().GetId())
	assert.Equal(t, "b", docs[1].GetFex().GetId())

	assert.Empty(t, FexToDocuments(nil))
}

func TestVexToDocument(t *testing.T) {
	v := &VulnerabilityExchange{Id: "CVE-2026-0001"}

	doc := VexToDocument(v)

	require.NotNil(t, doc)
	require.Same(t, v, doc.GetVex())
	assert.Nil(t, doc.GetFex())
}

func TestVexToDocuments(t *testing.T) {
	vexes := []*VulnerabilityExchange{{Id: "CVE-1"}, {Id: "CVE-2"}}

	docs := VexToDocuments(vexes)

	require.Len(t, docs, 2)
	assert.Equal(t, "CVE-1", docs[0].GetVex().GetId())
	assert.Equal(t, "CVE-2", docs[1].GetVex().GetId())

	assert.Empty(t, VexToDocuments(nil))
}

func TestNewRemediation(t *testing.T) {
	r := NewRemediation("upgrade", "bump to 1.2.3", "https://example.com/advisory")

	require.NotNil(t, r)
	assert.Equal(t, Remediation_Fix, r.GetCategory())
	assert.Equal(t, "upgrade", r.GetSummary())
	assert.Equal(t, "bump to 1.2.3", r.GetDetails())
	assert.Equal(t, "https://example.com/advisory", r.GetUrl())
}

func TestHttpRequestEvidenceRoundTrip(t *testing.T) {
	f := &FindingExchange{
		Id: "xss-1",
		Evidences: []*Evidence{{
			Details: &Evidence_HttpRequest{HttpRequest: &HttpRequest{
				Method:   "GET",
				Url:      "https://example.com/search?q=x",
				Param:    "q",
				Attack:   "<script>alert(1)</script>",
				Evidence: "<script>alert(1)</script>",
			}},
		}},
	}
	data, err := f.MarshalVT()
	require.NoError(t, err)

	out := &FindingExchange{}
	require.NoError(t, out.UnmarshalVT(data))

	hr := out.GetEvidences()[0].GetHttpRequest()
	require.NotNil(t, hr)
	assert.Equal(t, "GET", hr.GetMethod())
	assert.Equal(t, "q", hr.GetParam())
	assert.Equal(t, "https://example.com/search?q=x", hr.GetUrl())
}

func TestSourceVersionEvidenceRoundTrip(t *testing.T) {
	when := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	f := &FindingExchange{
		Id: "secret-1",
		Evidences: []*Evidence{{
			Details: &Evidence_File{File: &File{
				Path:     "config.env",
				Contents: "sk_live_...",
			}},
			SourceVersion: &SourceVersion{
				Commit: "096bccac898275dadd52c326756d98249599f534",
				Author: "Alice Introducer",
				Email:  "alice@example.com",
				Date:   timestamppb.New(when),
				Url:    "https://github.com/acme/repo/commit/096bccac",
			},
		}},
	}
	data, err := f.MarshalVT()
	require.NoError(t, err)

	out := &FindingExchange{}
	require.NoError(t, out.UnmarshalVT(data))

	sv := out.GetEvidences()[0].GetSourceVersion()
	require.NotNil(t, sv)
	assert.Equal(t, "096bccac898275dadd52c326756d98249599f534", sv.GetCommit())
	assert.Equal(t, "Alice Introducer", sv.GetAuthor())
	assert.Equal(t, "alice@example.com", sv.GetEmail())
	assert.True(t, when.Equal(sv.GetDate().AsTime()))
	assert.Equal(t, "https://github.com/acme/repo/commit/096bccac", sv.GetUrl())
}

// uploadSetRequest is one part of an upload set with every field that
// carries the set, its counts, the ref and the run metadata.
// Synthetic: field coverage for the upload-set fields; no producer sends
// these yet.
func uploadSetRequest() *FindingsUploadRequest {
	return &FindingsUploadRequest{
		Source:          "xgrep",
		SpaceMrn:        "//captain.api.mondoo.app/spaces/test-space",
		ImportStartedAt: timestamppb.New(time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)),
		CompleteKinds:   []FindingKind{FindingKind_FINDING_KIND_FINDING},
		Findings: FexToDocuments([]*FindingExchange{
			{Id: "rule-1", Summary: "SQL injection"},
		}),
		UploadSetId:           "0b5f2a52-6f0e-4a5e-9a39-7d7a1c6f3e10",
		PartIndex:             1,
		PartCount:             3,
		EligibleFindingsCount: 4123,
		CappedReason:          "platform-no-upload-sets",
		ScanRef: &ScanRef{
			Kind:    ScanRefKind_SCAN_REF_KIND_PULL_REQUEST,
			Number:  4914,
			HeadSha: "096bccac898275dadd52c326756d98249599f534",
			BaseSha: "b241d5eea0000000000000000000000000000000",
		},
		CodeOwnerRules: []*CodeOwnerRule{
			{Pattern: "*.go", Owners: []string{"@acme/go-team", "dev@example.com"}},
			{Pattern: "/docs/", Section: "Docs", Optional: true},
		},
		CodeOwnerRulesTruncated: true,
		RunRules: &RunRules{
			Source:         "built-in",
			Count:          2100,
			FallbackReason: "platform-unreachable",
			Skipped:        []string{"org-rule-7"},
			Etag:           "W/\"abc\"",
		},
		RunPolicies: []*RunPolicy{
			{Kind: "code-scan-gate", Source: "cache", Etag: "\"g1\"", FallbackReason: "platform-unreachable"},
		},
	}
}

func TestFindingsUploadRequestUploadSetRoundTrip(t *testing.T) {
	in := uploadSetRequest()

	// vtproto writes, the reflection decoder reads.
	vt, err := in.MarshalVT()
	require.NoError(t, err)
	viaReflect := &FindingsUploadRequest{}
	require.NoError(t, proto.Unmarshal(vt, viaReflect))
	assert.True(t, proto.Equal(in, viaReflect), "reflection decode of vtproto bytes differs")

	// The reflection encoder writes, vtproto reads.
	std, err := proto.Marshal(in)
	require.NoError(t, err)
	viaVT := &FindingsUploadRequest{}
	require.NoError(t, viaVT.UnmarshalVT(std))
	assert.True(t, proto.Equal(in, viaVT), "vtproto decode of reflection bytes differs")

	assert.Equal(t, "0b5f2a52-6f0e-4a5e-9a39-7d7a1c6f3e10", viaVT.GetUploadSetId())
	assert.Equal(t, int32(1), viaVT.GetPartIndex())
	assert.Equal(t, int32(3), viaVT.GetPartCount())
	assert.Equal(t, int32(4123), viaVT.GetEligibleFindingsCount())
	assert.Equal(t, ScanRefKind_SCAN_REF_KIND_PULL_REQUEST, viaVT.GetScanRef().GetKind())
	assert.Equal(t, int64(4914), viaVT.GetScanRef().GetNumber())
	assert.True(t, viaVT.GetCodeOwnerRules()[1].GetOptional())
	assert.Equal(t, []string{"org-rule-7"}, viaVT.GetRunRules().GetSkipped())
	assert.Equal(t, "code-scan-gate", viaVT.GetRunPolicies()[0].GetKind())
	assert.True(t, viaVT.GetCodeOwnerRulesTruncated())
}

// TestFindingsUploadRequestFieldNumbers pins the wire numbers of the
// upload-set fields. The platform's copy of this message decodes them by
// number, and numbers 7, 8 and 10 to 12 are used by that copy, so a change
// here is a wire break, not a refactor.
func TestFindingsUploadRequestFieldNumbers(t *testing.T) {
	fields := (&FindingsUploadRequest{}).ProtoReflect().Descriptor().Fields()
	want := map[protoreflect.Name]protoreflect.FieldNumber{
		"findings":                   1,
		"source":                     2,
		"mondoo_enrichment":          3,
		"space_mrn":                  4,
		"create_assets":              5,
		"import_started_at":          6,
		"complete_kinds":             9,
		"scanned_components":         13,
		"upload_set_id":              15,
		"part_index":                 16,
		"part_count":                 17,
		"eligible_findings_count":    18,
		"capped_reason":              19,
		"scan_ref":                   20,
		"code_owner_rules":           21,
		"run_rules":                  22,
		"run_policies":               23,
		"code_owner_rules_truncated": 24,
	}
	assert.Equal(t, len(want), fields.Len(), "a field was added or removed; pin its number here")
	for name, num := range want {
		fd := fields.ByName(name)
		if assert.NotNil(t, fd, "field %s", name) {
			assert.Equal(t, num, fd.Number(), "field %s", name)
		}
	}
	for _, reserved := range []protoreflect.FieldNumber{7, 8, 10, 11, 12} {
		assert.Nil(t, fields.ByNumber(reserved), "field %d is used by the platform's copy of this message", reserved)
	}
}

// preUploadSetRequestType is FindingsUploadRequest as it was before fields
// 15 to 24: the current descriptor with those fields removed. It stands in
// for a reader built against the earlier contract.
func preUploadSetRequestType(t *testing.T) protoreflect.MessageType {
	t.Helper()
	fdp := protodesc.ToFileDescriptorProto(File_fex_proto)
	for _, m := range fdp.GetMessageType() {
		if m.GetName() != "FindingsUploadRequest" {
			continue
		}
		kept := m.Field[:0]
		for _, f := range m.GetField() {
			if f.GetNumber() < 14 {
				kept = append(kept, f)
			}
		}
		m.Field = kept
	}
	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	require.NoError(t, err)
	return dynamicpb.NewMessageType(fd.Messages().ByName("FindingsUploadRequest"))
}

// TestFindingsUploadRequestUploadSetWireCompatibility checks that a reader
// built before the upload-set fields reads an upload that carries them, keeps
// every earlier field, and passes the new ones through as unknown fields.
func TestFindingsUploadRequestUploadSetWireCompatibility(t *testing.T) {
	oldType := preUploadSetRequestType(t)
	in := uploadSetRequest()

	data, err := in.MarshalVT()
	require.NoError(t, err)

	old := oldType.New().Interface()
	require.NoError(t, proto.Unmarshal(data, old))
	oldFields := old.ProtoReflect().Descriptor().Fields()
	assert.Equal(t, "xgrep", old.ProtoReflect().Get(oldFields.ByName("source")).String())
	assert.Equal(t, 1, old.ProtoReflect().Get(oldFields.ByName("findings")).List().Len())
	assert.Equal(t, 1, old.ProtoReflect().Get(oldFields.ByName("complete_kinds")).List().Len())
	assert.NotEmpty(t, old.ProtoReflect().GetUnknown(), "the new fields must reach an old reader as unknown fields")

	// An old reader that re-encodes the message keeps the new fields.
	passed, err := proto.Marshal(old)
	require.NoError(t, err)
	back := &FindingsUploadRequest{}
	require.NoError(t, back.UnmarshalVT(passed))
	assert.True(t, proto.Equal(in, back), "fields were lost passing through an old reader")

}
