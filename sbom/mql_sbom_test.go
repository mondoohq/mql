// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// lockfileHistorySbom is a repository SBOM carrying the lockfile history of
// one package: a version added, removed and added again (two intervals), and
// the coverage of the walk that read it.
// Synthetic: field coverage for presence intervals and history coverage; no
// producer sends these yet.
func lockfileHistorySbom() *Sbom {
	return &Sbom{
		Generator: &Generator{Vendor: "Mondoo, Inc.", Name: "xgrep", Version: "1.0.0"},
		Timestamp: "2026-11-26T09:00:00Z",
		Status:    Status_STATUS_SUCCEEDED,
		Packages: []*Package{{
			Name:    "axios",
			Version: "1.14.1",
			Purl:    "pkg:npm/axios@1.14.1",
			PresenceIntervals: []*PresenceInterval{
				{
					Lockfile:    "web/package-lock.json",
					Branch:      "main",
					FirstCommit: "1111111111111111111111111111111111111111",
					FirstSeen:   "2026-09-01T10:00:00Z",
					AtWalkStart: true,
					LastCommit:  "2222222222222222222222222222222222222222",
					LastSeen:    "2026-09-03T10:00:00Z",
				},
				{
					Lockfile:    "web/package-lock.json",
					Branch:      "main",
					FirstCommit: "3333333333333333333333333333333333333333",
					FirstSeen:   "2026-10-01T10:00:00Z",
					Open:        true,
				},
			},
		}},
		HistoryCoverage: []*HistoryCoverage{{
			Lockfile:        "web/package-lock.json",
			Branch:          "main",
			RequestedSince:  "2026-08-28T00:00:00Z",
			Since:           "2026-09-01T10:00:00Z",
			Commits:         2000,
			Truncated:       true,
			TruncatedReason: "max-commits",
			Shallow:         true,
			UnparsedCommits: 2,
		}},
	}
}

func TestSbomLockfileHistoryRoundTrip(t *testing.T) {
	in := lockfileHistorySbom()

	// vtproto writes, the reflection decoder reads.
	vt, err := in.MarshalVT()
	require.NoError(t, err)
	viaReflect := &Sbom{}
	require.NoError(t, proto.Unmarshal(vt, viaReflect))
	assert.True(t, proto.Equal(in, viaReflect), "reflection decode of vtproto bytes differs")

	// The reflection encoder writes, vtproto reads.
	std, err := proto.Marshal(in)
	require.NoError(t, err)
	out := &Sbom{}
	require.NoError(t, out.UnmarshalVT(std))
	assert.True(t, proto.Equal(in, out), "vtproto decode of reflection bytes differs")

	intervals := out.GetPackages()[0].GetPresenceIntervals()
	require.Len(t, intervals, 2)
	assert.True(t, intervals[0].GetAtWalkStart())
	assert.False(t, intervals[0].GetOpen())
	assert.Equal(t, "2222222222222222222222222222222222222222", intervals[0].GetLastCommit())
	assert.True(t, intervals[1].GetOpen())
	assert.Empty(t, intervals[1].GetLastSeen())

	cov := out.GetHistoryCoverage()
	require.Len(t, cov, 1)
	assert.Equal(t, "max-commits", cov[0].GetTruncatedReason())
	assert.Equal(t, int32(2000), cov[0].GetCommits())
	assert.Equal(t, int32(2), cov[0].GetUnparsedCommits())
	assert.True(t, cov[0].GetShallow())
}

// TestSbomLockfileHistoryFieldNumbers pins the wire numbers of the two new
// fields. SBOMs are uploaded and stored as protobuf, so a renumbered field
// is a wire break, not a refactor.
func TestSbomLockfileHistoryFieldNumbers(t *testing.T) {
	pkg := (&Package{}).ProtoReflect().Descriptor().Fields()
	assert.Equal(t, protoreflect.FieldNumber(37), pkg.ByName("source").Number())
	assert.Equal(t, protoreflect.FieldNumber(38), pkg.ByName("presence_intervals").Number())

	doc := (&Sbom{}).ProtoReflect().Descriptor().Fields()
	assert.Equal(t, protoreflect.FieldNumber(7), doc.ByName("dependencies").Number())
	assert.Equal(t, protoreflect.FieldNumber(8), doc.ByName("history_coverage").Number())
}

// preHistorySbomType is Sbom as it was before the lockfile history: the
// current descriptor without Sbom.history_coverage and
// Package.presence_intervals. It stands in for a reader built against the
// earlier schema.
func preHistorySbomType(t *testing.T) protoreflect.MessageType {
	t.Helper()
	fdp := protodesc.ToFileDescriptorProto(File_mql_sbom_proto)
	for _, m := range fdp.GetMessageType() {
		if m.GetName() != "Sbom" && m.GetName() != "Package" {
			continue
		}
		kept := m.Field[:0]
		for _, f := range m.GetField() {
			if f.GetName() != "history_coverage" && f.GetName() != "presence_intervals" {
				kept = append(kept, f)
			}
		}
		m.Field = kept
	}
	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	require.NoError(t, err)
	return dynamicpb.NewMessageType(fd.Messages().ByName("Sbom"))
}

// TestSbomLockfileHistoryWireCompatibility checks that a reader built before
// the fields reads an SBOM that carries them, keeps every package, and passes
// the history through as unknown fields.
func TestSbomLockfileHistoryWireCompatibility(t *testing.T) {
	oldType := preHistorySbomType(t)
	in := lockfileHistorySbom()

	data, err := in.MarshalVT()
	require.NoError(t, err)

	old := oldType.New().Interface()
	require.NoError(t, proto.Unmarshal(data, old))
	oldFields := old.ProtoReflect().Descriptor().Fields()
	pkgs := old.ProtoReflect().Get(oldFields.ByName("packages")).List()
	require.Equal(t, 1, pkgs.Len())
	pkg := pkgs.Get(0).Message()
	assert.Equal(t, "pkg:npm/axios@1.14.1", pkg.Get(pkg.Descriptor().Fields().ByName("purl")).String())
	assert.NotEmpty(t, old.ProtoReflect().GetUnknown(), "history_coverage must reach an old reader as unknown fields")
	assert.NotEmpty(t, pkg.GetUnknown(), "presence_intervals must reach an old reader as unknown fields")

	// An old reader that re-encodes the document keeps the history.
	passed, err := proto.Marshal(old)
	require.NoError(t, err)
	back := &Sbom{}
	require.NoError(t, back.UnmarshalVT(passed))
	assert.True(t, proto.Equal(in, back), "history was lost passing through an old reader")

}
