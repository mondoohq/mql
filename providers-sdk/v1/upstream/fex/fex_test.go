// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fex

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
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

func TestValidReporter(t *testing.T) {
	// Synthetic: the reporter format; no producer sends these yet.
	valid := []string{
		"tool:code",
		"tool:dspm",
		"a-b:c1",
		"0:0",
		"a:" + strings.Repeat("b", MaxReporterLength-2), // exactly 64 bytes
	}
	for _, s := range valid {
		assert.True(t, ValidReporter(s), "%q should be a valid reporter", s)
	}

	invalid := []string{
		"",            // empty is valid on the wire, but not a reporter value
		"tool",        // no mode
		"tool:",       // empty mode
		":code",       // empty producer
		"Tool:code",   // upper case
		"tool:code:x", // two separators
		"tool:co de",  // space
		"tool_x:code", // underscore
		"tool:code\n", // trailing newline must not slip past the anchors
		"tööl:code",   // non-ASCII
		"a:" + strings.Repeat("b", MaxReporterLength-1), // 65 bytes
	}
	for _, s := range invalid {
		assert.False(t, ValidReporter(s), "%q should not be a valid reporter", s)
	}
}

func TestReporterRoundTrip(t *testing.T) {
	// Synthetic: wire and proto-JSON encoding of field 14.
	req := &FindingsUploadRequest{Source: "src", Reporter: "tool:dspm"}

	b, err := req.MarshalVT()
	require.NoError(t, err)
	// Field 14, wire type 2: tag byte 0x72, then the length and the bytes.
	assert.Contains(t, string(b), "\x72\x09tool:dspm")

	var got FindingsUploadRequest
	require.NoError(t, got.UnmarshalVT(b))
	assert.Equal(t, "tool:dspm", got.GetReporter())

	j, err := protojson.Marshal(req)
	require.NoError(t, err)
	assert.Contains(t, string(j), `"reporter":"tool:dspm"`)

	var fromJSON FindingsUploadRequest
	require.NoError(t, protojson.Unmarshal([]byte(`{"source":"src","reporter":"tool:code"}`), &fromJSON))
	assert.Equal(t, "tool:code", fromJSON.GetReporter())

	// A request without a reporter carries no field 14, so it encodes exactly
	// as a request built before the field existed.
	without, err := (&FindingsUploadRequest{Source: "src"}).MarshalVT()
	require.NoError(t, err)
	assert.Equal(t, []byte("\x12\x03src"), without)
	jw, err := protojson.Marshal(&FindingsUploadRequest{Source: "src"})
	require.NoError(t, err)
	assert.NotContains(t, string(jw), "reporter")
}
