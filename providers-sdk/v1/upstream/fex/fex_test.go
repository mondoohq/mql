// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fex

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
