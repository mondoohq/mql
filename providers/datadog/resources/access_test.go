// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

func TestIsNotFound(t *testing.T) {
	if isNotFound(nil) {
		t.Fatal("expected false for a nil response")
	}
	if isNotFound(&http.Response{StatusCode: http.StatusOK}) {
		t.Fatal("expected false for a 200 response")
	}
	if isNotFound(&http.Response{StatusCode: http.StatusForbidden}) {
		t.Fatal("expected false for a 403 response")
	}
	if !isNotFound(&http.Response{StatusCode: http.StatusNotFound}) {
		t.Fatal("expected true for a 404 response")
	}
}

func attrsWithForwarder(forwarder datadogV2.CustomDestinationResponseForwardDestination) datadogV2.CustomDestinationResponseAttributes {
	attrs := datadogV2.NewCustomDestinationResponseAttributes()
	attrs.SetForwarderDestination(forwarder)
	return *attrs
}

func TestDestinationForwarderHttp(t *testing.T) {
	auth := datadogV2.CustomDestinationResponseHttpDestinationAuth{
		CustomDestinationResponseHttpDestinationAuthBasic: datadogV2.NewCustomDestinationResponseHttpDestinationAuthBasic(
			datadogV2.CUSTOMDESTINATIONRESPONSEHTTPDESTINATIONAUTHBASICTYPE_BASIC),
	}
	httpDest := datadogV2.NewCustomDestinationResponseForwardDestinationHttp(
		auth, "https://logs.example.com/ingest",
		datadogV2.CUSTOMDESTINATIONRESPONSEFORWARDDESTINATIONHTTPTYPE_HTTP)

	got := destinationForwarder(attrsWithForwarder(datadogV2.CustomDestinationResponseForwardDestination{
		CustomDestinationResponseForwardDestinationHttp: httpDest,
	}))

	if got.destinationType != "http" {
		t.Fatalf("expected destination type http, got %q", got.destinationType)
	}
	if got.endpoint != "https://logs.example.com/ingest" {
		t.Fatalf("unexpected endpoint %q", got.endpoint)
	}
	if got.authType != "basic" {
		t.Fatalf("expected auth type basic, got %q", got.authType)
	}
	if got.indexName != "" {
		t.Fatalf("expected no index name for an HTTP destination, got %q", got.indexName)
	}
}

func TestDestinationForwarderSplunk(t *testing.T) {
	splunk := datadogV2.NewCustomDestinationResponseForwardDestinationSplunk(
		"https://splunk.example.com:8088",
		datadogV2.CUSTOMDESTINATIONRESPONSEFORWARDDESTINATIONSPLUNKTYPE_SPLUNK_HEC)

	got := destinationForwarder(attrsWithForwarder(datadogV2.CustomDestinationResponseForwardDestination{
		CustomDestinationResponseForwardDestinationSplunk: splunk,
	}))

	if got.destinationType != "splunk_hec" {
		t.Fatalf("expected destination type splunk_hec, got %q", got.destinationType)
	}
	if got.endpoint != "https://splunk.example.com:8088" {
		t.Fatalf("unexpected endpoint %q", got.endpoint)
	}
	if got.authType != "" {
		t.Fatalf("expected no auth type for a Splunk destination, got %q", got.authType)
	}
}

func TestDestinationForwarderElasticsearch(t *testing.T) {
	elastic := datadogV2.NewCustomDestinationResponseForwardDestinationElasticsearch(
		map[string]any{}, "https://es.example.com", "datadog-logs",
		datadogV2.CUSTOMDESTINATIONRESPONSEFORWARDDESTINATIONELASTICSEARCHTYPE_ELASTICSEARCH)

	got := destinationForwarder(attrsWithForwarder(datadogV2.CustomDestinationResponseForwardDestination{
		CustomDestinationResponseForwardDestinationElasticsearch: elastic,
	}))

	if got.destinationType != "elasticsearch" {
		t.Fatalf("expected destination type elasticsearch, got %q", got.destinationType)
	}
	if got.indexName != "datadog-logs" {
		t.Fatalf("expected index name datadog-logs, got %q", got.indexName)
	}
}

// The Microsoft Sentinel variant names its address differently; it must still
// land in endpoint so a query for where logs go covers every destination type.
func TestDestinationForwarderMicrosoftSentinel(t *testing.T) {
	sentinel := datadogV2.NewCustomDestinationResponseForwardDestinationMicrosoftSentinel(
		"client-id", "https://dce.example.com", "dcr-id", "Custom-Datadog", "tenant-id",
		datadogV2.CUSTOMDESTINATIONRESPONSEFORWARDDESTINATIONMICROSOFTSENTINELTYPE_MICROSOFT_SENTINEL)

	got := destinationForwarder(attrsWithForwarder(datadogV2.CustomDestinationResponseForwardDestination{
		CustomDestinationResponseForwardDestinationMicrosoftSentinel: sentinel,
	}))

	if got.destinationType != "microsoft_sentinel" {
		t.Fatalf("expected destination type microsoft_sentinel, got %q", got.destinationType)
	}
	if got.endpoint != "https://dce.example.com" {
		t.Fatalf("expected the data collection endpoint, got %q", got.endpoint)
	}
}

// A variant Datadog adds later deserializes with every known pointer nil. It
// must read as unknown rather than borrowing another variant's fields.
func TestDestinationForwarderUnknownVariant(t *testing.T) {
	got := destinationForwarder(attrsWithForwarder(datadogV2.CustomDestinationResponseForwardDestination{}))
	if got != (forwarderDetails{}) {
		t.Fatalf("expected an empty result for an unrecognized variant, got %+v", got)
	}

	// Attributes with no forwarder at all must behave the same.
	if got := destinationForwarder(*datadogV2.NewCustomDestinationResponseAttributes()); got != (forwarderDetails{}) {
		t.Fatalf("expected an empty result when no forwarder is set, got %+v", got)
	}
}

func TestAuthnMappingGrants(t *testing.T) {
	roleData := datadogV2.NewRelationshipToRoleData()
	roleData.SetId("role-1")
	role := datadogV2.NewRelationshipToRole()
	role.SetData(*roleData)

	rels := datadogV2.NewAuthNMappingRelationships()
	rels.SetRole(*role)

	mapping := datadogV2.NewAuthNMapping("mapping-1", datadogV2.AUTHNMAPPINGSTYPE_AUTHN_MAPPINGS)
	mapping.SetRelationships(*rels)

	gotRole, gotTeam := authnMappingGrants(*mapping)
	if gotRole != "role-1" {
		t.Fatalf("expected role-1, got %q", gotRole)
	}
	if gotTeam != "" {
		t.Fatalf("expected no team, got %q", gotTeam)
	}
}

func TestAuthnMappingGrantsTeam(t *testing.T) {
	teamData := datadogV2.NewRelationshipToTeamData()
	teamData.SetId("team-1")
	team := datadogV2.NewRelationshipToTeam()
	team.SetData(*teamData)

	rels := datadogV2.NewAuthNMappingRelationships()
	rels.SetTeam(*team)

	mapping := datadogV2.NewAuthNMapping("mapping-1", datadogV2.AUTHNMAPPINGSTYPE_AUTHN_MAPPINGS)
	mapping.SetRelationships(*rels)

	gotRole, gotTeam := authnMappingGrants(*mapping)
	if gotRole != "" {
		t.Fatalf("expected no role, got %q", gotRole)
	}
	if gotTeam != "team-1" {
		t.Fatalf("expected team-1, got %q", gotTeam)
	}
}

// A mapping with no relationships must yield two empty IDs, which the
// accessors report as null, rather than dereferencing a nil pointer.
func TestAuthnMappingGrantsMissingRelationships(t *testing.T) {
	mapping := datadogV2.NewAuthNMapping("mapping-1", datadogV2.AUTHNMAPPINGSTYPE_AUTHN_MAPPINGS)

	gotRole, gotTeam := authnMappingGrants(*mapping)
	if gotRole != "" || gotTeam != "" {
		t.Fatalf("expected empty IDs, got (%q, %q)", gotRole, gotTeam)
	}

	mapping.SetRelationships(*datadogV2.NewAuthNMappingRelationships())
	gotRole, gotTeam = authnMappingGrants(*mapping)
	if gotRole != "" || gotTeam != "" {
		t.Fatalf("expected empty IDs for an empty relationships block, got (%q, %q)", gotRole, gotTeam)
	}
}
