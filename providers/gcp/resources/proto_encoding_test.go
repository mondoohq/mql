// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"cloud.google.com/go/recommender/apiv1/recommenderpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	dns "google.golang.org/api/dns/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestTimestampAsTimePtrDistinguishesAbsentFromEpoch pins why 15 fields had to
// stop calling llx.TimeData(x.AsTime()) directly.
//
// (*timestamppb.Timestamp)(nil).AsTime() is nil-SAFE, which is exactly what
// makes it dangerous: it silently returns the Unix epoch instead of panicking.
// A live, non-deleted Cloud Run service therefore reported
// deleted: 1970-01-01T00:00:00Z, so `services.all(deleted == null)` failed on
// every service. timestampAsTimePtr preserves the absence as a nil pointer,
// which llx.TimeDataPtr renders as null.
func TestTimestampAsTimePtrDistinguishesAbsentFromEpoch(t *testing.T) {
	var absent *timestamppb.Timestamp

	// The hazard being guarded against: the nil timestamp is not an error, it
	// is a real-looking date in 1970.
	assert.True(t, absent.AsTime().Equal(time.Unix(0, 0).UTC()),
		"a nil timestamp's AsTime() is the epoch, not a zero value")

	assert.Nil(t, timestampAsTimePtr(absent), "an absent timestamp must stay absent")

	want := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	got := timestampAsTimePtr(timestamppb.New(want))
	require.NotNil(t, got)
	assert.True(t, want.Equal(*got))
}

// TestDurationToStringIsNotTheProtoStringer pins the distinction that four
// fields (firestore versionRetentionPeriod and backup retention, privateca CA
// and certificate lifetime) plus monitoring's SLO rollingPeriod got wrong.
//
// (*durationpb.Duration).String() is the GENERATED PROTO STRINGER: it renders
// the message as protobuf text ("seconds:2592000"), not as a duration, and
// upstream explicitly documents the output as unstable across builds. Users saw
// that string in reports and no equality check against a duration ever matched.
func TestDurationToStringIsNotTheProtoStringer(t *testing.T) {
	d := durationpb.New(720 * time.Hour)

	// The documented encoding, matching the GCP API's own JSON duration form.
	assert.Equal(t, "2592000s", durationToString(d))

	// Deliberately not asserting the proto stringer's exact output -- upstream
	// randomizes its spacing -- only that it is NOT the value encoding.
	assert.NotEqual(t, durationToString(d), d.String(),
		"the proto stringer must never be used as a field value")

	assert.Equal(t, "", durationToString(nil), "an absent duration is empty, not \"<nil>\"")
}

// TestDnssecStateEnabled covers the three states the DNS API documents.
//
// Matching only "on" reported a zone in "transfer" state -- which IS signed,
// the state a zone sits in mid-KSK-transfer -- as having DNSSEC disabled. That
// also silenced dnsSecAlgorithmWeak(), which short-circuits on this predicate,
// so a transfer-state zone signed with RSASHA1 reported as not weak.
func TestDnssecStateEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  *dns.ManagedZoneDnsSecConfig
		want bool
	}{
		{name: "on", cfg: &dns.ManagedZoneDnsSecConfig{State: "on"}, want: true},
		{name: "transfer is signed", cfg: &dns.ManagedZoneDnsSecConfig{State: "transfer"}, want: true},
		{name: "off", cfg: &dns.ManagedZoneDnsSecConfig{State: "off"}, want: false},
		{name: "empty state", cfg: &dns.ManagedZoneDnsSecConfig{State: ""}, want: false},
		{name: "no config at all", cfg: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dnssecStateEnabled(tt.cfg))
		})
	}
}

// TestProtoToDictEmitsDocumentedKeysAndEnumNames pins the encoding bug that
// made several shipped dicts undocumentable.
//
// convert.JsonToDict is encoding/json over a protobuf-generated struct, and
// those structs carry snake_case json tags with enums rendered as their numeric
// value. gcp.recommendation.primaryImpact therefore documented `category`,
// `costProjection` and friends while actually emitting `{"category": 2, ...}`.
// protoToDict marshals through protojson, which is what the schema documents.
func TestProtoToDictEmitsDocumentedKeysAndEnumNames(t *testing.T) {
	impact := &recommenderpb.Impact{
		Category: recommenderpb.Impact_SECURITY,
		Service:  "compute.googleapis.com",
	}

	// The hazard being guarded against.
	viaEncodingJSON, err := convert.JsonToDict(impact)
	require.NoError(t, err)
	assert.EqualValues(t, float64(recommenderpb.Impact_SECURITY), viaEncodingJSON["category"],
		"encoding/json renders the enum as its number")

	got, err := protoToDict(impact)
	require.NoError(t, err)
	assert.Equal(t, "SECURITY", got["category"])
	assert.Equal(t, "compute.googleapis.com", got["service"])
}

// TestProtoToDictSlicePreservesOrderAndNilInput guards the helper the recommender,
// Network Connectivity and Privileged Access Manager listers share.
func TestProtoToDictSlicePreservesOrderAndNilInput(t *testing.T) {
	got, err := protoToDictSlice([]*recommenderpb.Impact{
		{Category: recommenderpb.Impact_COST},
		{Category: recommenderpb.Impact_SECURITY},
	})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "COST", got[0].(map[string]any)["category"])
	assert.Equal(t, "SECURITY", got[1].(map[string]any)["category"])

	empty, err := protoToDictSlice([]*recommenderpb.Impact{})
	require.NoError(t, err)
	assert.Empty(t, empty)
}
