// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/monitoring"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestOciAlarmSuppressed(t *testing.T) {
	from := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	until := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		from  *time.Time
		until *time.Time
		now   time.Time
		want  bool
	}{
		{"inside the window", &from, &until, from.Add(time.Hour), true},
		{"before the window", &from, &until, from.Add(-time.Second), false},
		{"after the window", &from, &until, until.Add(time.Second), false},
		{"start is inclusive", &from, &until, from, true},
		{"end is inclusive", &from, &until, until, true},
		// A half-window is not an open-ended one. Both bounds are mandatory on
		// an OCI suppression, so a missing bound means there is no suppression
		// at all - reporting the alarm as silenced on the strength of it would
		// hide a live control behind a field the service never sent.
		{"no suppression at all", nil, nil, from.Add(time.Hour), false},
		{"only a start", &from, nil, from.Add(time.Hour), false},
		{"only an end", nil, &until, from.Add(time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociAlarmSuppressed(tt.from, tt.until, tt.now))
		})
	}
}

// TestOciAlarmSummaryDecode pins the payload keys the alarm lister reads. A
// renamed key would decode to a zero value, which reports every alarm as
// unsuppressed and reaching nobody.
func TestOciAlarmSummaryDecode(t *testing.T) {
	payload := `{
	  "id": "ocid1.alarm.oc1..aaaa",
	  "displayName": "High CPU",
	  "compartmentId": "ocid1.compartment.oc1..bbbb",
	  "metricCompartmentId": "ocid1.compartment.oc1..cccc",
	  "namespace": "oci_computeagent",
	  "query": "CpuUtilization[1m].mean() > 85",
	  "severity": "CRITICAL",
	  "destinations": ["ocid1.onstopic.oc1..dddd", "ocid1.stream.oc1..eeee"],
	  "isEnabled": true,
	  "lifecycleState": "ACTIVE",
	  "suppression": {
	    "timeSuppressFrom": "2026-03-01T10:00:00.000Z",
	    "timeSuppressUntil": "2026-03-01T12:00:00.000Z",
	    "description": "planned outage"
	  }
	}`

	var alarm monitoring.AlarmSummary
	require.NoError(t, json.Unmarshal([]byte(payload), &alarm))

	// The metric compartment is what the alarm watches, and it is a different
	// compartment from the one the alarm is defined in.
	assert.Equal(t, "ocid1.compartment.oc1..cccc", stringValue(alarm.MetricCompartmentId))
	assert.NotEqual(t, stringValue(alarm.CompartmentId), stringValue(alarm.MetricCompartmentId))

	// Both destination kinds land in one list. topics() resolves only the
	// Notifications entry, so an alarm whose only destination is a stream must
	// still be visible as reaching something.
	require.Len(t, alarm.Destinations, 2)
	assert.Equal(t, "ocid1.onstopic.oc1..dddd", alarm.Destinations[0])
	assert.Equal(t, "ocid1.stream.oc1..eeee", alarm.Destinations[1])

	require.NotNil(t, alarm.Suppression)
	require.NotNil(t, alarm.Suppression.TimeSuppressFrom)
	require.NotNil(t, alarm.Suppression.TimeSuppressUntil)
	assert.Equal(t, "planned outage", stringValue(alarm.Suppression.Description))

	// The alarm reports itself enabled while suppressed. That is the whole
	// point of the field: isEnabled alone cannot tell the two apart.
	assert.True(t, boolValue(alarm.IsEnabled))
	assert.True(t, ociAlarmSuppressed(
		&alarm.Suppression.TimeSuppressFrom.Time,
		&alarm.Suppression.TimeSuppressUntil.Time,
		time.Date(2026, 3, 1, 11, 0, 0, 0, time.UTC),
	))
}

func TestOciAlarmSummaryDecodeWithoutSuppression(t *testing.T) {
	var alarm monitoring.AlarmSummary
	require.NoError(t, json.Unmarshal([]byte(`{"id":"ocid1.alarm.oc1..aaaa","destinations":[]}`), &alarm))

	assert.Nil(t, alarm.Suppression)
	assert.Empty(t, alarm.Destinations)
	// An absent suppression must not become a window starting at the zero
	// time, which would report the alarm as silenced since year one.
	assert.False(t, ociAlarmSuppressed(nil, nil, time.Now()))
}

func TestOciCompartmentParent(t *testing.T) {
	const root = "ocid1.tenancy.oc1..root"

	tests := []struct {
		name     string
		self     string
		reported string
		want     string
	}{
		{"a child names its parent", "ocid1.compartment.oc1..child", root, root},
		// The tenancy root names itself. Resolving that would make a walk up
		// the hierarchy loop instead of terminating.
		{"the root names itself", root, root, ""},
		{"nothing reported", "ocid1.compartment.oc1..child", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociCompartmentParent(tt.self, tt.reported))
		})
	}
}

func TestOciCompartmentArgsIsAccessible(t *testing.T) {
	t.Run("reported true", func(t *testing.T) {
		yes := true
		args := ociCompartmentArgs(identity.Compartment{IsAccessible: &yes})
		assert.Equal(t, llx.BoolData(true), args["isAccessible"])
	})

	t.Run("reported false", func(t *testing.T) {
		no := false
		args := ociCompartmentArgs(identity.Compartment{IsAccessible: &no})
		assert.Equal(t, llx.BoolData(false), args["isAccessible"])
	})

	// The tenancy root is read with GetCompartment rather than as part of the
	// subtree listing, and comes back without the field. Null keeps "we never
	// asked" apart from "the caller cannot look inside"; a default false would
	// make the root look walled off from its own owner.
	t.Run("not reported stays null", func(t *testing.T) {
		args := ociCompartmentArgs(identity.Compartment{})
		require.Contains(t, args, "isAccessible")
		assert.Equal(t, llx.NilData, args["isAccessible"])
	})

	// ociCompartmentUnreadable derives its field list from ociCompartmentArgs,
	// so a new field is nulled there without a second edit. Assert it, because
	// an unset field crosses the plugin boundary as an untyped primitive.
	t.Run("an unreadable compartment nulls it", func(t *testing.T) {
		yes := true
		args := ociCompartmentArgs(identity.Compartment{IsAccessible: &yes})
		args["id"] = llx.StringData("ocid1.compartment.oc1..aaaa")
		ociCompartmentUnreadable(args)
		assert.Equal(t, llx.NilData, args["isAccessible"])
		assert.Equal(t, llx.StringData("ocid1.compartment.oc1..aaaa"), args["id"])
	})
}

func TestOciReadSecretReplication(t *testing.T) {
	t.Run("no replication configuration", func(t *testing.T) {
		got := ociReadSecretReplication(vault.SecretSummary{})
		// Null, not false. A secret with nothing to forward to has not been
		// configured to forward nothing.
		assert.Nil(t, got.WriteForwardEnabled)
		assert.Nil(t, got.SourceRegion)
		assert.Empty(t, got.Targets)
		assert.Equal(t, "", got.SourceVaultID)
		assert.Equal(t, "", got.SourceKeyID)
	})

	// Replication is configured but the service said nothing about write
	// forwarding. That is unread, not off - a fabricated false here would let
	// a check assert "writes are not forwarded" on a secret nobody asked about.
	t.Run("replication configured with write forwarding unreported", func(t *testing.T) {
		got := ociReadSecretReplication(vault.SecretSummary{
			ReplicationConfig: &vault.ReplicationConfig{
				ReplicationTargets: []vault.ReplicationTarget{{}},
			},
		})
		assert.Nil(t, got.WriteForwardEnabled)
		require.Len(t, got.Targets, 1)
	})

	t.Run("write forwarding explicitly off", func(t *testing.T) {
		no := false
		got := ociReadSecretReplication(vault.SecretSummary{
			ReplicationConfig: &vault.ReplicationConfig{IsWriteForwardEnabled: &no},
		})
		require.NotNil(t, got.WriteForwardEnabled)
		assert.False(t, *got.WriteForwardEnabled)
	})

	t.Run("targets and source are carried through", func(t *testing.T) {
		region := "us-phoenix-1"
		vaultID := "ocid1.vault.oc1.phx.aaaa"
		keyID := "ocid1.key.oc1.phx.bbbb"
		got := ociReadSecretReplication(vault.SecretSummary{
			ReplicationConfig: &vault.ReplicationConfig{
				ReplicationTargets: []vault.ReplicationTarget{{
					TargetRegion:  &region,
					TargetVaultId: &vaultID,
					TargetKeyId:   &keyID,
				}},
			},
			SourceRegionInformation: &vault.SourceRegionInformation{
				SourceRegion:  &region,
				SourceVaultId: &vaultID,
				SourceKeyId:   &keyID,
			},
		})
		require.Len(t, got.Targets, 1)
		assert.Equal(t, region, stringValue(got.Targets[0].TargetRegion))
		assert.Equal(t, region, stringValue(got.SourceRegion))
		assert.Equal(t, vaultID, got.SourceVaultID)
		assert.Equal(t, keyID, got.SourceKeyID)
	})
}

// TestOciSecretSummaryDecode pins the replication keys the secret lister reads.
func TestOciSecretSummaryDecode(t *testing.T) {
	payload := `{
	  "id": "ocid1.vaultsecret.oc1.iad.aaaa",
	  "secretName": "db-password",
	  "compartmentId": "ocid1.compartment.oc1..bbbb",
	  "vaultId": "ocid1.vault.oc1.iad.cccc",
	  "lifecycleState": "ACTIVE",
	  "isReplica": false,
	  "replicationConfig": {
	    "isWriteForwardEnabled": true,
	    "replicationTargets": [{
	      "targetKeyId": "ocid1.key.oc1.phx.dddd",
	      "targetRegion": "us-phoenix-1",
	      "targetVaultId": "ocid1.vault.oc1.phx.eeee"
	    }]
	  }
	}`

	var secret vault.SecretSummary
	require.NoError(t, json.Unmarshal([]byte(payload), &secret))

	got := ociReadSecretReplication(secret)
	require.NotNil(t, got.WriteForwardEnabled)
	assert.True(t, *got.WriteForwardEnabled)
	require.Len(t, got.Targets, 1)
	assert.Equal(t, "us-phoenix-1", stringValue(got.Targets[0].TargetRegion))
	assert.Equal(t, "ocid1.vault.oc1.phx.eeee", stringValue(got.Targets[0].TargetVaultId))
	assert.Equal(t, "ocid1.key.oc1.phx.dddd", stringValue(got.Targets[0].TargetKeyId))

	require.NotNil(t, secret.IsReplica)
	assert.False(t, *secret.IsReplica)
}

// TestOciKeyDecode pins the rotation and replication keys read off GetKey.
func TestOciKeyDecode(t *testing.T) {
	payload := `{
	  "id": "ocid1.key.oc1.iad.aaaa",
	  "compartmentId": "ocid1.compartment.oc1..bbbb",
	  "vaultId": "ocid1.vault.oc1.iad.cccc",
	  "currentKeyVersion": "ocid1.keyversion.oc1.iad.dddd",
	  "displayName": "app-key",
	  "lifecycleState": "ENABLED",
	  "timeCreated": "2026-01-02T03:04:05.000Z",
	  "keyShape": {"algorithm": "AES", "length": 32},
	  "isPrimary": true,
	  "isAutoRotationEnabled": true,
	  "replicaDetails": {"replicationId": "ocid1.replication.oc1..eeee"},
	  "autoKeyRotationDetails": {
	    "rotationIntervalInDays": 90,
	    "timeOfLastRotation": "2026-01-01T00:00:00.000Z",
	    "timeOfNextRotation": "2026-04-01T00:00:00.000Z",
	    "lastRotationStatus": "SUCCESS"
	  }
	}`

	var key keymanagement.Key
	require.NoError(t, json.Unmarshal([]byte(payload), &key))

	require.NotNil(t, key.AutoKeyRotationDetails)
	require.NotNil(t, key.AutoKeyRotationDetails.RotationIntervalInDays)
	// The cadence is the whole point: isAutoRotationEnabled reads true for a
	// key rotating yearly and for one rotating monthly alike.
	assert.Equal(t, 90, *key.AutoKeyRotationDetails.RotationIntervalInDays)
	require.NotNil(t, key.AutoKeyRotationDetails.TimeOfLastRotation)
	require.NotNil(t, key.AutoKeyRotationDetails.TimeOfNextRotation)
	assert.Equal(t, keymanagement.AutoKeyRotationDetailsLastRotationStatusSuccess,
		key.AutoKeyRotationDetails.LastRotationStatus)

	require.NotNil(t, key.IsPrimary)
	assert.True(t, *key.IsPrimary)
	require.NotNil(t, key.ReplicaDetails)
	assert.Equal(t, "ocid1.replication.oc1..eeee", stringValue(key.ReplicaDetails.ReplicationId))
}

func TestOciKeyDecodeWithoutRotationSchedule(t *testing.T) {
	var key keymanagement.Key
	require.NoError(t, json.Unmarshal([]byte(`{"id":"ocid1.key.oc1.iad.aaaa","isAutoRotationEnabled":false}`), &key))

	// No schedule at all. The accessors must report null rather than a zero
	// interval, which would read as a key rotating constantly, and rather than
	// the zero time, which would read as a rotation in year one.
	assert.Nil(t, key.AutoKeyRotationDetails)
	assert.Nil(t, key.ReplicaDetails)
	assert.Nil(t, key.IsPrimary)
}

// TestOciRegionByName covers the one thing that makes a region lookup by name
// different from every other lookup in this provider: oci.region is keyed by
// the short region key, and matching on that key would silently find nothing
// for a service that reports the full region name.
func TestOciRegionByName(t *testing.T) {
	region := func(key, name string) *mqlOciRegion {
		return &mqlOciRegion{
			Id:   plugin.TValue[string]{Data: key, State: plugin.StateIsSet},
			Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		}
	}
	items := []any{region("iad", "us-ashburn-1"), region("phx", "us-phoenix-1")}

	t.Run("matches the full region name", func(t *testing.T) {
		got := ociRegionByName(items, "us-phoenix-1")
		require.NotNil(t, got)
		assert.Equal(t, "phx", got.Id.Data)
	})

	// The short key is what oci.region is keyed by, and it is NOT what a
	// replication target reports. Matching it here would mean a lookup by key
	// quietly succeeded where the caller meant a name.
	t.Run("does not match the short region key", func(t *testing.T) {
		assert.Nil(t, ociRegionByName(items, "phx"))
	})

	t.Run("region names are matched without regard to case", func(t *testing.T) {
		got := ociRegionByName(items, "US-Phoenix-1")
		require.NotNil(t, got)
		assert.Equal(t, "phx", got.Id.Data)
	})

	// A region the tenancy is not subscribed to. The caller reports null for
	// the region while keeping its own regionName populated, so the
	// destination stays on the record.
	t.Run("an unsubscribed region misses", func(t *testing.T) {
		assert.Nil(t, ociRegionByName(items, "eu-frankfurt-1"))
	})

	t.Run("an empty name misses", func(t *testing.T) {
		assert.Nil(t, ociRegionByName(items, ""))
	})
}
