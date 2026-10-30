// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/database"
	"github.com/oracle/oci-go-sdk/v65/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func TestOciShieldedInstanceFlags(t *testing.T) {
	t.Run("read off a shape that supports shielded instances", func(t *testing.T) {
		// The four getters are declared on core.PlatformConfig itself, so any
		// member answers them without a type switch.
		secureBoot, tpm, measuredBoot, memoryEncryption := ociShieldedInstanceFlags(core.AmdVmPlatformConfig{
			IsSecureBootEnabled:            new(true),
			IsTrustedPlatformModuleEnabled: new(true),
			IsMeasuredBootEnabled:          new(false),
			IsMemoryEncryptionEnabled:      new(true),
		})

		require.NotNil(t, secureBoot)
		assert.True(t, *secureBoot)
		require.NotNil(t, tpm)
		assert.True(t, *tpm)
		require.NotNil(t, measuredBoot)
		assert.False(t, *measuredBoot, "an explicit false must survive as false, not as null")
		require.NotNil(t, memoryEncryption)
		assert.True(t, *memoryEncryption)
	})

	t.Run("a different member answers the same getters", func(t *testing.T) {
		// Proves no type switch crept back in: an Intel shape must read the
		// same way an AMD one does.
		secureBoot, tpm, measuredBoot, memoryEncryption := ociShieldedInstanceFlags(core.IntelVmPlatformConfig{
			IsSecureBootEnabled:            new(false),
			IsTrustedPlatformModuleEnabled: new(true),
			IsMeasuredBootEnabled:          new(true),
		})

		require.NotNil(t, secureBoot)
		assert.False(t, *secureBoot)
		require.NotNil(t, tpm)
		assert.True(t, *tpm)
		require.NotNil(t, measuredBoot)
		assert.True(t, *measuredBoot)
		assert.Nil(t, memoryEncryption, "a flag the member leaves unset stays null")
	})

	t.Run("a shape without shielded-instance support reads null", func(t *testing.T) {
		// A shape that does not offer these features carries no platform
		// configuration at all. Reporting false here would say Secure Boot is
		// turned off on a shape that cannot run it, and a "Secure Boot must be
		// enabled" audit would then raise a finding nobody can remediate.
		secureBoot, tpm, measuredBoot, memoryEncryption := ociShieldedInstanceFlags(nil)

		assert.Nil(t, secureBoot)
		assert.Nil(t, tpm)
		assert.Nil(t, measuredBoot)
		assert.Nil(t, memoryEncryption)
	})
}

func TestOciInstanceSource(t *testing.T) {
	t.Run("an instance launched from an image", func(t *testing.T) {
		// The SDK unmarshals this branch as a value, not a pointer. Naming the
		// pointer type in the switch would match nothing, and the instance
		// would report no boot source at all while still looking read.
		bootVolumeID, image := ociInstanceSource(core.InstanceSourceViaImageDetails{
			ImageId:             new("ocid1.image.oc1..img"),
			KmsKeyId:            new("ocid1.key.oc1..key"),
			BootVolumeSizeInGBs: int64Ptr(120),
			BootVolumeVpusPerGB: int64Ptr(20),
		})

		assert.Empty(t, bootVolumeID, "an image-launched instance reuses no existing boot volume")
		require.NotNil(t, image)
		assert.Equal(t, "ocid1.image.oc1..img", *image.ImageId)
		assert.Equal(t, "ocid1.key.oc1..key", *image.KmsKeyId)
		assert.Equal(t, int64(120), *image.BootVolumeSizeInGBs)
	})

	t.Run("an instance launched from an existing boot volume", func(t *testing.T) {
		// The volume was sized and keyed when it was created, so there is no
		// image source to report. A non-nil image here would publish a boot
		// volume size of null as a fact about the instance.
		bootVolumeID, image := ociInstanceSource(core.InstanceSourceViaBootVolumeDetails{
			BootVolumeId: new("ocid1.bootvolume.oc1..vol"),
		})

		assert.Equal(t, "ocid1.bootvolume.oc1..vol", bootVolumeID)
		assert.Nil(t, image)
	})

	t.Run("an instance reporting no source details", func(t *testing.T) {
		bootVolumeID, image := ociInstanceSource(nil)

		assert.Empty(t, bootVolumeID)
		assert.Nil(t, image)
	})
}

// ociIngressValuesOf lifts a normalized rule into the values the open-ingress
// predicate reads, so a test can go straight from an SDK rule to a verdict.
func ociIngressValuesOf(r securityRule) ociIngressRuleValues {
	return ociIngressRuleValues{
		direction:  r.direction,
		sourceType: r.sourceType,
		source:     r.source,
		protocol:   r.protocol,
	}
}

func TestOciRuleValuesOpenIngressAcrossBothRuleSources(t *testing.T) {
	// The bug this replaces: the exposure resource read its open rules out of
	// two differently-shaped dicts. A network security group rule carried
	// isStateless and a security list rule carried stateless, so a filter
	// naming either one silently matched half the rows. Both sources now
	// normalize onto securityRule before they reach MQL, so the predicate sees
	// the same values whichever layer wrote the rule.
	nsgRule := securityRuleFromNsg(core.SecurityRule{
		Id:          new("ocid1.securityrule.oc1..open"),
		Direction:   core.SecurityRuleDirectionIngress,
		Protocol:    new("6"),
		Source:      new("0.0.0.0/0"),
		SourceType:  core.SecurityRuleSourceTypeCidrBlock,
		IsStateless: new(true),
	})
	listRule := securityRuleFromIngress(core.IngressSecurityRule{
		Protocol:    new("6"),
		Source:      new("0.0.0.0/0"),
		SourceType:  core.IngressSecurityRuleSourceTypeCidrBlock,
		IsStateless: new(true),
	})

	assert.True(t, ociRuleValuesOpenIngress(ociIngressValuesOf(nsgRule)),
		"a network security group rule open to any address must match")
	assert.True(t, ociRuleValuesOpenIngress(ociIngressValuesOf(listRule)),
		"a security list rule open to any address must match")

	// Both sources land the stateless flag on the same field, which is what
	// makes .where(stateless) mean one thing across the combined list.
	assert.True(t, nsgRule.stateless)
	assert.True(t, listRule.stateless)

	// A security list ingress rule states no direction of its own; the adapter
	// supplies INGRESS, without which the predicate would reject every
	// security list rule.
	assert.Equal(t, securityRuleIngress, listRule.direction)

	t.Run("narrow and internal sources do not match", func(t *testing.T) {
		narrow := securityRuleFromIngress(core.IngressSecurityRule{
			Source:     new("10.0.0.0/16"),
			SourceType: core.IngressSecurityRuleSourceTypeCidrBlock,
		})
		assert.False(t, ociRuleValuesOpenIngress(ociIngressValuesOf(narrow)))

		service := securityRuleFromIngress(core.IngressSecurityRule{
			Source:     new("all-services-in-oracle-services-network"),
			SourceType: core.IngressSecurityRuleSourceTypeServiceCidrBlock,
		})
		assert.False(t, ociRuleValuesOpenIngress(ociIngressValuesOf(service)))

		egress := securityRuleFromNsg(core.SecurityRule{
			Direction:       core.SecurityRuleDirectionEgress,
			Destination:     new("0.0.0.0/0"),
			DestinationType: core.SecurityRuleDestinationTypeCidrBlock,
		})
		assert.False(t, ociRuleValuesOpenIngress(ociIngressValuesOf(egress)),
			"an egress rule open to the world is not an ingress opening")
	})

	t.Run("ipv6 any-address source matches", func(t *testing.T) {
		v6 := securityRuleFromNsg(core.SecurityRule{
			Direction:  core.SecurityRuleDirectionIngress,
			Source:     new("::/0"),
			SourceType: core.SecurityRuleSourceTypeCidrBlock,
		})
		assert.True(t, ociRuleValuesOpenIngress(ociIngressValuesOf(v6)))
	})
}

func TestOciDnssecKeyVersionArgs(t *testing.T) {
	when := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	sdkTime := &common.SDKTime{Time: when}

	t.Run("key-signing key with a full lifecycle", func(t *testing.T) {
		args := ociKskKeyVersionArgs("ocid1.dns-zone.oc1..zone", dns.KskDnssecKeyVersion{
			Uuid:                            new("uuid-ksk"),
			Algorithm:                       dns.DnssecSigningAlgorithmRsasha256,
			LengthInBytes:                   new(256),
			KeyTag:                          new(12345),
			TimeCreated:                     sdkTime,
			TimeActivated:                   sdkTime,
			PredecessorDnssecKeyVersionUuid: new("uuid-old"),
			DsData: []dns.DnssecKeyVersionDsData{
				{Rdata: new("12345 8 2 ABCD"), DigestType: dns.DnssecDigestTypeSha256},
			},
		})

		assert.Equal(t, "ocid1.dns-zone.oc1..zone/ksk/uuid-ksk", args["__id"].Value)
		assert.Equal(t, "RSASHA256", args["algorithm"].Value)
		assert.Equal(t, int64(256), args["lengthInBytes"].Value)
		assert.Equal(t, int64(12345), args["keyTag"].Value)
		assert.Equal(t, "uuid-old", args["predecessorUuid"].Value)

		created, ok := args["created"].Value.(*time.Time)
		require.True(t, ok, "created must decode to a time")
		assert.Equal(t, when, *created)

		ds, ok := args["dsData"].Value.([]any)
		require.True(t, ok)
		require.Len(t, ds, 1)
		assert.Equal(t, "SHA_256", ds[0].(map[string]any)["digestType"])
	})

	t.Run("an absent timestamp reads null, not the zero time", func(t *testing.T) {
		// Every lifecycle timestamp is optional. Decoding an absent one to the
		// zero time would publish 1 January year 1 as a real date, and an
		// "expired before now" or "activated before X" audit would treat that
		// key as long expired instead of as never scheduled.
		args := ociKskKeyVersionArgs("ocid1.dns-zone.oc1..zone", dns.KskDnssecKeyVersion{
			Uuid:        new("uuid-ksk"),
			TimeCreated: sdkTime,
		})

		for _, field := range []string{
			"timePublished", "timeActivated", "timeInactivated",
			"timeUnpublished", "timeExpired", "timePromoted",
		} {
			assert.Equal(t, types.Nil, args[field].Type, "%s must be null when the service reports none", field)
			assert.Nil(t, args[field].Value, "%s must not decode to the zero time", field)
		}
	})

	t.Run("an absent key length and tag read null, not zero", func(t *testing.T) {
		args := ociZskKeyVersionArgs("ocid1.dns-zone.oc1..zone", dns.ZskDnssecKeyVersion{
			Uuid: new("uuid-zsk"),
		})

		assert.Nil(t, args["lengthInBytes"].Value, "a zero-byte key is not the same as an unreported one")
		assert.Nil(t, args["keyTag"].Value)
	})

	t.Run("a zone-signing key publishes no DS records", func(t *testing.T) {
		// The chain of trust runs through the key-signing key, so an empty list
		// here is a fact about the key rather than a gap in the mapping.
		args := ociZskKeyVersionArgs("ocid1.dns-zone.oc1..zone", dns.ZskDnssecKeyVersion{
			Uuid:      new("uuid-zsk"),
			Algorithm: dns.DnssecSigningAlgorithmRsasha256,
		})

		assert.Equal(t, "ocid1.dns-zone.oc1..zone/zsk/uuid-zsk", args["__id"].Value)
		assert.Equal(t, "RSASHA256", args["algorithm"].Value)
		ds, ok := args["dsData"].Value.([]any)
		require.True(t, ok)
		assert.Empty(t, ds)
	})
}

func TestOciGroupFromList(t *testing.T) {
	group := func(id, ocid string) *mqlOciIdentityDomainGroup {
		return &mqlOciIdentityDomainGroup{
			Id:   plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
			Ocid: plugin.TValue[string]{Data: ocid, State: plugin.StateIsSet},
		}
	}

	admins := group("scim-admins", "ocid1.group.oc1..admins")
	readers := group("scim-readers", "ocid1.group.oc1..readers")
	// A domain predating membership OCIDs reports the SCIM id alone.
	legacy := group("scim-legacy", "")
	groups := []any{admins, readers, legacy}

	t.Run("resolves by OCID", func(t *testing.T) {
		assert.Same(t, readers, ociGroupFromList(groups, "ocid1.group.oc1..readers", "scim-admins"),
			"the OCID is the stronger key and must win over the SCIM id")
	})

	t.Run("falls back to the SCIM id when the membership carries no OCID", func(t *testing.T) {
		assert.Same(t, legacy, ociGroupFromList(groups, "", "scim-legacy"))
	})

	t.Run("an empty OCID never matches a group that reports none", func(t *testing.T) {
		// Without the empty-string guard every membership on a domain that
		// predates membership OCIDs would resolve to whichever group came back
		// first, silently reporting the wrong group's members and description.
		assert.Nil(t, ociGroupFromList([]any{legacy}, "", ""))
	})

	t.Run("a group the caller cannot read resolves to nothing", func(t *testing.T) {
		assert.Nil(t, ociGroupFromList(groups, "ocid1.group.oc1..hidden", "scim-hidden"))
	})

	t.Run("entries of another type are skipped", func(t *testing.T) {
		mixed := []any{"garbage", admins}
		assert.Same(t, admins, ociGroupFromList(mixed, "ocid1.group.oc1..admins", ""))
	})
}

func TestOciMaintenanceWindowArgs(t *testing.T) {
	t.Run("a system with no maintenance window builds no window at all", func(t *testing.T) {
		// Not every DB system has a window configured. Building a window out of
		// the zero of each type would say "patched on a rolling basis with no
		// lead time", which is a claim about a system nobody has configured.
		// The nil return is what makes maintenanceSchedule read null.
		assert.Nil(t, ociMaintenanceWindowArgs(nil))
	})

	t.Run("a custom window maps onto the sub-resource fields", func(t *testing.T) {
		args := ociMaintenanceWindowArgs(&database.MaintenanceWindow{
			Preference:                   database.MaintenanceWindowPreferenceCustomPreference,
			PatchingMode:                 database.MaintenanceWindowPatchingModeNonrolling,
			IsCustomActionTimeoutEnabled: new(true),
			CustomActionTimeoutInMins:    new(30),
			IsMonthlyPatchingEnabled:     new(false),
			Months:                       []database.Month{{Name: database.MonthNameJanuary}, {Name: database.MonthNameApril}},
			WeeksOfMonth:                 []int{2},
			DaysOfWeek:                   []database.DayOfWeek{{Name: database.DayOfWeekNameSunday}},
			HoursOfDay:                   []int{4, 20},
			LeadTimeInWeeks:              new(2),
			SkipRu:                       []bool{true},
		})
		require.NotNil(t, args)

		assert.Equal(t, "CUSTOM_PREFERENCE", args["preference"].Value)
		assert.Equal(t, "NONROLLING", args["patchingMode"].Value)
		assert.Equal(t, true, args["isCustomActionTimeoutEnabled"].Value)
		assert.Equal(t, int64(30), args["customActionTimeoutInMins"].Value)
		assert.Equal(t, false, args["isMonthlyPatchingEnabled"].Value)
		assert.Equal(t, []any{"JANUARY", "APRIL"}, args["months"].Value)
		assert.Equal(t, []any{int64(2)}, args["weeksOfMonth"].Value)
		assert.Equal(t, []any{"SUNDAY"}, args["daysOfWeek"].Value)
		assert.Equal(t, []any{int64(4), int64(20)}, args["hoursOfDay"].Value)
		assert.Equal(t, int64(2), args["leadTimeInWeeks"].Value)
		assert.Equal(t, []any{true}, args["skipRu"].Value)
	})

	t.Run("an absent lead time reads null, not zero weeks", func(t *testing.T) {
		args := ociMaintenanceWindowArgs(&database.MaintenanceWindow{
			Preference: database.MaintenanceWindowPreferenceNoPreference,
		})
		require.NotNil(t, args)

		assert.Equal(t, "NO_PREFERENCE", args["preference"].Value)
		assert.Nil(t, args["leadTimeInWeeks"].Value, "zero weeks of notice is a claim; no lead time configured is not")
		assert.Nil(t, args["isCustomActionTimeoutEnabled"].Value)
		assert.Empty(t, args["months"].Value)
	})
}
