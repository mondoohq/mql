// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/containerinstances"
	"github.com/oracle/oci-go-sdk/v65/networkfirewall"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// unknownDecryptionProfile stands in for an inspection type newer than the
// pinned SDK, which the generated polymorphic decoder surfaces as a value that
// satisfies the interface but matches neither concrete case.
type unknownDecryptionProfile struct{}

func (unknownDecryptionProfile) GetName() *string { return new("future-profile") }
func (unknownDecryptionProfile) GetParentResourceId() *string {
	return new("ocid1.networkfirewallpolicy.oc1..example")
}
func (unknownDecryptionProfile) GetDescription() *string { return new("unknown") }

// TestDecryptionProfileFieldsUnknownTypeBlocksNothing covers the branch the
// existing TestDecryptionProfileFields never exercised. Every control on a
// profile we could not decode must read false, not null: MQL evaluates
// `null && null` as true, so leaving them null let an undecodable profile pass
// a certificate-validation check it was never measured for.
func TestDecryptionProfileFieldsUnknownTypeBlocksNothing(t *testing.T) {
	summary := networkfirewall.DecryptionProfileSummary{
		Name:        new("future-profile"),
		Type:        "SSL_SOMETHING_NEW",
		Description: new("an inspection type newer than the pinned SDK"),
	}

	// A profile the type switch does not know about, standing in for whatever
	// Oracle ships next. The base struct satisfies the interface without
	// matching either concrete case, which is exactly the SDK's own fallback.
	fields := decryptionProfileFields(unknownDecryptionProfile{}, summary)

	mustBeExplicitFalse := []string{
		"isUnsupportedVersionBlocked",
		"isUnsupportedCipherBlocked",
		"isOutOfCapacityBlocked",
		"isExpiredCertificateBlocked",
		"isUntrustedIssuerBlocked",
		"isRevocationStatusTimeoutBlocked",
		"isUnknownRevocationStatusBlocked",
		"areCertificateExtensionsRestricted",
		"isAutoIncludeAltName",
	}
	for _, name := range mustBeExplicitFalse {
		raw, ok := fields[name]
		if !ok {
			t.Fatalf("field %q missing from the unknown-profile branch", name)
		}
		if raw.Value == nil {
			t.Errorf("field %q is null on an undecodable profile; null && null passes a check that was never measured", name)
			continue
		}
		if v, ok := raw.Value.(bool); !ok || v {
			t.Errorf("field %q = %v, want explicit false", name, raw.Value)
		}
	}

	if got := fields["type"].Value; got != "SSL_SOMETHING_NEW" {
		t.Errorf("type = %v, want the summary's type passed through", got)
	}
}

// TestOciContainerSecurityContext pins the flattening of a container's Linux
// security context, including the deliberate asymmetry between the booleans
// (explicit false, so an unhardened container fails a check) and the uid/gid
// (null, so an absent context does not assert the container runs as root).
func TestOciContainerSecurityContext(t *testing.T) {
	t.Run("absent security context fails closed", func(t *testing.T) {
		view := ociContainerSecurityContext(nil)

		if view.nonRootUserCheck {
			t.Error("nonRootUserCheck must be false when there is no security context")
		}
		if view.readonlyRootFs {
			t.Error("readonlyRootFs must be false when there is no security context")
		}
		if view.runAsUser != nil {
			t.Errorf("runAsUser = %v, want nil: an absent context does not mean uid 0", *view.runAsUser)
		}
		if view.runAsGroup != nil {
			t.Errorf("runAsGroup = %v, want nil", *view.runAsGroup)
		}
		if view.added == nil || len(view.added) != 0 {
			t.Errorf("added = %v, want an empty non-nil slice", view.added)
		}
		if view.dropped == nil || len(view.dropped) != 0 {
			t.Errorf("dropped = %v, want an empty non-nil slice", view.dropped)
		}
	})

	t.Run("hardened container", func(t *testing.T) {
		uid, gid := 1000, 1000
		view := ociContainerSecurityContext(containerinstances.LinuxSecurityContext{
			RunAsUser:                 &uid,
			RunAsGroup:                &gid,
			IsNonRootUserCheckEnabled: new(true),
			IsRootFileSystemReadonly:  new(true),
			Capabilities: &containerinstances.ContainerCapabilities{
				DropCapabilities: []containerinstances.ContainerCapabilityTypeEnum{
					containerinstances.ContainerCapabilityTypeCapChown,
				},
			},
		})

		if !view.nonRootUserCheck || !view.readonlyRootFs {
			t.Error("hardened flags did not survive flattening")
		}
		if view.runAsUser == nil || *view.runAsUser != 1000 {
			t.Errorf("runAsUser = %v, want 1000", view.runAsUser)
		}
		if len(view.dropped) != 1 || view.dropped[0] != string(containerinstances.ContainerCapabilityTypeCapChown) {
			t.Errorf("dropped = %v, want the dropped capability as a string", view.dropped)
		}
	})

	t.Run("root container with added capabilities", func(t *testing.T) {
		uid := 0
		view := ociContainerSecurityContext(containerinstances.LinuxSecurityContext{
			RunAsUser: &uid,
			Capabilities: &containerinstances.ContainerCapabilities{
				AddCapabilities: []containerinstances.ContainerCapabilityTypeEnum{
					containerinstances.ContainerCapabilityTypeCapKill,
				},
			},
		})

		if view.runAsUser == nil || *view.runAsUser != 0 {
			t.Errorf("runAsUser = %v, want an explicit 0 for a root container", view.runAsUser)
		}
		if len(view.added) != 1 {
			t.Errorf("added = %v, want one capability", view.added)
		}
	})
}

// TestOciTunnelCryptoValue pins the null-vs-empty-string contract for IPSec
// tunnel crypto. Reporting "" for an unnegotiated parameter made the natural
// denylist assertion (`phase1DhGroup != "GROUP2"`) pass on a tunnel whose crypto
// was never measured.
func TestOciTunnelCryptoValue(t *testing.T) {
	t.Run("absent value marks the field null", func(t *testing.T) {
		var field plugin.TValue[string]
		got, err := ociTunnelCryptoValue(&field, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("value = %q, want the zero string", got)
		}
		if field.State&plugin.StateIsNull == 0 || field.State&plugin.StateIsSet == 0 {
			t.Errorf("state = %v, want set|null so the field reads as MQL null", field.State)
		}
	})

	t.Run("empty string is treated as absent", func(t *testing.T) {
		var field plugin.TValue[string]
		empty := ""
		if _, err := ociTunnelCryptoValue(&field, &empty); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if field.State&plugin.StateIsNull == 0 {
			t.Error("an empty negotiated value must read as null, not as a real answer")
		}
	})

	t.Run("negotiated value passes through", func(t *testing.T) {
		var field plugin.TValue[string]
		group := "GROUP20"
		got, err := ociTunnelCryptoValue(&field, &group)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "GROUP20" {
			t.Errorf("value = %q, want GROUP20", got)
		}
		if field.State&plugin.StateIsNull != 0 {
			t.Error("a real value must not be marked null")
		}
	})
}

// TestOciTunnelCryptoFlag pins the boolean counterpart, which resolves an
// absent value to false because false is the failing direction for every flag
// it covers (PFS off, IKE/ESP not established).
func TestOciTunnelCryptoFlag(t *testing.T) {
	if ociTunnelCryptoFlag(nil) {
		t.Error("nil must read as false, so an unmeasured tunnel fails the check")
	}
	if ociTunnelCryptoFlag(new(false)) {
		t.Error("false must stay false")
	}
	if !ociTunnelCryptoFlag(new(true)) {
		t.Error("true must stay true")
	}
}

// TestOciBucketCacheKey pins the bucket cache key. Buckets are keyed on
// namespace and name rather than an OCID, which the listing API does not
// return, so the key must stay distinct across both parts.
func TestOciBucketCacheKey(t *testing.T) {
	a := ociBucketCacheKey("mytenancy", "logs")
	b := ociBucketCacheKey("mytenancy", "backups")
	c := ociBucketCacheKey("othertenancy", "logs")

	if a == b || a == c || b == c {
		t.Errorf("cache keys collide: %q %q %q", a, b, c)
	}
	if want := "oci.objectStorage.bucket/mytenancy/logs"; a != want {
		t.Errorf("key = %q, want %q", a, want)
	}
}
