// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package purl_test

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

func TestNewQualifiers(t *testing.T) {
	t.Run("Empty qualifiers map", func(t *testing.T) {
		result := purl.NewQualifiers(map[string]string{})
		assert.Empty(t, result)
	})

	t.Run("Valid qualifiers map", func(t *testing.T) {
		qualifiers := map[string]string{
			"arch": "x86_64",
			"os":   "linux",
		}
		expected := packageurl.Qualifiers{
			{Key: "arch", Value: "x86_64"},
			{Key: "os", Value: "linux"},
		}

		result := purl.NewQualifiers(qualifiers)
		assert.Equal(t, expected, result)
	})

	t.Run("Qualifiers map with empty values", func(t *testing.T) {
		qualifiers := map[string]string{
			"arch": "x86_64",
			"os":   "",
		}
		expected := packageurl.Qualifiers{
			{Key: "arch", Value: "x86_64"},
		}

		result := purl.NewQualifiers(qualifiers)
		assert.Equal(t, expected, result)
	})

	t.Run("Qualifiers map with unsorted keys", func(t *testing.T) {
		qualifiers := map[string]string{
			"os":   "linux",
			"arch": "x86_64",
		}
		expected := packageurl.Qualifiers{
			{Key: "arch", Value: "x86_64"},
			{Key: "os", Value: "linux"},
		}

		result := purl.NewQualifiers(qualifiers)
		assert.Equal(t, expected, result)
	})
}

func TestNewPackageURL(t *testing.T) {
	platform := &inventory.Platform{
		Arch:    "x86_64",
		Version: "22.04",
		Labels: map[string]string{
			"distro-id": "ubuntu",
		},
	}

	t.Run("Basic PackageURL", func(t *testing.T) {
		p := purl.NewPackageURL(platform, purl.TypeApk, "testpkg", "1.0.0")
		assert.Equal(t, purl.TypeApk, p.Type)
		assert.Equal(t, "testpkg", p.Name)
		assert.Equal(t, "1.0.0", p.Version)
		assert.Equal(t, "x86_64", p.Arch)
		assert.Equal(t, "", p.Namespace)
	})

	t.Run("Modifiers applied", func(t *testing.T) {
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0",
			purl.WithArch("arm64"),
			purl.WithEpoch("1"),
		)
		assert.Equal(t, "arm64", p.Arch)
		assert.Equal(t, "1", p.Epoch)
	})

	t.Run("Nil platform won't discover optional attributes", func(t *testing.T) {
		p := purl.NewPackageURL(nil, purl.TypeDebian, "testpkg", "1.0.0")
		assert.Equal(t, purl.TypeDebian, p.Type)
		assert.Equal(t, "testpkg", p.Name)
		assert.Equal(t, "1.0.0", p.Version)
		assert.Empty(t, p.Arch)
		assert.Empty(t, p.Namespace)
	})
}

func TestPackageURLString(t *testing.T) {
	platform := &inventory.Platform{
		Arch:    "x86_64",
		Version: "22.04",
		Labels: map[string]string{
			"distro-id": "ubuntu",
		},
	}

	t.Run("Basic PackageURL string", func(t *testing.T) {
		p := purl.NewPackageURL(platform, purl.TypeDebian, "testpkg", "1.0.0")
		expected := "pkg:deb/testpkg@1.0.0?arch=x86_64&distro=ubuntu-22.04"
		assert.Equal(t, expected, p.String())
	})

	t.Run("With Epoch", func(t *testing.T) {
		p := purl.NewPackageURL(platform, purl.TypeDebian, "testpkg", "1.0.0",
			purl.WithEpoch("2"),
		)
		expected := "pkg:deb/testpkg@1.0.0?arch=x86_64&distro=ubuntu-22.04&epoch=2"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Without Namespace from platform", func(t *testing.T) {
		platform := &inventory.Platform{
			Arch:    "x86_64",
			Version: "11",
			Labels:  nil,
		}
		p := purl.NewPackageURL(platform, purl.TypeDebian, "testpkg", "1.0.0")
		expected := "pkg:deb/testpkg@1.0.0?arch=x86_64"
		assert.Equal(t, expected, p.String())

		t.Run("But Namespace from modifiers", func(t *testing.T) {
			platform := &inventory.Platform{
				Arch:    "x86_64",
				Version: "11",
				Labels:  nil,
			}
			p := purl.NewPackageURL(platform, purl.TypeDebian, "testpkg", "1.0.0",
				purl.WithNamespace("debian"),
			)
			expected := "pkg:deb/debian/testpkg@1.0.0?arch=x86_64"
			assert.Equal(t, expected, p.String())
		})
	})

	t.Run("Modifiers overriding platform values", func(t *testing.T) {
		p := purl.NewPackageURL(platform, purl.TypeDebian, "testpkg", "1.0.0",
			purl.WithArch("arm64"),
		)
		expected := "pkg:deb/testpkg@1.0.0?arch=arm64&distro=ubuntu-22.04"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Empty Platform and Qualifiers", func(t *testing.T) {
		p := purl.NewPackageURL(nil, purl.TypeApk, "testpkg", "1.0.0")
		expected := "pkg:apk/testpkg@1.0.0"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Non-standard Type", func(t *testing.T) {
		p := purl.NewPackageURL(nil, "customtype", "testpkg", "1.0.0")
		expected := "pkg:customtype/testpkg@1.0.0"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Special characters in fields", func(t *testing.T) {
		p := purl.NewPackageURL(nil, purl.TypeApk, "pkg@123", "1.0.0")
		expected := "pkg:apk/pkg%40123@1.0.0"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Empty name and version", func(t *testing.T) {
		p := purl.NewPackageURL(nil, purl.TypeGeneric, "", "")
		assert.Equal(t, purl.TypeGeneric, p.Type)
		assert.Empty(t, p.Name)
		assert.Empty(t, p.Version)
		assert.Empty(t, p.Namespace)
		assert.Empty(t, p.Arch)
	})

	// These three used to mutate the shared `platform` above in place and read
	// each other's writes, which made them position-dependent and left
	// "Set platform name" failing under `go test -run`. Each builds its own
	// fixture now, matching every subtest from "Red Hat package" down.
	t.Run("Both version and build specified, we prefer version", func(t *testing.T) {
		platform := &inventory.Platform{
			Arch:    "x86_64",
			Version: "22.04",
			Build:   "20.04",
			Labels:  map[string]string{"distro-id": "ubuntu"},
		}
		p := purl.NewPackageURL(platform, purl.TypeDebian, "testpkg", "1.0.0")
		expected := "pkg:deb/testpkg@1.0.0?arch=x86_64&distro=ubuntu-22.04"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Only build specified", func(t *testing.T) {
		platform := &inventory.Platform{
			Arch:   "x86_64",
			Build:  "20.04",
			Labels: map[string]string{"distro-id": "ubuntu"},
		}
		p := purl.NewPackageURL(platform, purl.TypeDebian, "testpkg", "1.0.0")
		expected := "pkg:deb/testpkg@1.0.0?arch=x86_64&distro=ubuntu-20.04"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Set platform name", func(t *testing.T) {
		platform := &inventory.Platform{
			Arch:   "x86_64",
			Name:   "ubuntu",
			Build:  "20.04",
			Labels: map[string]string{"distro-id": "ubuntu"},
		}
		p := purl.NewPackageURL(platform, purl.TypeDebian, "testpkg", "1.0.0")
		expected := "pkg:deb/ubuntu/testpkg@1.0.0?arch=x86_64&distro=ubuntu-20.04"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Red Hat package", func(t *testing.T) {
		platform := &inventory.Platform{
			Arch:    "x86_64",
			Version: "9.2",
			Labels: map[string]string{
				"distro-id": "rhel",
			},
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/testpkg@1.0.0?arch=x86_64&distro=rhel-9.2"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Red Hat package without distro-id", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "redhat",
			Arch:    "x86_64",
			Version: "9.2",
			Labels:  nil,
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/redhat/testpkg@1.0.0?arch=x86_64"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Red Hat package with distro-id and name", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "redhat",
			Arch:    "x86_64",
			Version: "9.2",
			Labels: map[string]string{
				"distro-id": "rhel",
			},
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/redhat/testpkg@1.0.0?arch=x86_64&distro=rhel-9.2"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Photon package", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "photon",
			Arch:    "x86_64",
			Version: "4.0",
			Labels:  nil,
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/photon%20os/testpkg@1.0.0?arch=x86_64"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Photon package with distro-id and name", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "photon",
			Arch:    "x86_64",
			Version: "4.0",
			Labels: map[string]string{
				"distro-id": "photon",
			},
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/photon%20os/testpkg@1.0.0?arch=x86_64&distro=photon-4.0"
		assert.Equal(t, expected, p.String())
	})

	t.Run("Rocky Linux package", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "rockylinux",
			Arch:    "x86_64",
			Version: "8.6",
			Labels:  nil,
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/rocky-linux/testpkg@1.0.0?arch=x86_64"
		assert.Equal(t, expected, p.String())
	})

	t.Run("openSUSE package", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "opensuse-leap",
			Arch:    "x86_64",
			Version: "15.4",
			Labels:  nil,
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/opensuse/testpkg@1.0.0?arch=x86_64"
		assert.Equal(t, expected, p.String())
	})

	t.Run("SUSE package", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "sles",
			Arch:    "x86_64",
			Version: "15.4",
			Labels:  nil,
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/suse/testpkg@1.0.0?arch=x86_64"
		assert.Equal(t, expected, p.String())
	})

	// SUSE Linux Micro packages are SUSE's, like SLES ones.
	t.Run("SUSE Linux Micro package", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "suse-microos",
			Arch:    "x86_64",
			Version: "6.2",
			Labels:  map[string]string{detector.LabelDistroID: "sl-micro"},
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/suse/testpkg@1.0.0?arch=x86_64&distro=sl-micro-6.2"
		assert.Equal(t, expected, p.String())
	})

	// matches what openSUSE's own build service emits for MicroOS packages:
	// the namespace collapses to opensuse and the product stays in the distro
	// qualifier.
	t.Run("openSUSE MicroOS package", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:    "opensuse-microos",
			Arch:    "x86_64",
			Version: "20260822",
			Labels:  map[string]string{detector.LabelDistroID: "opensuse-microos"},
		}
		p := purl.NewPackageURL(platform, purl.TypeRPM, "testpkg", "1.0.0")
		expected := "pkg:rpm/opensuse/testpkg@1.0.0?arch=x86_64&distro=opensuse-microos-20260822"
		assert.Equal(t, expected, p.String())
	})

	// Arch and its derivatives ship no VERSION_ID, only BUILD_ID=rolling, so
	// the distro qualifier has to come from the build id.
	t.Run("rolling release package", func(t *testing.T) {
		platform := &inventory.Platform{
			Name:  "arch",
			Arch:  "x86_64",
			Build: "rolling",
			Labels: map[string]string{
				"distro-id": "arch",
			},
		}
		p := purl.NewPackageURL(platform, purl.TypeAlpm, "testpkg", "1.0.0")
		expected := "pkg:alpm/arch/testpkg@1.0.0?arch=x86_64&distro=arch-rolling"
		assert.Equal(t, expected, p.String())
	})

	t.Run("package without version or build", func(t *testing.T) {
		platform := &inventory.Platform{
			Name: "arch",
			Arch: "x86_64",
			Labels: map[string]string{
				"distro-id": "arch",
			},
		}
		p := purl.NewPackageURL(platform, purl.TypeAlpm, "testpkg", "1.0.0")
		expected := "pkg:alpm/arch/testpkg@1.0.0?arch=x86_64&distro=arch"
		assert.Equal(t, expected, p.String())
	})
}

// TestPackageURLEncoding pins how each purl segment is percent-encoded, for
// characters a plausible encoder change would treat differently.
//
// It lives in its own function so encoding cases sit together and stay
// independent of TestPackageURLString's platform fixtures.
func TestPackageURLEncoding(t *testing.T) {
	// Name and version. packageurl-go v0.1.6 stopped percent-encoding the RFC
	// 3986 sub-delimiters here and emitted "... Redistributable (x64)@..."
	// instead of "%28x64%29"; we pinned to v0.1.5 until the upstream fix
	// (package-url/packageurl-go#93) shipped in v0.1.7. Both cases fail on
	// v0.1.6. The existing "Special characters in fields" subtest covers @ in
	// a name; these cover the sub-delimiters it does not.
	t.Run("Name and version", func(t *testing.T) {
		t.Run("Every RFC 3986 sub-delimiter", func(t *testing.T) {
			p := purl.NewPackageURL(nil, purl.TypeGeneric, "a!b$c&d'e(f)g*h+i,j;k=l", "1;2=3")
			expected := "pkg:generic/a%21b%24c%26d%27e%28f%29g%2Ah%2Bi%2Cj%3Bk%3Dl@1%3B2%3D3"
			assert.Equal(t, expected, p.String())
		})

		t.Run("Windows display name with parentheses", func(t *testing.T) {
			p := purl.NewPackageURL(nil, purl.TypeWindows,
				"Microsoft Visual C++ 2015-2022 Redistributable (x64)", "14.38.33130.0")
			expected := "pkg:windows/Microsoft%20Visual%20C%2B%2B%202015-2022%20Redistributable%20%28x64%29@14.38.33130.0"
			assert.Equal(t, expected, p.String())
		})
	})

	// Namespace. v0.1.7 replaced the namespace encoder wholesale, and this
	// case fails on v0.1.6 ("Brother%20&%20Co." rather than "%26"), so the
	// namespace path was genuinely unguarded against that class of change.
	//
	// Spaces in a namespace are already covered through the real photon
	// mapping by the "Photon package" subtests in TestPackageURLString; a
	// space renders identically on v0.1.5, v0.1.6 and v0.1.7, so a second
	// space case here would add nothing. Sub-delimiters are the gap.
	//
	// The vendor string is illustrative. pkg:windows-driver purls are built
	// today by printerdriver.go concatenating pre-slugified lowercase-hyphen
	// tokens, which never reach this encoder -- that hand-rolled path does no
	// percent-encoding at all and is worth guarding separately.
	t.Run("Sub-delimiters in a namespace", func(t *testing.T) {
		p := purl.NewPackageURL(nil, purl.TypeWindowsDriver, "PCL 6 Driver", "1.0",
			purl.WithNamespace("Brother & Co."))
		assert.Equal(t, "pkg:windows-driver/Brother%20%26%20Co./PCL%206%20Driver@1.0", p.String())
	})

	// Qualifier values. Neither case fails on v0.1.6 -- the qualifier encoder
	// did not regress there -- so these guard forward, against a future
	// release changing what it escapes.
	t.Run("Qualifier values", func(t *testing.T) {
		// An unescaped '&' would split one qualifier into two, so this is the
		// difference between a value and a corrupt purl.
		t.Run("Ampersand is escaped", func(t *testing.T) {
			p := purl.NewPackageURL(nil, purl.TypeMacos, "app", "1.0",
				purl.WithQualifiers(map[string]string{"remoting-name": "Photo & Video Editor"}))
			assert.Equal(t, "pkg:macos/app@1.0?remoting-name=Photo%20%26%20Video%20Editor", p.String())
		})

		// The colon must stay literal. rpm_packages.go emits rpmmod values
		// shaped "nodejs:18:8060020220810121341:ad008a3a", and ':' is a
		// deliberate one-byte exception in v0.1.7's rewritten qualifier
		// allowlist. If a future release drops that exception every modular
		// RPM purl gains "%3A" and stops matching stored purls -- silently,
		// since nothing else in the repo pins it.
		t.Run("Colon in an rpmmod value stays literal", func(t *testing.T) {
			p := purl.NewPackageURL(nil, purl.TypeRPM, "nodejs", "18.20.4",
				purl.WithQualifiers(map[string]string{"rpmmod": "nodejs:18:8060020220810121341:ad008a3a"}))
			assert.Equal(t, "pkg:rpm/nodejs@18.20.4?rpmmod=nodejs:18:8060020220810121341:ad008a3a", p.String())
		})
	})
}

// TestPackageURLStringDoesNotMutateQualifiers guards the render-side copy in
// String().
//
// The derived arch/epoch/distro entries used to be written into the caller's
// map, so a second package rendered from the same map inherited the first
// one's platform -- reporting an arch and distro it never had, with no error
// anywhere. No caller reuses a map today (each builds a fresh one per
// package), so this pins the contract rather than fixing a live bug.
//
// What this does NOT protect: a caller that accumulates keys in its own map
// across a loop. If a conditional `qualifiers["efix"] = "locked"` runs on one
// iteration, every later package built from that same map still carries the
// key. No copy on our side can undo the caller's own writes -- the map must be
// built per package.
func TestPackageURLStringDoesNotMutateQualifiers(t *testing.T) {
	shared := map[string]string{"custom": "value"}

	platform := &inventory.Platform{
		Arch:    "x86_64",
		Version: "22.04",
		Name:    "ubuntu",
		Labels:  map[string]string{"distro-id": "ubuntu"},
	}

	withPlatform := purl.NewPackageURL(platform, purl.TypeDebian, "pkgA", "1.0",
		purl.WithQualifiers(shared))
	assert.Equal(t, "pkg:deb/ubuntu/pkgA@1.0?arch=x86_64&custom=value&distro=ubuntu-22.04",
		withPlatform.String())

	assert.Equal(t, map[string]string{"custom": "value"}, shared,
		"String() must not write its derived qualifiers into the caller's map")

	// String() renders; it must not also mutate. Without the render-side copy
	// the derived arch/epoch/distro land in the PackageURL's own qualifier map
	// as a side effect, so reading Qualifiers after a render returns something
	// different from before it.
	assert.Equal(t, map[string]string{"custom": "value"}, withPlatform.Qualifiers,
		"String() must not write its derived qualifiers into the PackageURL either")

	// The leak was observable here: rendered with no platform, this package
	// used to come back carrying the first one's arch and distro.
	noPlatform := purl.NewPackageURL(nil, purl.TypeDebian, "pkgB", "2.0",
		purl.WithQualifiers(shared))
	assert.Equal(t, "pkg:deb/pkgB@2.0?custom=value", noPlatform.String())
}

// TestWithQualifiersCopiesTheCallerMap guards the other direction. String()
// copying on the way out is not enough on its own: if WithQualifiers stored
// the caller's map by reference, a later edit by the caller would silently
// change an already-constructed purl, and purl.Qualifiers would be a live
// handle writing back into caller storage.
func TestWithQualifiersCopiesTheCallerMap(t *testing.T) {
	caller := map[string]string{"custom": "original"}

	p := purl.NewPackageURL(nil, purl.TypeDebian, "pkg", "1.0",
		purl.WithQualifiers(caller))

	// The caller edits its map after construction.
	caller["custom"] = "MUTATED"
	caller["sneaked-in"] = "yes"

	assert.Equal(t, "pkg:deb/pkg@1.0?custom=original", p.String(),
		"a constructed purl must not track later edits to the caller's map")

	// And the purl's own map must not be a handle into the caller's.
	p.Qualifiers["written-through"] = "yes"
	assert.NotContains(t, caller, "written-through",
		"purl.Qualifiers must not alias the caller's map")
}
