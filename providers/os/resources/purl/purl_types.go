// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package purl

import "github.com/package-url/packageurl-go"

type Type string

// These are only an extension of the known purl types defined at:
//
// https://github.com/package-url/purl-spec#known-purl-types
var (
	// TypeWindows is a pkg:windows purl.
	TypeWindows Type = "windows"
	// TypeAppx is a pkg:appx purl.
	TypeAppx Type = "appx"
	// TypeMacos is a pkg:macos purl.
	TypeMacos Type = "macos"
	// TypeWindowsDriver is a pkg:windows-driver purl.
	//
	// Drivers are not ordinary Windows software and must not share pkg:windows
	// with it. A vendor bundle that shipped an installer registers in
	// Add/Remove Programs as well as with the spooler, so the same driver can
	// be reported twice; the type keeps those apart. The namespace is the
	// VENDOR, because driver names are not unique across vendors: "PCL 6
	// Driver" and "PostScript3 Driver" name page description languages every
	// printer vendor ships a driver for, so keying on the name alone would
	// match one vendor's advisory against another's driver.
	TypeWindowsDriver Type = "windows-driver"
	// Type_X_Platform is a pkg:platform purl.
	Type_X_Platform Type = "platform"
	// TypeSnap is a pkg:snap purl.
	TypeSnap Type = "snap"
	// TypeFlatpak is a pkg:flatpak purl.
	//
	// The namespace is the REMOTE the application was installed from, not a
	// vendor: one application ID names different software depending on where it
	// came from. org.mozilla.firefox is the rapid channel from Flathub and ESR
	// from Red Hat's own remote, so the remote is what keeps two builds of "the
	// same" app apart -- and what decides which advisories apply to it.
	TypeFlatpak Type = "flatpak"
	// TypeCos is a pkg:cos purl for Google Container-Optimized OS packages.
	// Tracks the shape proposed in package-url/purl-spec#270 and emitted by
	// osv-scalibr; not (yet) in the formal purl-spec registry.
	TypeCos Type = "cos"
	// Types we use coming from:
	// https://github.com/package-url/packageurl-go/blob/master/packageurl.go#L54
	TypeGeneric = Type(packageurl.TypeGeneric)
	TypeApk     = Type(packageurl.TypeApk)
	TypeDebian  = Type(packageurl.TypeDebian)
	TypeAlpm    = Type(packageurl.TypeAlpm)
	TypeEbuild  = Type(packageurl.TypeEbuild)
	TypeNix     = Type(packageurl.TypeNix)
	TypeRPM     = Type(packageurl.TypeRPM)

	KnownTypes = map[Type]struct{}{
		TypeAppx:          {},
		TypeWindows:       {},
		TypeWindowsDriver: {},
		TypeMacos:         {},
		TypeFlatpak:       {},
		Type_X_Platform:   {},
		TypeGeneric:       {},
		TypeApk:           {},
		TypeDebian:        {},
		TypeAlpm:          {},
		TypeEbuild:        {},
		TypeNix:           {},
		TypeRPM:           {},
		TypeCos:           {},
	}
)

func ValidTypeString(t string) bool {
	return ValidType(Type(t))
}

func ValidType(t Type) bool {
	_, ok := KnownTypes[t]
	return ok
}
