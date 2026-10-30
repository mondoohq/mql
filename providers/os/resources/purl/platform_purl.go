// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package purl

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func NewPlatformPurl(platform *inventory.Platform) (string, error) {
	if platform == nil {
		return "", fmt.Errorf("platform is required")
	}

	qualifiers := map[string]string{}
	if platform.Arch != "" {
		qualifiers[QualifierArch] = platform.Arch
	}

	// generate distro qualifier
	distroQualifiers := []string{}
	distroQualifiers = append(distroQualifiers, platform.Name)
	if platform.Version != "" {
		distroQualifiers = append(distroQualifiers, platform.Version)
	} else if platform.Build != "" {
		distroQualifiers = append(distroQualifiers, platform.Build)
	}

	qualifiers[QualifierDistro] = strings.Join(distroQualifiers, "-")

	if platform.Build != "" {
		qualifiers[QualifierBuild] = platform.Build
	}

	// e.g. used on suse linux
	variantID, ok := platform.Labels["variant-id"]
	if ok && variantID != "" {
		qualifiers["variant-id"] = variantID
	}

	return packageurl.NewPackageURL(
		string(Type_X_Platform),
		"",
		platform.Name,
		platform.Version,
		NewQualifiers(qualifiers),
		"",
	).ToString(), nil
}
