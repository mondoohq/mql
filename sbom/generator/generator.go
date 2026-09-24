// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package generator

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/cli/reporter"
	"go.mondoo.com/mql/mrn"
	"go.mondoo.com/mql/sbom"
	"go.mondoo.com/mql/utils/sortx"
)

var LABEL_KERNEL_RUNNING = "mondoo.com/os/kernel-running"

// languagePackages maps the packages one language ecosystem reported into SBOM
// packages.
//
// Most ecosystems' mappings are identical apart from the package type, so they
// share one constructor rather than a copy each. That is not only tidiness: a
// field added to the mapping has to reach every ecosystem, and a row of
// hand-maintained copies is exactly the shape where it reaches all but one, and
// the last is found later by a user whose SBOM is missing it.
func languagePackages(pkgs []BomPackage, pkgType string) []*sbom.Package {
	out := make([]*sbom.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		out = append(out, languagePackage(pkg, pkgType))
	}
	return out
}

// languagePackage maps one reported package, for the ecosystems whose loop
// carries something of its own and cannot use languagePackages.
func languagePackage(pkg BomPackage, pkgType string) *sbom.Package {
	bomPkg := &sbom.Package{
		Name:    pkg.Name,
		Version: pkg.Version,
		Purl:    pkg.Purl,
		Cpes:    pkg.CPEs,
		Type:    pkgType,
		// The legacy scalar stays written alongside the list. Nothing populates
		// it from the list, so a consumer that has not migrated would otherwise
		// see nothing where a license was reported.
		License:  pkg.License,
		Licenses: sbom.DeclaredLicenses(pkg.License),
	}

	for _, filepath := range pkg.FilePaths {
		bomPkg.EvidenceList = append(bomPkg.EvidenceList, &sbom.Evidence{
			Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
			Value: filepath,
		})
	}

	return bomPkg
}

// GenerateBom generates a BOM from a cnquery json report collection
func GenerateBom(r *reporter.Report) []*sbom.Sbom {
	if r == nil {
		return nil
	}

	generator := &sbom.Generator{
		Vendor:  "Mondoo, Inc.",
		Name:    "mql",
		Version: mql.Version,
		Url:     "https://mondoo.com",
	}
	now := time.Now().UTC().Format(time.RFC3339)

	boms := []*sbom.Sbom{}
	for mrn := range r.Assets {
		asset := r.Assets[mrn]
		bom := &sbom.Sbom{
			Generator: generator,
			Timestamp: now,
			Status:    sbom.Status_STATUS_SUCCEEDED,
		}

		bom.Asset = &sbom.Asset{
			Name:        asset.GetName(),
			PlatformIds: nil,
			Platform:    &sbom.Platform{},
			Labels:      asset.GetLabels(),
			ExternalIds: []*sbom.ExternalID{},
			TraceId:     asset.GetTraceId(),
		}

		bom.Packages = []*sbom.Package{}

		// extract os packages and python packages
		dataPoints := r.Data[mrn]
		if dataPoints == nil {
			bom.Status = sbom.Status_STATUS_FAILED
			bom.ErrorMessage = "no data points found"
			boms = append(boms, bom)
			continue
		}
		// ensure deterministic order of enumeration
		keys := sortx.Keys(dataPoints.Values)
		// fieldErrors collects one message per data point that could not be
		// consumed (e.g. a provider crashed mid-scan and left that field's
		// content an error rather than the expected shape). The BOM still
		// builds from whatever other data points did decode, so this is a
		// partial result, not a failed one -- matching cnspec's aibom
		// generator (internal/aibom/generator/generator.go), which treats
		// the same per-data-point decode failure as PARTIALLY_SUCCEEDED
		// rather than FAILED.
		//
		// decodedCount tracks how many data points decoded successfully, so
		// "everything failed" can be told apart from "everything decoded but
		// legitimately produced zero packages" (e.g. an asset with no
		// installed software). Using len(bom.Packages) == 0 for that instead
		// would be wrong on both sides: it would call a BOM with zero
		// packages "failed" even though every data point decoded fine, and
		// it would call a BOM with some packages "partially succeeded" even
		// if every data point failed to decode but happened to still leave
		// packages from a still-standing field (see PrinterDrivers below,
		// which can append before an error on a later key). Basing it on
		// decode success -- not package count -- is correct either way.
		var fieldErrors []string
		var decodedCount int
		for _, k := range keys {
			dataValue := dataPoints.Values[k]
			jsondata, err := reporter.JsonValue(dataValue.Content)
			if err != nil {
				fieldErrors = append(fieldErrors, k+": "+errors.Wrap(err, "failed to parse json data").Error())
				continue
			}
			rb := BomFields{}
			err = json.Unmarshal(jsondata, &rb)
			if err != nil {
				fieldErrors = append(fieldErrors, k+": "+errors.Wrap(err, "failed to parse bom fields json data").Error())
				continue
			}
			decodedCount++
			if rb.Asset != nil {
				bom.Asset.Name = rb.Asset.Name
				bom.Asset.Platform.Name = rb.Asset.Platform
				bom.Asset.Platform.Version = rb.Asset.Version
				bom.Asset.Platform.Build = rb.Asset.Build
				bom.Asset.Platform.Family = rb.Asset.Family
				bom.Asset.Platform.Arch = rb.Asset.Arch
				bom.Asset.Platform.Cpes = rb.Asset.CPEs
				bom.Asset.Platform.Labels = rb.Asset.Labels
				bom.Asset.PlatformIds = enrichPlatformIds(rb.Asset.IDs)
				bom.Asset.Platform.Title = rb.Asset.PlatformTitle
			}

			if bom.Asset == nil {
				bom.Asset = &sbom.Asset{}
			}
			if bom.Asset.Labels == nil {
				bom.Asset.Labels = map[string]string{}
			}

			// store version of running kernel
			for _, kernel := range rb.KernelInstalled {
				if kernel.Running {
					bom.Asset.Labels[LABEL_KERNEL_RUNNING] = kernel.Version
				}
			}

			// Windows print drivers. Their purl is built by the resource
			// (providers/os/resources/windows/printerdriver.go) and is empty
			// when the spooler reports no manufacturer or no name -- a driver
			// name alone does not identify a driver, since "PCL 6 Driver" names
			// a page description language that every printer vendor ships one
			// for. Such a driver is still listed, it just carries no purl.
			for _, drv := range rb.PrinterDrivers {
				bom.Packages = append(bom.Packages, &sbom.Package{
					Name:    drv.Name,
					Version: drv.Version,
					Purl:    drv.Purl,
					Cpes:    drv.CPEs,
					Type:    "windows-driver",
				})
			}

			if rb.Packages != nil {
				for _, pkg := range rb.Packages {
					bomPkg := &sbom.Package{
						Name:         pkg.Name,
						Version:      pkg.Version,
						Architecture: pkg.Arch,
						Origin:       pkg.Origin,
						Purl:         pkg.Purl,
						Cpes:         pkg.CPEs,
						Type:         pkg.Format,
						License:      pkg.License,
						Licenses:     sbom.DeclaredLicenses(pkg.License),
					}

					for _, filepath := range pkg.FilePaths {
						bomPkg.EvidenceList = append(bomPkg.EvidenceList, &sbom.Evidence{
							Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
							Value: filepath,
						})
					}

					bom.Packages = append(bom.Packages, bomPkg)
				}
			}

			for _, pkg := range rb.PythonPackages {
				bomPkg := &sbom.Package{
					Name:     pkg.Name,
					Version:  pkg.Version,
					Purl:     pkg.Purl,
					Cpes:     pkg.CPEs,
					Type:     "pypi",
					License:  pkg.License,
					Licenses: sbom.DeclaredLicenses(pkg.License),
				}

				// deprecated path, all files are now in the FilePaths field
				// TODO: update once the python resource returns multiple results
				if pkg.FilePath != "" {
					bomPkg.EvidenceList = append(bomPkg.EvidenceList, &sbom.Evidence{
						Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
						Value: pkg.FilePath,
					})
				}

				for _, filepath := range pkg.FilePaths {
					bomPkg.EvidenceList = append(bomPkg.EvidenceList, &sbom.Evidence{
						Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
						Value: filepath,
					})
				}

				bom.Packages = append(bom.Packages, bomPkg)
			}

			bom.Packages = append(bom.Packages, languagePackages(rb.NpmPackages, "npm")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.GoPackages, "go-module")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.JavaPackages, "maven")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.RustPackages, "cargo")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.DotnetPackages, "nuget")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.PhpPackages, "composer")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.GithubActionsPackages, "github-action")...)

			for _, pkg := range rb.SwiftPackages {
				pkgType := "swift"
				if strings.HasPrefix(pkg.Purl, "pkg:cocoapods/") {
					pkgType = "cocoapods"
				}
				bom.Packages = append(bom.Packages, languagePackage(pkg, pkgType))
			}

			bom.Packages = append(bom.Packages, languagePackages(rb.TerraformPackages, "terraform")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.JenkinsPackages, "jenkins-plugin")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.WordpressPackages, "wordpress-plugin")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.RubyPackages, "gem")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.DartPackages, "pub")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.HaskellPackages, "hackage")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.ElixirPackages, "hex")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.ErlangPackages, "hex")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.PrologPackages, "swi-prolog")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.JuliaPackages, "julia")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.CondaPackages, "conda")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.RPackages, "cran")...)

			bom.Packages = append(bom.Packages, languagePackages(rb.LuaPackages, "luarocks")...)
		}

		// Stamp a stable bom_ref on every component (purl-when-present, else a
		// synthesized fallback) so renders are reproducible and dependency-graph
		// edges have a stable endpoint to reference. Only fills empties, so a ref
		// already carried from a lockfile is preserved.
		for _, pkg := range bom.Packages {
			if pkg.BomRef == "" {
				pkg.BomRef = sbom.BomRefFor(pkg)
			}
		}

		if len(fieldErrors) > 0 {
			if decodedCount == 0 {
				// Every data point failed to decode: nothing usable was
				// produced for this asset, so a BOM with zero packages here
				// is a genuine failure, not a partial success.
				bom.Status = sbom.Status_STATUS_FAILED
			} else {
				bom.Status = sbom.Status_STATUS_PARTIALLY_SUCCEEDED
			}
			bom.ErrorMessage = strings.Join(fieldErrors, "; ")
		}

		boms = append(boms, bom)
	}
	return boms
}

// enrichPlatformIds adds the platform id based on cnquery ids
// - AWS EC2 instance ARN
func enrichPlatformIds(ids []string) []string {
	platformIds := []string{}
	for i := range ids {
		platformIds = append(platformIds, ids[i])

		// handle AWS EC2 instance platform identifier and generate AWS ARN as additional identifier
		// EC2 arns have the following format arn:aws:ec2:<REGION>:<ACCOUNT_ID>:instance/<instance-id>
		// //platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/12345678910/regions/us-east-1/instances/i-1234567890abcdef0
		if strings.HasPrefix(ids[i], "//platformid.api.mondoo.app/runtime/aws/ec2/v1") {
			ec2mrn, err := mrn.NewMRN(ids[i])
			if err != nil {
				continue
			}

			accountID, _ := ec2mrn.ResourceID("accounts")
			region, _ := ec2mrn.ResourceID("regions")
			instanceID, _ := ec2mrn.ResourceID("instances")

			if accountID != "" && region != "" && instanceID != "" {
				platformIds = append(platformIds, fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, instanceID))
			}
		}
	}
	return platformIds
}
