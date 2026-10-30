// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package generator

import (
	"encoding/json"
	"os"

	"go.mondoo.com/mql/cli/reporter"
	"sigs.k8s.io/yaml"
)

// Structures to parse the data from cnquery report
type BomAsset struct {
	Name          string            `json:"name,omitempty"`
	Platform      string            `json:"platform,omitempty"`
	Version       string            `json:"version,omitempty"`
	Build         string            `json:"build,omitempty"`
	Family        []string          `json:"family,omitempty"`
	Arch          string            `json:"arch,omitempty"`
	CPEs          []string          `json:"cpes.map,omitempty"`
	IDs           []string          `json:"ids,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	PlatformTitle string            `json:"platformTitle,omitempty"`
}

type BomPackage struct {
	Name    string   `json:"name,omitempty"`
	Version string   `json:"version,omitempty"`
	Origin  string   `json:"origin,omitempty"`
	Arch    string   `json:"arch,omitempty"`
	Format  string   `json:"format,omitempty"`
	Purl    string   `json:"purl,omitempty"`
	CPEs    []string `json:"cpes.map,omitempty"`
	// License as the package's own manifest or metadata declared it, e.g. npm
	// package.json `license` or a Python distribution's METADATA. Empty when
	// the query did not select it, or when the package declared none -- the
	// two are indistinguishable here, which is why an empty value records no
	// license entry rather than an unknown one.
	License string `json:"license,omitempty"`
	// used by python packages
	// deprecated: remove once python.packages uses files
	FilePath string `json:"file.path,omitempty"`
	// used by os packages
	FilePaths []string `json:"files.map,omitempty"`
	// used by running binaries, the executable's path
	Path string `json:"path,omitempty"`
	// used by running binaries, the vendor the binary names, if any
	Vendor string `json:"vendor,omitempty"`
	// used by running binaries, the hex SHA-256 digest of the executable
	Sha256 string `json:"sha256,omitempty"`
	// used by running binaries, the evidence the version was read from
	// (goBuildInfo, peVersionInfo, bundleInfo, versionString, installMetadata)
	VersionSource string `json:"versionSource,omitempty"`
	// used by running binaries, the status of the code signature (macOS and
	// Windows), empty where executables carry none
	SignatureStatus string `json:"signatureStatus,omitempty"`
	// used by running binaries, the organizations and the common name in the
	// subject of the certificate that signed the executable
	SignerOrganization []string `json:"signer.subject.organization,omitempty"`
	SignerCommonName   string   `json:"signer.subject.commonName,omitempty"`
}

type KernelInstalled struct {
	Name    string
	Running bool
	Version string
}

type BomFields struct {
	Asset                 *BomAsset         `json:"asset,omitempty"`
	Packages              []BomPackage      `json:"packages.list,omitempty"`
	PythonPackages        []BomPackage      `json:"python.packages,omitempty"`
	NpmPackages           []BomPackage      `json:"npm.packages.list,omitempty"`
	GoPackages            []BomPackage      `json:"go.packages.list,omitempty"`
	JavaPackages          []BomPackage      `json:"java.packages.list,omitempty"`
	RustPackages          []BomPackage      `json:"rust.packages.list,omitempty"`
	DotnetPackages        []BomPackage      `json:"dotnet.packages.list,omitempty"`
	PhpPackages           []BomPackage      `json:"php.packages.list,omitempty"`
	GithubActionsPackages []BomPackage      `json:"githubactions.packages.list,omitempty"`
	SwiftPackages         []BomPackage      `json:"swift.packages.list,omitempty"`
	TerraformPackages     []BomPackage      `json:"terraform.packages.list,omitempty"`
	JenkinsPackages       []BomPackage      `json:"jenkins.packages.list,omitempty"`
	WordpressPackages     []BomPackage      `json:"wordpress.packages.list,omitempty"`
	RubyPackages          []BomPackage      `json:"ruby.packages.list,omitempty"`
	DartPackages          []BomPackage      `json:"dart.packages.list,omitempty"`
	HaskellPackages       []BomPackage      `json:"haskell.packages.list,omitempty"`
	ElixirPackages        []BomPackage      `json:"elixir.packages.list,omitempty"`
	ErlangPackages        []BomPackage      `json:"erlang.packages.list,omitempty"`
	PrologPackages        []BomPackage      `json:"prolog.packages.list,omitempty"`
	JuliaPackages         []BomPackage      `json:"julia.packages.list,omitempty"`
	CondaPackages         []BomPackage      `json:"conda.packages.list,omitempty"`
	RPackages             []BomPackage      `json:"r.packages.list,omitempty"`
	LuaPackages           []BomPackage      `json:"lua.packages.list,omitempty"`
	KernelInstalled       []KernelInstalled `json:"kernel.installed,omitempty"`
	// PrinterDrivers are read from the Windows print spooler rather than from
	// installed software: a driver delivered as an INF/CAB package lands in the
	// driver store and creates no Add/Remove Programs entry, so a software
	// inventory cannot see it while the spooler is still loading it.
	//
	// The key is the compiled datapoint label for a list resource, which is
	// "<resource>.list" -- the same shape as packages.list and
	// npm.packages.list.
	PrinterDrivers []BomPackage `json:"windows.printerDrivers.list,omitempty"`
	// RunningBinaries are the executables of running processes that no
	// installed package owns. The query filters the list with where(), which
	// is why the compiled label is "runningBinaries.where.list".
	RunningBinaries []BomPackage `json:"runningBinaries.where.list,omitempty"`
}

func (b *BomFields) ToJSON() ([]byte, error) {
	return json.Marshal(b)
}

func LoadReport(filename string) (*reporter.Report, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var report *reporter.Report
	err = yaml.Unmarshal(data, &report)
	if err != nil {
		return nil, err
	}
	return report, nil
}
