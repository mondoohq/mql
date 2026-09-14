// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cpe

import (
	"bytes"
	"regexp"
	"strconv"
	"text/template"

	"go.mondoo.com/mql/utils/stringx"
)

// amznLegacyVersion matches the Amazon Linux 1 version scheme.
var amznLegacyVersion = regexp.MustCompile(`^(2017|2018)\.`)

type platformCPEEntry struct {
	Platform    string
	CPEBuilder  func(platform, version string, workstation bool) (string, error)
	Workstation bool
}

var platformCPES = []platformCPEEntry{
	// apple macos
	{
		Platform: "macos",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			// mql uses 10.14 instead of 10.14.0, so we need to add the .0
			v := version + ".0"
			return cpeVersionPatternFunc(
				"cpe:2.3:o:apple:mac_os_x:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: v,
				})
		},
	},
	// amazon linux
	{
		Platform: "amazonlinux",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			product := ""

			if amznLegacyVersion.MatchString(version) {
				product = "linux"
			} else if version == "2" {
				product = "linux_2"
			} else if version == "2023" {
				product = "linux_2023"
			}

			return cpeVersionPatternFunc(
				"cpe:2.3:o:amazon:{{.Product}}:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Product: product,
					Version: "-",
				})
		},
	},
	// centos
	{
		Platform: "centos",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:centos:centos:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// centos stream
	//
	// Stream is its own platform for advisory purposes but not for CPE: its
	// os-release declares CPE_NAME="cpe:/o:centos:centos:9", and NVD has no
	// centos_stream product to point at, so it keeps the centos:centos name the
	// distribution gives itself.
	{
		Platform: "centos-stream",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:centos:centos:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// debian
	{
		Platform: "debian",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:debian:debian_linux:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// fedora
	{
		Platform: "fedora",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:fedora:linux:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// oracle linux
	{
		Platform: "oraclelinux",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:oracle:linux:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// redhat linux
	{
		Platform: "redhat",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:redhat:redhat_enterprise_linux:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// rockylinux
	{
		Platform: "rockylinux",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:rocky:rocky_linux:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// alma linux
	{
		Platform: "almalinux",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:almalinux:almalinux:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// suse
	{
		Platform: "sles",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:suse:suse_linux_enterprise_server:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// ubuntu
	{
		Platform: "ubuntu",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			lts := []string{"14.04", "16.04", "18.04", "20.04", "22.04", "24.04"}
			swEdition := "*"
			isLts := stringx.Contains(lts, version)
			if isLts {
				swEdition = "lts"
			}
			return cpeVersionPatternFunc(
				"cpe:2.3:o:canonical:ubuntu_linux:{{.Version}}:*:*:*:{{.SwEdition}}:*:*:*",
				cpePatternArgs{
					Version:   version,
					SwEdition: swEdition,
				})
		},
	},
	// windows
	{
		Platform: "windows",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			product := "windows"
			productVersion := ""

			v, err := strconv.Atoi(version)
			if err != nil {
				return "", err
			}

			if v >= 10000 && v < 20000 && workstation {
				productVersion = "10"
			} else if v >= 20000 && v < 30000 && workstation {
				productVersion = "11"
			} else if v == 14393 {
				product = "windows_server_2016"
				productVersion = "-"
			} else if v == 17763 {
				// see https://nvd.nist.gov/products/cpe/detail/0A406A68-C024-45BC-88F7-2EDC1A54F7C7
				product = "windows_server_2019"
				productVersion = "-"
			} else if v == 20348 {
				product = "windows_server_2022"
				productVersion = "-"
			} else {
				return "", nil
			}

			return cpeVersionPatternFunc(
				"cpe:2.3:o:microsoft:{{.Product}}:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Product: product,
					Version: productVersion,
				})
		},
	},
	// aix
	{
		Platform: "aix",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:ibm:aix:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
	// alpine
	{
		// see https://nvd.nist.gov/products/cpe/detail/B7A89734-EC97-4D04-9CF0-1E93C09F79D4
		Platform: "alpine",
		CPEBuilder: func(platform, version string, workstation bool) (string, error) {
			return cpeVersionPatternFunc(
				"cpe:2.3:o:alpinelinux:alpine_linux:{{.Version}}:*:*:*:*:*:*:*",
				cpePatternArgs{
					Version: version,
				})
		},
	},
}

type cpePatternArgs struct {
	Product   string
	Version   string
	SwEdition string
}

func cpeVersionPatternFunc(pattern string, args cpePatternArgs) (string, error) {
	t := template.Must(template.New("cpe-template").Parse(pattern))
	buf := bytes.Buffer{}
	err := t.Execute(&buf, args)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func PlatformCPE(platform string, version string, workstation bool) (string, bool) {
	for i := range platformCPES {
		entry := platformCPES[i]
		if entry.Platform == platform && entry.CPEBuilder != nil {
			cpe, err := entry.CPEBuilder(platform, version, workstation)
			if err != nil {
				return "", false
			}
			return cpe, true
		}
	}

	return "", false
}
