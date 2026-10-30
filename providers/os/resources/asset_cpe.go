// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/facebookincubator/nvdtools/wfn"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"strings"
)

func (a *mqlAsset) cpes() ([]any, error) {
	// 1 - try to read the cpe from the file
	lf, err := CreateResource(a.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData("/etc/system-release-cpe"),
	})
	if err != nil {
		return nil, err
	}
	file := lf.(*mqlFile)
	data := file.GetContent()
	if data.Error == nil {
		// cpe:2.3:o:amazon:amazon_linux:2023 is not complete
		attr, err := wfn.Parse(strings.TrimSpace(data.Data))
		if err == nil {
			cpe, err := a.MqlRuntime.CreateSharedResource("cpe", map[string]*llx.RawData{
				"uri": llx.StringData(attr.BindToFmtString()),
			})
			if err != nil {
				return nil, err
			}
			return []any{cpe}, nil
		}
	}

	conn, ok := a.MqlRuntime.Connection.(shared.Connection)

	// 2 - SUSE declares its CPE in os-release (CPE_NAME="cpe:/o:suse:sles:15:sp7",
	// "cpe:/o:opensuse:leap:15.6"). The platform version alone cannot rebuild it:
	// SLES 15.7 is 15:sp7, and Leap has no entry in the platform table.
	if ok && conn.Asset() != nil && usesOsReleaseCPE(conn.Asset().Platform) {
		uri, err := a.osReleaseCPE()
		if err != nil {
			return nil, err
		}
		if uri != "" {
			cpe, err := a.MqlRuntime.CreateSharedResource("cpe", map[string]*llx.RawData{
				"uri": llx.StringData(uri),
			})
			if err != nil {
				return nil, err
			}
			return []any{cpe}, nil
		}
	}

	// 3 - use platform and version to generate the cpe
	if ok && conn.Asset() != nil && conn.Asset().Platform != nil {
		// on windows, we need to determine if we are on a workstation
		workstation := false
		if conn.Asset().Platform.Labels["windows.mondoo.com/product-type"] == "1" {
			workstation = true
		}

		cpe, ok := cpe.PlatformCPE(conn.Asset().Platform.Name, conn.Asset().Platform.Version, workstation)
		if ok {
			cpe, err := a.MqlRuntime.CreateSharedResource("cpe", map[string]*llx.RawData{
				"uri": llx.StringData(cpe),
			})
			if err != nil {
				return nil, err
			}
			return []any{cpe}, nil
		}
	}

	return nil, nil
}

// osReleaseCPE returns the CPE_NAME of the first os-release file that exists,
// bound to CPE 2.3, or "" when there is none. Per os-release(5) the first file
// found is the only one read: /usr/lib/os-release is a fallback for a missing
// /etc/os-release, not for one without CPE_NAME.
func (a *mqlAsset) osReleaseCPE() (string, error) {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		f, err := CreateResource(a.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return "", err
		}
		content := f.(*mqlFile).GetContent()
		if content.Error != nil {
			continue
		}
		return osReleaseCPEName(content.Data), nil
	}
	return "", nil
}

// osReleaseCPEName binds the CPE_NAME of os-release content to CPE 2.3, or
// returns "" when it has none.
func osReleaseCPEName(content string) string {
	osRelease, err := detector.ParseOsRelease(content)
	if err != nil {
		return ""
	}
	uri, ok := cpe.OsReleaseCPE(osRelease["CPE_NAME"])
	if !ok {
		return ""
	}
	return uri
}

// usesOsReleaseCPE reports whether the asset's CPE comes from os-release
// CPE_NAME. The SUSE family and ALT Linux do; ALT has neither
// /etc/system-release-cpe nor a platform table entry, and declares
// CPE_NAME="cpe:/o:alt:container:11". Every other platform keeps
// /etc/system-release-cpe and the platform table.
func usesOsReleaseCPE(pf *inventory.Platform) bool {
	return pf != nil && (pf.IsFamily("suse") || pf.Name == "altlinux")
}
