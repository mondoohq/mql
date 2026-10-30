// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSecurityProductState(t *testing.T) {
	code := uint32(397568)
	res := parseProductState(code)
	assert.Equal(t, uint32(1), res.Owner)     // microsoft
	assert.Equal(t, uint32(0), res.Product)   // on
	assert.Equal(t, uint32(1), res.Signature) // up to date

	code = uint32(393216)
	res = parseProductState(code)
	assert.Equal(t, uint32(0), res.Owner)     // other
	assert.Equal(t, uint32(1), res.Product)   // off
	assert.Equal(t, uint32(1), res.Signature) // up to date

	code = uint32(397584)
	res = parseProductState(code)
	assert.Equal(t, uint32(1), res.Owner)     // microsoft
	assert.Equal(t, uint32(0), res.Product)   // on
	assert.Equal(t, uint32(0), res.Signature) // ouf to date
}

func findProduct(products []securityProduct, id string, typ string) securityProduct {
	var actual securityProduct

	for i := range products {
		p := products[i]
		if p.Guid == id && p.Type == typ {
			actual = p
			break
		}
	}
	return actual
}

func mustParse(value string) time.Time {
	t, err := time.Parse(time.RFC1123, value)
	if err != nil {
		panic(err)
	}
	return t
}

func TestSecurityProductsPowershell(t *testing.T) {
	// default windows 10
	r, err := os.Open("./testdata/security_products_antivirus.json")
	require.NoError(t, err)

	products, err := ParseWindowsSecurityProducts(r)
	require.NoError(t, err)
	assert.True(t, len(products) == 1)

	assert.Equal(t, "Windows Defender", products[0].Name)
	assert.Equal(t, int64(397568), products[0].State)
	assert.Equal(t, "UP-TO-DATE", products[0].SignatureStatus)
	assert.Equal(t, "ON", products[0].ProductStatus)

	// parse more products
	r, err = os.Open("./testdata/security_products_antispyware.json")
	require.NoError(t, err)

	products, err = ParseWindowsSecurityProducts(r)
	require.NoError(t, err)
	assert.True(t, len(products) == 6)

	assert.Equal(t, securityProduct{
		Type:               "antivirus",
		Guid:               "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}",
		Name:               "Windows Defender",
		SignedProductExe:   "windowsdefender://",
		SignedReportingExe: "%ProgramFiles%\\Windows Defender\\MsMpeng.exe",
		State:              393472,
		ProductStatus:      "OFF",
		SignatureStatus:    "UP-TO-DATE",
		Timestamp:          mustParse("Sun, 14 Nov 2021 12:09:12 GMT"),
	}, findProduct(products, "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}", "antivirus"))

	assert.Equal(t, securityProduct{
		Type:               "antivirus",
		Guid:               "{F6EF0F75-4CCD-059F-B5E3-F43DFF8ECEEF}",
		Name:               "Sophos Intercept X",
		SignedProductExe:   "C:\\Program Files\\Sophos\\Endpoint Defense\\SEDcli.exe",
		SignedReportingExe: "C:\\Program Files\\Sophos\\Endpoint Defense\\SEDService.exe",
		State:              266240,
		ProductStatus:      "ON",
		SignatureStatus:    "UP-TO-DATE",
		Timestamp:          mustParse("Fri, 22 Apr 2022 07:56:39 GMT"),
	}, findProduct(products, "{F6EF0F75-4CCD-059F-B5E3-F43DFF8ECEEF}", "antivirus"))

	assert.Equal(t, securityProduct{
		Type:               "antivirus",
		Guid:               "{8E0623B8-CF1C-DFFE-CEA3-AA41BDA4B8EE}",
		Name:               "Sophos Anti-Virus",
		SignedProductExe:   "C:\\Program Files (x86)\\Sophos\\Sophos Anti-Virus\\WSCClient.exe",
		SignedReportingExe: "C:\\Program Files (x86)\\Sophos\\Sophos Anti-Virus\\WSCClient.exe",
		State:              331776,
		ProductStatus:      "ON",
		SignatureStatus:    "UP-TO-DATE",
		Timestamp:          mustParse("Tue, 02 Nov 2021 15:42:21 GMT"),
	}, findProduct(products, "{8E0623B8-CF1C-DFFE-CEA3-AA41BDA4B8EE}", "antivirus"))

	assert.Equal(t, securityProduct{
		Type:               "firewall",
		Guid:               "{CED48E50-06A2-04C7-9EBC-5D08015D8994}",
		Name:               "Sophos Intercept X",
		SignedProductExe:   "C:\\Program Files\\Sophos\\Endpoint Defense\\SEDcli.exe",
		SignedReportingExe: "C:\\Program Files\\Sophos\\Endpoint Defense\\SEDService.exe",
		State:              266240,
		ProductStatus:      "ON",
		SignatureStatus:    "UP-TO-DATE",
		Timestamp:          mustParse("Fri, 22 Apr 2022 07:56:39 GMT"),
	}, findProduct(products, "{CED48E50-06A2-04C7-9EBC-5D08015D8994}", "firewall"))

	assert.Equal(t, securityProduct{
		Type:               "antispyware",
		Guid:               "{577C8ED3-C22B-48D4-E5E0-298D0463E6CD}",
		Name:               "ESET Security",
		SignedProductExe:   "C:\\Program Files\\ESET\\ESET Security\\ecmds.exe",
		SignedReportingExe: "C:\\Program Files\\ESET\\ESET Security\\ekrn.exe",
		State:              266240,
		ProductStatus:      "ON",
		SignatureStatus:    "UP-TO-DATE",
		Timestamp:          mustParse("Fri, 13 Sep 2019 08:03:30 GMT"),
	}, findProduct(products, "{577C8ED3-C22B-48D4-E5E0-298D0463E6CD}", "antispyware"))

	assert.Equal(t, securityProduct{
		Type:               "antispyware",
		Guid:               "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}",
		Name:               "Windows Defender",
		SignedProductExe:   "windowsdefender://",
		SignedReportingExe: "%ProgramFiles%\\Windows Defender\\MsMpeng.exe",
		State:              393472,
		ProductStatus:      "OFF",
		SignatureStatus:    "UP-TO-DATE",
		Timestamp:          mustParse("Fri, 05 Apr 2019 16:26:27 GMT"),
	}, findProduct(products, "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}", "antispyware"))
}

// A real SecurityCenter2 reading from Windows Server 2016 (10.0.14393), 2019
// (10.0.17763) and 2022 (10.0.20348), all of which produced identical output.
//
// Windows Server has no Security Center: the root/SecurityCenter2 namespace
// does not exist, so every class query fails and the script emits three empty
// arrays. The parse has to produce an empty list without inventing a product,
// and the caller has to understand that this list means "nothing was
// enumerable here", not "no antivirus is installed".
func TestParseWindowsSecurityProducts_None(t *testing.T) {
	f, err := os.Open("./testdata/security_products_none.json")
	require.NoError(t, err)
	defer f.Close()

	products, err := ParseWindowsSecurityProducts(f)
	require.NoError(t, err)
	assert.Empty(t, products)
}
