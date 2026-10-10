// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// This implementation reads the security products from Windows Desktop Systems
// Initially we tried to use C# with DLL loading to iwscapi but that turned out to be quite complex, therefore
// we read that via Get-CimInstance -Namespace root/SecurityCenter2 -Classname AntiVirusProduct
// This retrieves the information from WMI (which does not exist on Windows Server). The Windows-internal
// firewall does not show up in that list. This is to be expected and we do not try to mimic the iwscapi
// which adds the firewall to the list. Instead, the firewall is being exposed via separate resources.
//
// References:
// https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/
// https://web.archive.org/web/20201128030749/https://social.msdn.microsoft.com/Forums/en-US/8da083a9-59bf-4e93-9f1b-209a2c5b9c72/how-to-use-wscapidll-in-c-for-getting-details-about-antivirus-softwares?forum=csharpgeneral
// https://social.msdn.microsoft.com/Forums/vstudio/en-US/8da083a9-59bf-4e93-9f1b-209a2c5b9c72/how-to-use-wscapidll-in-c-for-getting-details-about-antivirus-softwares?forum=csharpgeneral

const windowsSecurityProducts = `
$securityProducts = New-Object PSObject
Add-Member -InputObject $securityProducts -MemberType NoteProperty -Name firewall -Value @(Get-CimInstance -Namespace root/SecurityCenter2 -Classname FirewallProduct)
Add-Member -InputObject $securityProducts -MemberType NoteProperty -Name antiVirus -Value @(Get-CimInstance -Namespace root/SecurityCenter2 -Classname AntiVirusProduct)
Add-Member -InputObject $securityProducts -MemberType NoteProperty -Name antiSpyware -Value @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiSpywareProduct)
ConvertTo-Json -Depth 3 -Compress $securityProducts
`

// powershellBitlockerVolumeStatus is the struct to parse the powershell result
type powershellSecurityProducts struct {
	Firewall    []powershellSecurityProduct
	AntiVirus   []powershellSecurityProduct
	AntiSpyware []powershellSecurityProduct
}

type powershellSecurityProduct struct {
	DisplayName              string
	InstanceGUID             string
	PathToSignedProductExe   string
	PathToSignedReportingExe string
	ProductState             uint32
	Timestamp                string
}

type securityProduct struct {
	Type               string
	Guid               string
	Name               string
	SignedProductExe   string
	SignedReportingExe string
	State              int64
	ProductStatus      string
	SignatureStatus    string
	Timestamp          time.Time
}

func parseTimestamp(timestamp string) time.Time {
	var ts time.Time
	if timestamp != "" {
		// parse "Mon, 18 Apr 2022 08:05:47 GMT"
		parsedTime, err := time.Parse(time.RFC1123, timestamp)
		if err == nil {
			ts = parsedTime
		}
	}
	return ts
}

// https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/ne-iwscapi-wsc_security_product_state
var securityProductStatusValues = map[uint32]string{
	0: "ON",
	1: "OFF",
	2: "SNOOZED",
	3: "EXPIRED",
}

// https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/ne-iwscapi-wsc_security_signature_status
var securitySignatureStatusValues = map[uint32]string{
	0: "OUT-OF-DATE",
	1: "UP-TO-DATE",
}

var securityProductOwner = map[uint32]string{ //nolint:unused
	0: "NonMS",
	1: "Microsoft",
}

const (
	SignatureStatus = 0x00F0
	ProductOwner    = 0x0F00
	ProductState    = 0xF000

	// ProductState
	Off     = 0x0000
	On      = 0x1000
	Snoozed = 0x2000
	Expired = 0x3000

	// SignatureStatus
	UpToDate  = 0x00
	OutOfDate = 0x10

	// ProductOwner
	NonMs   = 0x000
	Windows = 0x100
)

type productState struct {
	Product   uint32
	Owner     uint32
	Signature uint32
}

// product state is encoded in a 4-byte, the last byte is not used
// https://web.archive.org/web/20200928123510/https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/identifying-antivirus-engine-state

func parseProductState(state uint32) productState {
	res := productState{}

	switch state & ProductState {
	case On:
		res.Product = 0
	case Off:
		res.Product = 1
	case Snoozed:
		res.Product = 2
	case Expired:
		res.Product = 3
	}

	switch state & SignatureStatus {
	case UpToDate:
		res.Signature = 1
	case OutOfDate:
		res.Signature = 0
	}

	switch state & ProductOwner {
	case NonMs:
		res.Owner = 0
	case Windows:
		res.Owner = 1
	}

	return res
}

func GetSecurityProducts(p shared.Connection) ([]securityProduct, error) {
	c, err := p.RunCommand(powershell.Encode(windowsSecurityProducts))
	if err != nil {
		return nil, err
	}

	if c.ExitStatus != 0 {
		stderr, err := io.ReadAll(c.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve security products: " + string(stderr))
	}

	return ParseWindowsSecurityProducts(c.Stdout)
}

func ParseWindowsSecurityProducts(r io.Reader) ([]securityProduct, error) {
	var psSecProducts powershellSecurityProducts
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &psSecProducts)
	if err != nil {
		return nil, err
	}

	res := []securityProduct{}
	for i := range psSecProducts.AntiVirus {
		p := psSecProducts.AntiVirus[i]

		res = append(res, securityProduct{
			Type:               "antivirus",
			Guid:               p.InstanceGUID,
			Name:               p.DisplayName,
			SignedProductExe:   p.PathToSignedProductExe,
			SignedReportingExe: p.PathToSignedReportingExe,
			State:              int64(p.ProductState),
			ProductStatus:      securityProductStatusValues[parseProductState(p.ProductState).Product],
			SignatureStatus:    securitySignatureStatusValues[parseProductState(p.ProductState).Signature],
			Timestamp:          parseTimestamp(p.Timestamp),
		})
	}

	for i := range psSecProducts.Firewall {
		p := psSecProducts.Firewall[i]

		res = append(res, securityProduct{
			Type:               "firewall",
			Guid:               p.InstanceGUID,
			Name:               p.DisplayName,
			SignedProductExe:   p.PathToSignedProductExe,
			SignedReportingExe: p.PathToSignedReportingExe,
			State:              int64(p.ProductState),
			ProductStatus:      securityProductStatusValues[parseProductState(p.ProductState).Product],
			SignatureStatus:    securitySignatureStatusValues[parseProductState(p.ProductState).Signature],
			Timestamp:          parseTimestamp(p.Timestamp),
		})
	}

	for i := range psSecProducts.AntiSpyware {
		p := psSecProducts.AntiSpyware[i]

		res = append(res, securityProduct{
			Type:               "antispyware",
			Guid:               p.InstanceGUID,
			Name:               p.DisplayName,
			SignedProductExe:   p.PathToSignedProductExe,
			SignedReportingExe: p.PathToSignedReportingExe,
			State:              int64(p.ProductState),
			ProductStatus:      securityProductStatusValues[parseProductState(p.ProductState).Product],
			SignatureStatus:    securitySignatureStatusValues[parseProductState(p.ProductState).Signature],
			Timestamp:          parseTimestamp(p.Timestamp),
		})
	}

	return res, nil
}
