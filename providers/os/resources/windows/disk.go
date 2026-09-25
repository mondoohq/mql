// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
)

// PSGetDisks lists every disk Windows Storage Management knows about, the same
// MSFT_Disk records Get-Disk returns. The enumerations are left as their
// numeric codes and mapped to names in Go (BusTypeName and friends), where the
// mapping is tested and an unknown code can be reported instead of dropped.
//
// -InputObject with an array keeps the output a JSON array for zero and one
// disk, where piping into ConvertTo-Json would emit nothing or a bare object.
// ErrorActionPreference Stop makes a failed query exit non-zero, so a host
// whose storage provider cannot be read reports an error instead of no disks.
const PSGetDisks = `$ErrorActionPreference = 'Stop'
$d = @(Get-CimInstance -Namespace 'root\Microsoft\Windows\Storage' -ClassName MSFT_Disk | Select-Object Number,FriendlyName,SerialNumber,UniqueId,Size,BusType,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly,OperationalStatus,HealthStatus)
ConvertTo-Json -InputObject $d -Depth 3 -Compress
`

// Disk is one MSFT_Disk record. Pointers keep a property Windows left unset
// apart from its zero value: a disk with no reported boot flag is not a disk
// known not to be the boot disk.
type Disk struct {
	Number            *int64       `json:"Number"`
	FriendlyName      *string      `json:"FriendlyName"`
	SerialNumber      *string      `json:"SerialNumber"`
	UniqueId          *string      `json:"UniqueId"`
	Size              *int64       `json:"Size"`
	BusType           *int64       `json:"BusType"`
	PartitionStyle    *int64       `json:"PartitionStyle"`
	IsBoot            *bool        `json:"IsBoot"`
	IsSystem          *bool        `json:"IsSystem"`
	IsOffline         *bool        `json:"IsOffline"`
	IsReadOnly        *bool        `json:"IsReadOnly"`
	OperationalStatus PSInt64Array `json:"OperationalStatus"`
	HealthStatus      *int64       `json:"HealthStatus"`
}

// ErrNoDiskOutput is returned by ParseDisks when the disk query printed nothing.
var ErrNoDiskOutput = errors.New("windows disk query returned no output")

// ParseDisks decodes the output of PSGetDisks.
//
// Empty output is an error, not an empty list. The script always prints a
// JSON array, even for a host with no disks, so empty output means the script
// never ran (a command line over the transport's cap is rejected before
// PowerShell starts, with a clean exit) and "no disks" would be a wrong answer.
func ParseDisks(r io.Reader) ([]Disk, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, ErrNoDiskOutput
	}
	list, err := psUnwrapList(data)
	if err != nil {
		return nil, err
	}
	if list == nil {
		return []Disk{}, nil
	}
	var disks []Disk
	if err := json.Unmarshal(list, &disks); err != nil {
		return nil, err
	}
	// MSFT_Disk enumerates in no particular order (a live Server 2022 host
	// lists disk 2 first). Ordering by disk number keeps the list stable
	// between scans; a record without a number sorts last.
	sort.SliceStable(disks, func(i, j int) bool {
		a, b := disks[i].Number, disks[j].Number
		if a == nil || b == nil {
			return a != nil && b == nil
		}
		return *a < *b
	})
	return disks, nil
}

// Enumeration names from the MSFT_Disk class documentation:
// https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-disk
var (
	diskBusTypes = map[int64]string{
		0:  "Unknown",
		1:  "SCSI",
		2:  "ATAPI",
		3:  "ATA",
		4:  "1394",
		5:  "SSA",
		6:  "Fibre Channel",
		7:  "USB",
		8:  "RAID",
		9:  "iSCSI",
		10: "SAS",
		11: "SATA",
		12: "SD",
		13: "MMC",
		14: "Virtual",
		15: "File Backed Virtual",
		16: "Storage Spaces",
		17: "NVMe",
	}

	// Code 0 is documented as Unknown. It is what an uninitialized disk
	// reports, and Get-Disk and Initialize-Disk both call that state RAW.
	diskPartitionStyles = map[int64]string{
		0: "RAW",
		1: "MBR",
		2: "GPT",
	}

	diskOperationalStatuses = map[int64]string{
		0:      "Unknown",
		1:      "Other",
		2:      "OK",
		3:      "Degraded",
		4:      "Stressed",
		5:      "Predictive Failure",
		6:      "Error",
		7:      "Non-Recoverable Error",
		8:      "Starting",
		9:      "Stopping",
		10:     "Stopped",
		11:     "In Service",
		12:     "No Contact",
		13:     "Lost Communication",
		14:     "Aborted",
		15:     "Dormant",
		16:     "Supporting Entity in Error",
		17:     "Completed",
		0xD010: "Online",
		0xD011: "Not Ready",
		0xD012: "No Media",
		0xD013: "Offline",
		0xD014: "Failed",
	}

	diskHealthStatuses = map[int64]string{
		0: "Healthy",
		1: "Warning",
		2: "Unhealthy",
	}
)

// enumName names a code, falling back to the decimal code for a value the
// table does not know. The sets are not closed (newer Windows releases add bus
// types), and a code is more useful to a policy author than an empty string.
func enumName(names map[int64]string, code *int64) *string {
	if code == nil {
		return nil
	}
	if name, ok := names[*code]; ok {
		return &name
	}
	s := strconv.FormatInt(*code, 10)
	return &s
}

// BusTypeName returns the bus type name, or nil when Windows reported none.
func (d Disk) BusTypeName() *string { return enumName(diskBusTypes, d.BusType) }

// PartitionStyleName returns GPT, MBR, or RAW, or nil when Windows reported none.
func (d Disk) PartitionStyleName() *string { return enumName(diskPartitionStyles, d.PartitionStyle) }

// HealthStatusName returns the health status name, or nil when Windows reported none.
func (d Disk) HealthStatusName() *string { return enumName(diskHealthStatuses, d.HealthStatus) }

// OperationalStatusNames returns one name per reported status. It is nil when
// the property was absent and empty when Windows reported an empty list.
func (d Disk) OperationalStatusNames() []string {
	if d.OperationalStatus == nil {
		return nil
	}
	out := make([]string, 0, len(d.OperationalStatus))
	for i := range d.OperationalStatus {
		out = append(out, *enumName(diskOperationalStatuses, &d.OperationalStatus[i]))
	}
	return out
}

// TrimmedSerialNumber returns the serial number without the padding some
// drives report around it (ATA serials are fixed-width, space-padded fields).
func (d Disk) TrimmedSerialNumber() *string {
	if d.SerialNumber == nil {
		return nil
	}
	s := strings.TrimSpace(*d.SerialNumber)
	return &s
}
