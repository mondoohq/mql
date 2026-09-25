// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// VolumesScript reads every volume and every access path in one round trip.
//
// Win32_Volume carries the file system and the capacity, but only the first
// access path of each volume in Name. Win32_MountPoint is the association that
// lists all of them, drive letters and NTFS folder mounts alike, so a volume
// reachable as both D:\ and C:\mnt\data is reported at both. A volume that has
// neither (the recovery partition, an EFI system partition) has no row there
// and falls back to its volume GUID path.
//
// -ErrorAction Stop inside the try turns a CIM failure into a non-zero exit:
// without it a failed query leaves the list empty and the script reports "no
// volumes" with exit status 0.
const VolumesScript = `
try {
	$v = @(Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop | Select-Object DeviceID,Name,Label,DriveLetter,DriveType,FileSystem,Capacity,FreeSpace,BootVolume,SystemVolume,PageFilePresent,Compressed)
	$m = @(Get-CimInstance -ClassName Win32_MountPoint -ErrorAction Stop | ForEach-Object { [PSCustomObject]@{ Volume = $_.Volume.DeviceID; Directory = $_.Directory.Name } })
} catch {
	[Console]::Error.WriteLine("could not read Win32_Volume: " + $_.Exception.Message)
	exit 1
}
ConvertTo-Json -Depth 3 -Compress @{ volumes = $v; mountPoints = $m }
`

// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-volume
var volumeDriveTypes = map[int64]string{
	0: "Unknown",
	1: "NoRootDirectory",
	2: "Removable",
	3: "Fixed",
	4: "Network",
	5: "CDRom",
	6: "RAMDisk",
}

// VolumeDriveTypeName maps a Win32_Volume DriveType code to its name. A code
// outside the documented set keeps its number rather than borrowing a name.
func VolumeDriveTypeName(code int64) string {
	if name, ok := volumeDriveTypes[code]; ok {
		return name
	}
	return fmt.Sprintf("%d", code)
}

type psVolume struct {
	DeviceID        string  `json:"DeviceID"`
	Name            *string `json:"Name"`
	Label           *string `json:"Label"`
	DriveLetter     *string `json:"DriveLetter"`
	DriveType       int64   `json:"DriveType"`
	FileSystem      *string `json:"FileSystem"`
	Capacity        *int64  `json:"Capacity"`
	FreeSpace       *int64  `json:"FreeSpace"`
	BootVolume      *bool   `json:"BootVolume"`
	SystemVolume    *bool   `json:"SystemVolume"`
	PageFilePresent *bool   `json:"PageFilePresent"`
	Compressed      *bool   `json:"Compressed"`
}

type psVolumeMountPoint struct {
	Volume    *string `json:"Volume"`
	Directory *string `json:"Directory"`
}

type psVolumeList []psVolume

func (l *psVolumeList) UnmarshalJSON(data []byte) error {
	return psDecodeList(data, (*[]psVolume)(l))
}

type psVolumeMountPointList []psVolumeMountPoint

func (l *psVolumeMountPointList) UnmarshalJSON(data []byte) error {
	return psDecodeList(data, (*[]psVolumeMountPoint)(l))
}

func psDecodeList[T any](data []byte, out *[]T) error {
	list, err := psUnwrapList(data)
	if err != nil {
		return err
	}
	if list == nil {
		*out = nil
		return nil
	}
	return json.Unmarshal(list, out)
}

type psVolumes struct {
	Volumes     psVolumeList           `json:"volumes"`
	MountPoints psVolumeMountPointList `json:"mountPoints"`
}

// Volume is one Windows volume and every path it is reachable at.
type Volume struct {
	// DeviceID is the volume GUID path, \\?\Volume{...}\.
	DeviceID string
	// AccessPaths are the drive letters and folders the volume is mounted
	// at, in the form VolumePath gives them. A volume with none is reported
	// at its DeviceID.
	AccessPaths []string
	Label       string
	DriveType   string
	// FileSystem is empty when the volume carries no file system Windows
	// recognizes, which includes a removable or optical drive with no media.
	FileSystem string
	// Capacity and FreeSpace are nil when Windows reports none, which is the
	// case for a drive with no media. They are never zero-filled.
	Capacity     *int64
	FreeSpace    *int64
	BootVolume   bool
	SystemVolume bool
	PageFile     bool
	Compressed   bool
}

// GetVolumes reads the volume table of a running Windows system.
func GetVolumes(conn shared.Connection) ([]Volume, error) {
	c, err := conn.RunCommand(powershell.Encode(VolumesScript))
	if err != nil {
		return nil, err
	}
	stdout, err := io.ReadAll(c.Stdout)
	if err != nil {
		return nil, err
	}
	stderr, _ := io.ReadAll(c.Stderr)
	return VolumesResult(stdout, c.ExitStatus, stderr)
}

// VolumesResult turns a raw command result into volumes. A failed command, or
// one that printed nothing, is an error: every running Windows system has at
// least its system volume, so an empty answer means the script did not run
// (an encoded command over the cmd.exe limit exits 0 with no output), not that
// nothing is mounted.
func VolumesResult(stdout []byte, exitStatus int, stderr []byte) ([]Volume, error) {
	if exitStatus != 0 {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = fmt.Sprintf("command exited with status %d", exitStatus)
		}
		return nil, errors.New("failed to retrieve Windows volumes: " + msg)
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, errors.New("failed to retrieve Windows volumes: the collection script produced no output")
	}
	vols, err := ParseVolumes(stdout)
	if err != nil {
		return nil, err
	}
	if len(vols) == 0 {
		return nil, errors.New("failed to retrieve Windows volumes: Win32_Volume reported no volumes")
	}
	return vols, nil
}

// ParseVolumes decodes the output of VolumesScript.
func ParseVolumes(data []byte) ([]Volume, error) {
	var raw psVolumes
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, llx.MalformedData(fmt.Errorf("could not parse the Windows volume table: %w", err))
	}

	// Access paths per volume, keyed by DeviceID without regard to case.
	paths := map[string][]string{}
	for _, mp := range raw.MountPoints {
		if mp.Volume == nil || mp.Directory == nil || *mp.Directory == "" {
			continue
		}
		key := strings.ToLower(*mp.Volume)
		paths[key] = append(paths[key], VolumePath(*mp.Directory))
	}

	res := make([]Volume, 0, len(raw.Volumes))
	for _, v := range raw.Volumes {
		if v.DeviceID == "" {
			continue
		}
		accessPaths := paths[strings.ToLower(v.DeviceID)]
		// Name is the first access path. It is normally among the mount
		// points already; adding it covers a host whose association did not
		// list it.
		if v.Name != nil && !isVolumeGUIDPath(*v.Name) && *v.Name != "" {
			accessPaths = append(accessPaths, VolumePath(*v.Name))
		}
		if v.DriveLetter != nil && *v.DriveLetter != "" {
			accessPaths = append(accessPaths, VolumePath(*v.DriveLetter))
		}
		accessPaths = dedupeVolumePaths(accessPaths)
		if len(accessPaths) == 0 {
			accessPaths = []string{VolumePath(v.DeviceID)}
		}

		vol := Volume{
			DeviceID:     v.DeviceID,
			AccessPaths:  accessPaths,
			DriveType:    VolumeDriveTypeName(v.DriveType),
			BootVolume:   derefBool(v.BootVolume),
			SystemVolume: derefBool(v.SystemVolume),
			PageFile:     derefBool(v.PageFilePresent),
			Compressed:   derefBool(v.Compressed),
		}
		if v.Label != nil {
			vol.Label = *v.Label
		}
		if v.FileSystem != nil {
			vol.FileSystem = *v.FileSystem
		}
		// Windows reports no capacity for a drive without media. Zero is a
		// measurement, and an empty drive has not been measured.
		if v.Capacity != nil && vol.FileSystem != "" {
			vol.Capacity = v.Capacity
			vol.FreeSpace = v.FreeSpace
		}
		res = append(res, vol)
	}
	return res, nil
}

func derefBool(b *bool) bool {
	return b != nil && *b
}

var (
	driveLetterOnly = regexp.MustCompile(`^[A-Za-z]:$`)
	driveRoot       = regexp.MustCompile(`^[A-Za-z]:\\$`)
)

func isVolumeGUIDPath(p string) bool {
	return strings.HasPrefix(p, `\\?\`)
}

// VolumePath puts an access path into the form Windows prints it in: a drive
// root keeps its backslash (C:\, since C: alone names the current directory on
// that drive), a volume GUID path keeps its trailing backslash, and a folder
// mount has none (C:\mnt\data), the way Explorer and PowerShell print a
// directory.
func VolumePath(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	switch {
	case driveLetterOnly.MatchString(p):
		return p + `\`
	case driveRoot.MatchString(p):
		return p
	case isVolumeGUIDPath(p):
		if !strings.HasSuffix(p, `\`) {
			return p + `\`
		}
		return p
	}
	return strings.TrimRight(p, `\`)
}

// VolumePathKey is the form two access paths are compared in. Windows paths
// are case-insensitive and C:, C:\ and c:\ name the same volume, so the key
// folds case, accepts either slash, and drops trailing separators.
func VolumePathKey(p string) string {
	return strings.ToLower(strings.TrimRight(strings.ReplaceAll(p, "/", `\`), `\`))
}

func dedupeVolumePaths(paths []string) []string {
	seen := map[string]bool{}
	res := make([]string, 0, len(paths))
	for _, p := range paths {
		k := VolumePathKey(p)
		if seen[k] {
			continue
		}
		seen[k] = true
		res = append(res, p)
	}
	sort.Strings(res)
	return res
}
