// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"go.mondoo.com/mql/llx"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// windowsProcessBinariesScript prints one object per executable that a
// running process was started from: its path, the ids of the processes, the
// file's version resource, and the Windows directory.
//
// The version resource is read with Get-Item from the file, not from the
// process: Get-Process reads it through a handle to the process, which a
// protected process refuses even to an administrator. A process whose Path
// is empty (System, Idle, and without elevation every process of another
// user) is skipped, since there is no file to report.
//
// The output is UTF-8: in the console's code page a version resource's
// "Microsoft® Windows®" reads as "Microsoftr Windowsr".
const windowsProcessBinariesScript = `[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Get-Process | Where-Object { $_.Path } | Group-Object -Property Path | ForEach-Object {
  $v = (Get-Item -LiteralPath $_.Name -Force).VersionInfo
  [pscustomobject]@{
    Path = $_.Name
    Ids = @($_.Group | ForEach-Object { $_.Id })
    ProductName = $v.ProductName
    ProductVersion = $v.ProductVersion
    FileVersion = $v.FileVersion
    CompanyName = $v.CompanyName
    FileDescription = $v.FileDescription
    SystemRoot = $env:SystemRoot
  }
} | ConvertTo-Json -Depth 3`

type windowsProcessBinary struct {
	Path            string  `json:"Path"`
	Ids             pidList `json:"Ids"`
	ProductName     string  `json:"ProductName"`
	ProductVersion  string  `json:"ProductVersion"`
	FileVersion     string  `json:"FileVersion"`
	CompanyName     string  `json:"CompanyName"`
	FileDescription string  `json:"FileDescription"`
	SystemRoot      string  `json:"SystemRoot"`
}

// pidList decodes a JSON array of process ids, or a lone id: PowerShell
// unrolls a one-element array on some paths through the pipeline.
type pidList []int64

func (l *pidList) UnmarshalJSON(data []byte) error {
	var one int64
	if err := json.Unmarshal(data, &one); err == nil {
		*l = pidList{one}
		return nil
	}
	var many []int64
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

// listWindows reads the running executables with the Win32 API when the
// scan runs on the Windows host itself (nativeWindows), and with PowerShell
// otherwise, as over WinRM or SSH.
func listWindows(conn shared.Connection) ([]Binary, error) {
	if nativeWindows(conn) {
		if bins, ok := nativeListWindows(); ok {
			return bins, nil
		}
	}
	cmd, err := runCommand(conn, powershell.Encode(windowsProcessBinariesScript))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not list process executables")
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	return parseWindowsProcessBinaries(data)
}

func parseWindowsProcessBinaries(data []byte) ([]Binary, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return []Binary{}, nil
	}
	entries, err := powershell.UnmarshalList[windowsProcessBinary](data)
	if err != nil {
		return nil, llx.MalformedData(errors.New("could not read the process list: " + err.Error()))
	}

	res := make([]Binary, 0, len(entries))
	for _, e := range entries {
		if e.Path == "" {
			continue
		}
		pids := slices.Clone([]int64(e.Ids))
		slices.Sort(pids)
		b := Binary{
			Path:   e.Path,
			Pids:   pids,
			System: underWindowsDir(e.Path, e.SystemRoot),
		}
		if e.ProductName != "" || e.ProductVersion != "" || e.FileVersion != "" || e.CompanyName != "" || e.FileDescription != "" {
			b.VersionInfo = &PEVersionInfo{
				ProductName:     strings.TrimSpace(e.ProductName),
				ProductVersion:  strings.TrimSpace(e.ProductVersion),
				FileVersion:     strings.TrimSpace(e.FileVersion),
				CompanyName:     strings.TrimSpace(e.CompanyName),
				FileDescription: strings.TrimSpace(e.FileDescription),
			}
		}
		res = append(res, b)
	}
	return res, nil
}

// underWindowsDir reports whether path is inside the Windows directory.
func underWindowsDir(path, systemRoot string) bool {
	if systemRoot == "" {
		return false
	}
	return windowsPathWithin(path, systemRoot)
}

// windowsPathWithin reports whether path is dir or inside it, comparing the
// way Windows file systems do: case-insensitively, with either separator,
// on whole path components.
func windowsPathWithin(path, dir string) bool {
	p := normalizeWindowsPath(path)
	d := strings.TrimRight(normalizeWindowsPath(dir), `\`)
	if d == "" {
		return false
	}
	return p == d || strings.HasPrefix(p, d+`\`)
}

func normalizeWindowsPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"`)
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.TrimPrefix(p, `\\?\`)
	return strings.ToLower(p)
}

// nativeWindows reports whether the running binaries are read with the
// Win32 API rather than PowerShell: on a local scan of the Windows host,
// unless MONDOO_WINDOWS_NATIVE turns it off. Unlike the resources that
// predate the native implementations, this one does not wait for the
// WindowsNative feature: it was verified against PowerShell on the native
// path from the start.
func nativeWindows(conn shared.Connection) bool {
	if conn == nil || conn.Type() != shared.Type_Local || runtime.GOOS != "windows" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(shared.WindowsNativeEnv))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}
