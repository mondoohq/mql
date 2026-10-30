// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// QEMU Guest Agent
// ---------------------------------------------------------------------------

type OsInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (c *PveConnection) GetOsInfo(node string, vmid int) (*OsInfo, error) {
	var result struct {
		Result OsInfo `json:"result"`
	}
	path := fmt.Sprintf("/nodes/%s/qemu/%d/agent/get-osinfo", node, vmid)
	if err := c.apiGet(path, &result); err != nil {
		return nil, fmt.Errorf("failed to get OS info for VMID %d: %w", vmid, err)
	}
	return &result.Result, nil
}

type QGAExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// QGAExec runs a command via QGA and waits synchronously for the result.
// Since Proxmox 8 the command array must be sent as an HTTP array:
// command=apt&command=list&command=--upgradable (not as a JSON string).
func (c *PveConnection) QGAExec(node string, vmid int, command []string) (*QGAExecResult, error) {
	form := url.Values{}
	for _, arg := range command {
		form.Add("command", arg)
	}

	path := fmt.Sprintf("/nodes/%s/qemu/%d/agent/exec", node, vmid)
	var execResp struct {
		PID int `json:"pid"`
	}
	if err := c.apiPostForm(path, form, &execResp); err != nil {
		return nil, fmt.Errorf("failed to start QGA exec: %w", err)
	}

	// Poll until result is available (max 30 seconds)
	statusPath := fmt.Sprintf("/nodes/%s/qemu/%d/agent/exec-status?pid=%d",
		node, vmid, execResp.PID)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		var status struct {
			Exited   int    `json:"exited"`
			ExitCode int    `json:"exitcode"`
			OutData  string `json:"out-data"`
			ErrData  string `json:"err-data"`
		}
		if err := c.apiGet(statusPath, &status); err != nil {
			return nil, fmt.Errorf("failed to get QGA exec status: %w", err)
		}

		if status.Exited == 1 {
			stdout := status.OutData
			if decoded, err := base64.StdEncoding.DecodeString(stdout); err == nil {
				stdout = string(decoded)
			}
			stderr := status.ErrData
			if decoded, err := base64.StdEncoding.DecodeString(stderr); err == nil {
				stderr = string(decoded)
			}
			return &QGAExecResult{
				Stdout:   stdout,
				Stderr:   stderr,
				ExitCode: status.ExitCode,
			}, nil
		}
	}

	return nil, fmt.Errorf("QGA exec timeout for VMID %d", vmid)
}

// ---------------------------------------------------------------------------
// Update queries via QEMU Guest Agent
// ---------------------------------------------------------------------------

type UpdateInfo struct {
	Name             string
	InstalledVersion string
	NewVersion       string
	Upgradable       bool
	Severity         string // "security", "enhancement"
}

// GetUpdates queries installed packages and update status via QGA.
func (c *PveConnection) GetUpdates(node string, vmid int, osInfo *OsInfo) ([]UpdateInfo, error) {
	osID := strings.ToLower(osInfo.ID)
	osName := strings.ToLower(osInfo.Name)

	switch {
	case strings.Contains(osID, "ubuntu") || strings.Contains(osID, "debian"):
		return c.getAptUpdates(node, vmid)
	case strings.Contains(osID, "rhel") || strings.Contains(osID, "centos") ||
		strings.Contains(osID, "almalinux") || strings.Contains(osID, "rocky") ||
		strings.Contains(osID, "fedora"):
		return c.getDnfUpdates(node, vmid)
	case strings.Contains(osName, "windows") || strings.Contains(osID, "windows"):
		return c.getWindowsUpdates(node, vmid)
	default:
		return []UpdateInfo{}, nil
	}
}

func (c *PveConnection) getAptUpdates(node string, vmid int) ([]UpdateInfo, error) {
	// `apt list --upgradable` is the only apt mode that reports pending
	// upgrades; `--installed` lists every installed package with no upgrade
	// annotation, so it can never surface an actual update.
	result, err := c.QGAExec(node, vmid, []string{"sh", "-c", "apt list --upgradable 2>/dev/null"})
	if err != nil {
		if errors.Is(err, ErrQGANotRunning) {
			return []UpdateInfo{}, nil
		}
		return nil, fmt.Errorf("apt list --upgradable failed: %w", err)
	}
	return ParseAptOutput(result.Stdout), nil
}

func (c *PveConnection) getDnfUpdates(node string, vmid int) ([]UpdateInfo, error) {
	// `dnf check-update` exits 100 when updates are available, but
	// QGAExec carries the exit code on the result struct rather than
	// returning a Go error — so any non-nil err is a real failure.
	result, err := c.QGAExec(node, vmid, []string{"dnf", "check-update", "--quiet"})
	if err != nil {
		if errors.Is(err, ErrQGANotRunning) {
			return []UpdateInfo{}, nil
		}
		return nil, fmt.Errorf("dnf check-update failed: %w", err)
	}
	return ParseDnfOutput(result.Stdout), nil
}

func (c *PveConnection) getWindowsUpdates(node string, vmid int) ([]UpdateInfo, error) {
	cmd := `Get-HotFix | Select-Object HotFixID,Description | ConvertTo-Json -Compress`
	result, err := c.QGAExec(node, vmid, []string{"powershell", "-NonInteractive", "-Command", cmd})
	if err != nil {
		if errors.Is(err, ErrQGANotRunning) {
			return []UpdateInfo{}, nil
		}
		return nil, fmt.Errorf("PowerShell Get-HotFix failed: %w", err)
	}
	return ParseWindowsHotfixes(result.Stdout), nil
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// ParseWindowsHotfixes parses the JSON output of Get-HotFix | ConvertTo-Json.
func ParseWindowsHotfixes(raw string) []UpdateInfo {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []UpdateInfo{}
	}

	if !strings.HasPrefix(raw, "[") {
		raw = "[" + raw + "]"
	}

	var hotfixes []struct {
		HotFixID    string `json:"HotFixID"`
		Description string `json:"Description"`
	}
	if err := json.Unmarshal([]byte(raw), &hotfixes); err != nil {
		return []UpdateInfo{}
	}

	updates := make([]UpdateInfo, 0, len(hotfixes))
	for _, hf := range hotfixes {
		if hf.HotFixID == "" {
			continue
		}
		severity := "enhancement"
		if strings.EqualFold(hf.Description, "Security Update") {
			severity = "security"
		}
		updates = append(updates, UpdateInfo{
			Name:             hf.HotFixID,
			InstalledVersion: hf.Description,
			Upgradable:       false,
			Severity:         severity,
		})
	}
	return updates
}

// ParseAptOutput parses "apt list --upgradable 2>/dev/null". Each line has the
// shape `pkg/repo,repo new-version arch [upgradable from: installed-version]`,
// so every reported package is a pending upgrade — the version column is the
// candidate (new) version and the bracket carries the currently-installed one.
func ParseAptOutput(raw string) []UpdateInfo {
	var updates []UpdateInfo
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		// Only "... [upgradable from: X]" lines are real upgrades; this also
		// skips the "Listing..." header and any stray output.
		const marker = "upgradable from: "
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		repoField := parts[0]
		pkgName, _, _ := strings.Cut(repoField, "/")
		newVersion := parts[1]
		installedVersion := strings.Trim(line[idx+len(marker):], "]")

		severity := "enhancement"
		if strings.Contains(repoField, "security") {
			severity = "security"
		}

		updates = append(updates, UpdateInfo{
			Name:             pkgName,
			InstalledVersion: installedVersion,
			NewVersion:       newVersion,
			Upgradable:       true,
			Severity:         severity,
		})
	}
	return updates
}

// ParseDnfOutput parses "dnf check-update --quiet".
func ParseDnfOutput(raw string) []UpdateInfo {
	var updates []UpdateInfo
	obsoleting := false
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Obsoleting") {
			obsoleting = true
			continue
		}
		if obsoleting {
			// Skip all lines in the "Obsoleting Packages" section;
			// a blank line ends the section.
			if line == "" {
				obsoleting = false
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "Last") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.Contains(parts[0], ".") {
			severity := "enhancement"
			if len(parts) >= 3 && strings.Contains(parts[2], "security") {
				severity = "security"
			}
			updates = append(updates, UpdateInfo{
				Name:       parts[0],
				NewVersion: parts[1],
				Upgradable: true,
				Severity:   severity,
			})
		}
	}
	return updates
}
