// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// windowsMemoryScript reads the memory snapshot in one round trip.
// TotalVisibleMemorySize is in KiB; the three perf counters are in bytes.
// Raw counters, not the formatted class, so the values are the exact byte
// counts Task Manager shows as Available and Committed.
const windowsMemoryScript = `$ErrorActionPreference = 'Stop'
$os = Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize
$pm = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Memory -Property AvailableBytes,CommittedBytes,CommitLimit
[PSCustomObject]@{
  TotalVisibleMemorySize = $os.TotalVisibleMemorySize
  AvailableBytes = $pm.AvailableBytes
  CommittedBytes = $pm.CommittedBytes
  CommitLimit = $pm.CommitLimit
} | ConvertTo-Json -Compress`

// memoryInfo holds one snapshot, in bytes. A nil pointer is a value the
// target did not report, which the fields surface as null rather than 0.
type memoryInfo struct {
	Total       *int64
	Available   *int64
	Committed   *int64
	CommitLimit *int64
}

type mqlMemoryInternal struct {
	once     sync.Once
	info     *memoryInfo
	fetchErr error
}

func (m *mqlMemory) id() (string, error) {
	return "memory", nil
}

// fetch reads the snapshot once, so every field comes from the same moment
// and the target runs one command however many fields a query reads.
func (m *mqlMemory) fetch() (*memoryInfo, error) {
	m.once.Do(func() {
		conn := m.MqlRuntime.Connection.(shared.Connection)
		m.info, m.fetchErr = readMemoryInfo(conn)
	})
	return m.info, m.fetchErr
}

func readMemoryInfo(conn shared.Connection) (*memoryInfo, error) {
	// Memory usage is a property of a running system. An image, a snapshot or
	// a mounted disk has none, whatever platform it holds.
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, llx.NotApplicable(errors.New("memory requires a running system; this asset cannot run commands"))
	}

	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, errors.New("memory: platform is unknown")
	}
	pf := asset.Platform
	if !pf.IsFamily("windows") {
		// Not classified: the target has memory, this provider does not read it yet.
		return nil, fmt.Errorf("memory is not yet supported on %s", pf.Name)
	}

	cmd, err := conn.RunCommand(powershell.Encode(windowsMemoryScript))
	if err != nil {
		return nil, err
	}
	stdout, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("failed to read memory counters (exit %d): %s", cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}
	return parseWindowsMemory(stdout)
}

// windowsMemoryRecord is the JSON the script emits. Pointers keep a missing
// or null counter distinguishable from a zero one.
type windowsMemoryRecord struct {
	TotalVisibleMemorySize *int64 `json:"TotalVisibleMemorySize"`
	AvailableBytes         *int64 `json:"AvailableBytes"`
	CommittedBytes         *int64 `json:"CommittedBytes"`
	CommitLimit            *int64 `json:"CommitLimit"`
}

func parseWindowsMemory(data []byte) (*memoryInfo, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("memory: the memory script returned no output")
	}
	var rec windowsMemoryRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("memory: failed to parse memory counters: %w", err)
	}

	info := &memoryInfo{
		Available:   rec.AvailableBytes,
		Committed:   rec.CommittedBytes,
		CommitLimit: rec.CommitLimit,
	}
	if rec.TotalVisibleMemorySize != nil {
		total := *rec.TotalVisibleMemorySize * 1024
		info.Total = &total
	}
	return info, nil
}

// memoryField resolves one value of the snapshot, marking the field null when
// the target did not report it.
func (m *mqlMemory) memoryField(field *plugin.TValue[int64], pick func(*memoryInfo) *int64) (int64, error) {
	info, err := m.fetch()
	if err != nil {
		return 0, err
	}
	v := pick(info)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *v, nil
}

func (m *mqlMemory) total() (int64, error) {
	return m.memoryField(&m.Total, func(i *memoryInfo) *int64 { return i.Total })
}

func (m *mqlMemory) available() (int64, error) {
	return m.memoryField(&m.Available, func(i *memoryInfo) *int64 { return i.Available })
}

func (m *mqlMemory) committed() (int64, error) {
	return m.memoryField(&m.Committed, func(i *memoryInfo) *int64 { return i.Committed })
}

func (m *mqlMemory) commitLimit() (int64, error) {
	return m.memoryField(&m.CommitLimit, func(i *memoryInfo) *int64 { return i.CommitLimit })
}
