// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defender_threats_win2016.json and defender_threat_detections_win2016.json are
// the real output of Get-MpThreat and Get-MpThreatDetection on a Windows Server
// 2016 host after the EICAR antivirus test file was written to disk and
// Defender remediated it. Until this capture, both resources had only ever been
// exercised against hand-written fixtures.
//
// Sanitized: the host name and the two detection GUIDs are replaced with
// synthetic values. Every other field is verbatim, including the CIM metadata
// wrappers being dropped as in the status and preference captures.

func TestParseMpThreatsLive(t *testing.T) {
	data, err := os.ReadFile("testdata/defender_threats_win2016.json")
	require.NoError(t, err)

	threats, err := ParseMpThreats(data)
	require.NoError(t, err)
	require.Len(t, threats, 1)

	th := threats[0]
	assert.Equal(t, int64(2147519003), th.ThreatID)
	assert.Equal(t, "Virus:DOS/EICAR_Test_File", th.ThreatName)
	assert.Equal(t, int64(5), th.SeverityID)
	assert.Equal(t, int64(42), th.CategoryID)
	assert.Equal(t, int64(1), th.RollupStatus)
	assert.False(t, th.IsActive)
	assert.False(t, th.DidThreatExecute)

	// Get-MpThreat leaves Resources null even for a threat it has just
	// remediated. The affected files are reported by Get-MpThreatDetection
	// instead, so an empty list here is the real answer and not a decode
	// failure.
	assert.Empty(t, th.Resources)
}

func TestParseMpThreatDetectionsLive(t *testing.T) {
	data, err := os.ReadFile("testdata/defender_threat_detections_win2016.json")
	require.NoError(t, err)

	dets, err := ParseMpThreatDetections(data)
	require.NoError(t, err)
	require.Len(t, dets, 2)

	// One threat produces several detections, one per detection source. They
	// share a ThreatID and are distinguished only by DetectionID, which is what
	// the resource keys on.
	assert.Equal(t, dets[0].ThreatID, dets[1].ThreatID)
	assert.NotEqual(t, dets[0].DetectionID, dets[1].DetectionID)

	d := dets[0]
	assert.Equal(t, "{00000000-0000-0000-0000-000000000001}", d.DetectionID)
	assert.Equal(t, int64(2147519003), d.ThreatID)
	assert.Equal(t, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, d.ProcessName)
	assert.Equal(t, `WIN-EXAMPLE-HOST\Administrator`, d.DomainUser)
	assert.Equal(t, int64(3), d.DetectionSourceTypeID)
	assert.Equal(t, int64(1), d.CurrentThreatExecutionStatusID)
	assert.Equal(t, int64(3), d.ThreatStatusID)
	assert.Equal(t, int64(2), d.CleaningActionID)
	assert.True(t, d.ActionSuccess)
	require.Len(t, d.Resources, 1)
	assert.Equal(t, `file:_C:\mqlvalidation\eicar-probe.txt`, d.Resources[0])

	// All three timestamps arrive in the PowerShell 5.1 "/Date(ms)/" form.
	for name, raw := range map[string]string{
		"initial detection": d.InitialDetectionTime,
		"status change":     d.LastThreatStatusChangeTime,
		"remediation":       d.RemediationTime,
	} {
		ts := DefenderTime(raw)
		require.NotNil(t, ts, name)
		assert.False(t, ts.IsZero(), name)
	}

	// A detection Defender attributes to no process reports "Unknown" rather
	// than an empty string.
	assert.Equal(t, "Unknown", dets[1].ProcessName)
	assert.Equal(t, `NT AUTHORITY\LOCAL SERVICE`, dets[1].DomainUser)
}
