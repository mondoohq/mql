// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEventHandlers_BashOnBoot(t *testing.T) {
	cfg := `!
event-handler BACKUP-ON-BOOT
   trigger on-boot
   action bash /mnt/flash/backup.sh --full
   delay 0
   timeout 30
   asynchronous
!
event-handler LINK-LOG
   trigger on-intf Ethernet1 operstatus
   action log
!
`
	handlers := ParseEventHandlers(cfg)
	require.Len(t, handlers, 2)

	h := handlers[0]
	assert.Equal(t, "BACKUP-ON-BOOT", h.Name)
	assert.Equal(t, "on-boot", h.Trigger)
	assert.Empty(t, h.TriggerDetail)
	assert.Equal(t, "bash", h.ActionType)
	// The command text is the whole question, so it survives in full.
	assert.Equal(t, "/mnt/flash/backup.sh --full", h.Action)
	assert.Equal(t, 0, h.Delay)
	assert.Equal(t, 30, h.Timeout)
	assert.True(t, h.Asynchronous)

	l := handlers[1]
	assert.Equal(t, "on-intf", l.Trigger)
	assert.Equal(t, "Ethernet1 operstatus", l.TriggerDetail)
	assert.Equal(t, "log", l.ActionType)
	assert.False(t, l.Asynchronous)
}

func TestParseEventHandlers_None(t *testing.T) {
	assert.Empty(t, ParseEventHandlers("interface Ethernet1\n   description X\n"))
}

func TestParseEventHandlers_NoActionConfigured(t *testing.T) {
	// A handler with a trigger and no action does nothing, which is worth
	// reporting rather than dropping.
	cfg := `event-handler EMPTY
   trigger on-boot
`
	handlers := ParseEventHandlers(cfg)
	require.Len(t, handlers, 1)
	assert.Equal(t, "on-boot", handlers[0].Trigger)
	assert.Empty(t, handlers[0].ActionType)
}

func TestParseScheduledTasks(t *testing.T) {
	cfg := `!
schedule tech-support interval 60 max-log-files 100 command show tech-support
schedule nightly interval 1440 max-log-files 10 timeout 30 command bash /mnt/flash/job.sh --quiet
!
`
	tasks := ParseScheduledTasks(cfg)
	require.Len(t, tasks, 2)

	assert.Equal(t, "tech-support", tasks[0].Name)
	assert.Equal(t, 60, tasks[0].Interval)
	assert.Equal(t, 100, tasks[0].MaxLogFiles)
	assert.Equal(t, "show tech-support", tasks[0].Command)

	// The command runs to the end of the line, arguments included.
	assert.Equal(t, "nightly", tasks[1].Name)
	assert.Equal(t, 1440, tasks[1].Interval)
	assert.Equal(t, 30, tasks[1].Timeout)
	assert.Equal(t, "bash /mnt/flash/job.sh --quiet", tasks[1].Command)
}

func TestParseScheduledTasks_IgnoresIndentedLines(t *testing.T) {
	// `schedule` also appears as a sub-command elsewhere; only top-level
	// lines are scheduled tasks.
	cfg := `qos map
   schedule something else
schedule real interval 5 command show version
`
	tasks := ParseScheduledTasks(cfg)
	require.Len(t, tasks, 1)
	assert.Equal(t, "real", tasks[0].Name)
}

func TestParseScheduledTasks_None(t *testing.T) {
	assert.Empty(t, ParseScheduledTasks("interface Ethernet1\n"))
}

func TestNormalizeConfigForComparison(t *testing.T) {
	// The two renderings differ only in the comment header and blank lines,
	// which is exactly what a saved device looks like.
	running := `! Command: show running-config
! device: switch (DCS-7050, EOS-4.30.1F)
!
hostname switch
!
interface Ethernet1
   description UPLINK
!
end
`
	startup := `! Command: show startup-config
! startup-config last modified at Fri Jan 10 09:00:00 2026
!
hostname switch

!
interface Ethernet1
   description UPLINK
!
end
`
	assert.Equal(t,
		NormalizeConfigForComparison(running),
		NormalizeConfigForComparison(startup))
}

func TestNormalizeConfigForComparison_DetectsRealDrift(t *testing.T) {
	running := `hostname switch
interface Ethernet1
   description NEW-UPLINK
`
	startup := `hostname switch
interface Ethernet1
   description UPLINK
`
	assert.NotEqual(t,
		NormalizeConfigForComparison(running),
		NormalizeConfigForComparison(startup))
}

func TestNormalizeConfigForComparison_Empty(t *testing.T) {
	assert.Empty(t, NormalizeConfigForComparison(""))
	assert.Empty(t, NormalizeConfigForComparison("!\n!\n\n"))
}

// TestNormalizeConfigForComparison_DoesNotHideRenderingAsymmetry pins why
// configSavedToStartup has to fetch its own plainly-rendered running-config.
//
// `show running-config all` expands every default-valued setting; `show
// startup-config` never carries them. The normalizer only strips comments,
// blank lines and trailing whitespace, so it cannot reconcile the two: a
// device saved seconds earlier still compared unequal, and the control
// reported "not saved" on every Arista device, forever.
func TestNormalizeConfigForComparison_DoesNotHideRenderingAsymmetry(t *testing.T) {
	allRendered := `! Command: show running-config all
hostname leaf1
management ssh
   idle-timeout 60
   no fips restrictions
   no shutdown
!
`
	plainRendered := `! Command: show startup-config
hostname leaf1
management ssh
   idle-timeout 60
!
`
	assert.NotEqual(t,
		NormalizeConfigForComparison(allRendered),
		NormalizeConfigForComparison(plainRendered),
		"the normalizer must not appear to reconcile two different renderings; "+
			"the fix is to fetch both sides the same way, not to strip harder")

	// Same rendering, same content: equal. This is what the control relies on.
	assert.Equal(t,
		NormalizeConfigForComparison(plainRendered),
		NormalizeConfigForComparison("! Command: show running-config\n"+
			"hostname leaf1\nmanagement ssh\n   idle-timeout 60\n!\n"))
}
