// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"strings"
)

// EventHandler is a configured reaction to a device event.
//
//	event-handler BACKUP-ON-BOOT
//	   trigger on-boot
//	   action bash /mnt/flash/backup.sh
//	   delay 0
//	   timeout 30
//	   asynchronous
//
// An event-handler whose action is `bash` runs an arbitrary shell command on
// the switch whenever its trigger fires. That makes it the closest thing EOS
// has to a cron backdoor: an `on-boot` trigger with a bash action re-executes
// on every reboot and survives most remediation. The action text is exposed
// in full, because what the command does is the whole question.
type EventHandler struct {
	Name string
	// Trigger is the event class the handler fires on, such as "on-boot",
	// "on-startup-config", "on-intf", "on-counters", or "on-logging".
	Trigger string
	// TriggerDetail is the remainder of the trigger line, for example the
	// interface and condition on an `on-intf` trigger.
	TriggerDetail string
	// ActionType is the kind of action, typically "bash" for a shell
	// command or "log" for a log message.
	ActionType string
	// Action is the action text as configured. For a bash action this is
	// the command line that runs on the switch.
	Action string
	// Delay is the wait before the action runs, in seconds (0 = unset).
	Delay int
	// Timeout bounds how long the action may run, in seconds (0 = unset).
	Timeout int
	// Asynchronous lets the action run without blocking the event.
	Asynchronous bool
}

// ScheduledTask is a recurring command the device runs on its own.
//
//	schedule tech-support interval 60 max-log-files 100 command show tech-support
//	schedule nightly interval 1440 max-log-files 10 command bash /mnt/flash/job.sh
//
// Like an event-handler, a schedule whose command is `bash` executes a shell
// command on the switch, on a timer, with no operator present.
type ScheduledTask struct {
	Name string
	// Interval is the run interval in minutes (0 = unset).
	Interval int
	// MaxLogFiles caps the retained output files (0 = unset).
	MaxLogFiles int
	// Timeout bounds how long the command may run, in minutes (0 = unset).
	Timeout int
	// Command is the command line the schedule runs.
	Command string
}

// ParseEventHandlers extracts the configured event-handlers.
func ParseEventHandlers(runningConfig string) []EventHandler {
	res := []EventHandler{}

	EachTopLevelBlock(runningConfig, func(header, body string) {
		name, ok := strings.CutPrefix(header, "event-handler ")
		if !ok {
			return
		}

		h := EventHandler{Name: strings.TrimSpace(name)}
		scanner := bufio.NewScanner(strings.NewReader(body))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			switch {
			case line == "":

			case strings.HasPrefix(line, "trigger "):
				rest := strings.TrimPrefix(line, "trigger ")
				trigger, detail, _ := strings.Cut(rest, " ")
				h.Trigger = trigger
				h.TriggerDetail = strings.TrimSpace(detail)

			case strings.HasPrefix(line, "action "):
				rest := strings.TrimPrefix(line, "action ")
				actionType, action, _ := strings.Cut(rest, " ")
				h.ActionType = actionType
				h.Action = strings.TrimSpace(action)

			case strings.HasPrefix(line, "delay "):
				h.Delay = atoiOrZero(strings.TrimPrefix(line, "delay "))

			case strings.HasPrefix(line, "timeout "):
				h.Timeout = atoiOrZero(strings.TrimPrefix(line, "timeout "))

			case line == "asynchronous":
				h.Asynchronous = true
			}
		}
		res = append(res, h)
	})

	return res
}

// ParseScheduledTasks extracts the configured `schedule` entries. They are
// rendered as flat top-level lines rather than blocks.
func ParseScheduledTasks(runningConfig string) []ScheduledTask {
	res := []ScheduledTask{}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		raw := scanner.Text()
		if CountLeadingSpace(raw) > 0 {
			continue
		}
		rest, ok := strings.CutPrefix(strings.TrimSpace(raw), "schedule ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}

		task := ScheduledTask{Name: fields[0]}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "command":
				// The command runs to the end of the line, so everything
				// after the keyword belongs to it.
				task.Command = strings.Join(fields[i+1:], " ")
				i = len(fields)
			case "interval":
				if i+1 < len(fields) {
					task.Interval = atoiOrZero(fields[i+1])
					i++
				}
			case "max-log-files":
				if i+1 < len(fields) {
					task.MaxLogFiles = atoiOrZero(fields[i+1])
					i++
				}
			case "timeout":
				if i+1 < len(fields) {
					task.Timeout = atoiOrZero(fields[i+1])
					i++
				}
			}
		}
		res = append(res, task)
	}

	return res
}

// NormalizeConfigForComparison strips the parts of a rendered configuration
// that differ between two renderings of the same content: comment lines, which
// carry the command and timestamp headers EOS prepends, blank lines, and
// trailing whitespace.
//
// Running-config and startup-config come from the same renderer, so once those
// are removed a saved device compares equal and an unsaved one does not.
func NormalizeConfigForComparison(config string) string {
	var out strings.Builder

	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "!") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}

	return out.String()
}
