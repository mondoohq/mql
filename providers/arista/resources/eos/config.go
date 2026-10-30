// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"io"
	"strings"
)

func CountLeadingSpace(line string) int {
	i := 0
	for _, runeValue := range line {
		if runeValue != ' ' {
			break
		}
		i++
	}
	return i
}

func ParseConfig(in io.Reader) map[string]any {
	stack := []map[string]any{}
	keyStack := []string{}

	scanner := bufio.NewScanner(in)

	// add root to stack
	stack = append(stack, map[string]any{})
	keyStack = append(keyStack, "root")

	lastDepth := 0
	lastKey := ""
	for scanner.Scan() {
		line := scanner.Text()
		key := strings.TrimSpace(line)

		if strings.HasPrefix(key, "!") || key == "end" {
			continue
		}

		indent := CountLeadingSpace(line)
		level := 0
		if indent > 0 {
			level = indent / 3
		}
		// An ascent only ever pushes one stack entry, so a line that is
		// indented more than one level deeper than the previous line (e.g. an
		// indented banner or comment block that isn't real config nesting)
		// would later be popped by more than was pushed, underflowing the
		// stack. Clamp to one level deeper to keep the stack balanced.
		if level > lastDepth+1 {
			level = lastDepth + 1
		}

		if level > lastDepth {
			// add level to stack
			entry := map[string]any{}
			stack = append(stack, entry)
			keyStack = append(keyStack, lastKey)
		}

		if level < lastDepth {
			stackKey := keyStack[lastDepth]

			// store stack with proper parent key
			stack[level][stackKey] = stack[level+1]

			levelDiff := lastDepth - level

			// delete old entry from stack
			stack = stack[:len(stack)-levelDiff]
			keyStack = keyStack[:len(keyStack)-levelDiff]
		}

		lastDepth = level
		lastKey = key

		// TODO: only temporary until we can check for key existence in MQL
		stack[level][key] = true
	}

	return stack[0]
}

// EachTopLevelBlock invokes fn once per top-level configuration block,
// passing the unindented header line and the indented body beneath it.
// Standalone top-level lines are reported with an empty body.
//
// This is the counterpart to GetSection for callers that do not know the
// section headers in advance, such as the ACL parser, which has to discover
// every `ip access-list <name>` block on the device.
func EachTopLevelBlock(runningConfig string, fn func(header, body string)) {
	scanner := bufio.NewScanner(strings.NewReader(runningConfig))

	header := ""
	var body strings.Builder
	flush := func() {
		if header != "" {
			fn(header, body.String())
		}
		header = ""
		body.Reset()
	}

	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") || line == "end" {
			continue
		}

		if CountLeadingSpace(raw) == 0 {
			flush()
			header = line
			continue
		}
		if header != "" {
			body.WriteString(line)
			body.WriteByte('\n')
		}
	}
	flush()
}

func GetSection(in io.Reader, section string) string {
	keyStack := []string{}
	keyStack = append(keyStack, "")

	scanner := bufio.NewScanner(in)

	lastDepth := 0
	lastKey := ""
	var recorded strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		key := strings.TrimSpace(line)

		if strings.HasPrefix(key, "!") || key == "end" {
			continue
		}

		indent := CountLeadingSpace(line)
		level := 0
		if indent > 0 {
			level = indent / 3
		}
		// An ascent only ever pushes one key, so clamp a multi-level indent
		// jump (e.g. an indented banner line) to one level deeper. Without
		// this a later dedent pops more than was pushed and slices keyStack
		// to a negative length, panicking the whole query.
		if level > lastDepth+1 {
			level = lastDepth + 1
		}

		if level > lastDepth {
			// add level to stack
			keyStack = append(keyStack, lastKey)
		}

		if level < lastDepth {
			levelDiff := lastDepth - level

			// delete old entry from stack
			keyStack = keyStack[:len(keyStack)-levelDiff]
		}

		lastDepth = level
		lastKey = key

		if strings.Join(keyStack, " ") == " "+section {
			recorded.WriteString(key)
			recorded.WriteByte('\n')
		}
	}

	return recorded.String()
}
