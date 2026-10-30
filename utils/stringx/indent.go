// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stringx

import (
	"bufio"
	"strconv"
	"strings"
)

func Indent(indent int, message string) string {
	var indentTxt strings.Builder
	for range indent {
		indentTxt.WriteString(" ")
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(message))
	for scanner.Scan() {
		sb.WriteString(indentTxt.String())
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
	}
	return sb.String()
}

func MaxLines(lines int, message string) string {
	res := strings.Split(message, "\n")
	if len(res) <= lines {
		return message
	}

	n := len(res) - lines

	return strings.Join(res[:lines], "\n") + "\n... " + strconv.Itoa(n) + " more lines ..."
}
