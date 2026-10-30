// Copyright (c) Nihad Abbasov
// SPDX-License-Identifier: BSD-2-Clause
//
// Code taken from: https://github.com/NARKOZ/go-nyancat

package shell

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pierrec/lz4/v4"
)

// nyanyaState holds the animation state
type nyanyaState struct {
	frames       [][]string
	currentFrame int
	loopCount    int
	maxLoops     int
}

// nyanyaTickMsg is sent when it's time to advance the frame
type nyanyaTickMsg time.Time

// nyanyaColors maps characters to 256-color codes
var nyanyaColors = map[string]string{
	"'": "0",   // outline
	".": "15",  // white
	",": "234", // bg
	">": "198", // lightred (rainbow 1)
	"&": "211", // lightorange (rainbow 2)
	"+": "222", // lightyellow (rainbow 3)
	"#": "86",  // lightgreen (rainbow 4)
	"=": "45",  // lightblue (rainbow 5)
	";": "32",  // lightpurple (rainbow 6)
	"@": "224", // outer body
	"$": "217", // inner body
	"-": "204", // dots on the cat
	"%": "210", // cheeks
	"*": "248", // grey
}

// initNyanya initializes the nyanya animation state
func initNyanya() *nyanyaState {
	cdec, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return nil
	}

	reader := lz4.NewReader(bytes.NewReader(cdec))
	all := make([]byte, 50000)
	if _, err := reader.Read(all); err != nil && err != io.EOF {
		return nil
	}

	framesRaw := strings.Split(string(all), "z")
	frames := make([][]string, len(framesRaw))
	for i := range framesRaw {
		frames[i] = strings.Split(framesRaw[i], "\n")
	}

	return &nyanyaState{
		frames:   frames,
		maxLoops: 3,
	}
}

// nyanyaTick returns a command that ticks the animation
func nyanyaTick() tea.Cmd {
	return tea.Tick(90*time.Millisecond, func(t time.Time) tea.Msg {
		return nyanyaTickMsg(t)
	})
}

// renderNyanya renders the current frame centered on screen
func renderNyanya(state *nyanyaState, width, height int) string {
	if state == nil || len(state.frames) == 0 {
		return ""
	}

	frame := state.frames[state.currentFrame]

	// Build the frame with colors, filtering empty lines
	var frameLines []string
	for _, line := range frame {
		if len(line) == 0 {
			continue // Skip empty lines
		}
		var lineBuilder strings.Builder
		for _, char := range line {
			colorCode := nyanyaColors[string(char)]
			if colorCode == "" {
				colorCode = "234" // default bg
			}
			// Use ANSI 256-color background
			fmt.Fprintf(&lineBuilder, "\033[48;5;%sm  \033[0m", colorCode)
		}
		frameLines = append(frameLines, lineBuilder.String())
	}

	frameHeight := len(frameLines)
	frameWidth := 0
	if frameHeight > 0 && len(frame) > 0 {
		// Find the first non-empty line to calculate width
		for _, line := range frame {
			if len(line) > 0 {
				frameWidth = len(line) * 2 // Each char becomes 2 spaces wide
				break
			}
		}
	}

	// Add instruction at bottom
	instruction := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Render("Press any key to exit")

	// Calculate vertical positioning
	topPadding := max((height-frameHeight-2)/2, 0)

	// Center each frame line horizontally
	leftPadding := max((width-frameWidth)/2, 0)
	padding := strings.Repeat(" ", leftPadding)

	var result strings.Builder

	// Add top padding (empty lines)
	for range topPadding {
		result.WriteString("\n")
	}

	// Add frame lines (no extra newline after the last one)
	for i, line := range frameLines {
		result.WriteString(padding + line)
		if i < len(frameLines)-1 {
			result.WriteString("\n")
		}
	}

	// Add spacing before instruction
	result.WriteString("\n\n")

	// Add centered instruction
	instructionPadding := max((width-lipgloss.Width(instruction))/2, 0)
	result.WriteString(strings.Repeat(" ", instructionPadding) + instruction)

	return result.String()
}

const c = "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"
