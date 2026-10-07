// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"strings"
	"time"
)

// Cat frames from Mondoo's catspin (Apache-2.0).
//
// Every frame in a set has the same rows and columns, so cycling through them
// never shifts the layout around the cat.

// catSet is one animated cat: the frames to cycle and the still shown when
// motion is reduced or scripts do not run.
type catSet struct {
	frames [][]string
	still  []string
}

// catInterval is how long each frame of a browser cat is shown.
const catInterval = 180 * time.Millisecond

// catLove is the success cat: sparkle eyes and a swishing tail.
var catLove = catSet{
	frames: [][]string{
		{" /\\_/\\  ", "( *v* )/", " > ^ <  "},
		{" /\\_/\\  ", "( *v* )~", " > ^ <  "},
		{" /\\_/\\  ", "( *.* )\\", " > ^ <  "},
		{" /\\_/\\  ", "( *.* )~", " > ^ <  "},
	},
	still: []string{" /\\_/\\  ", "( *v* ) ", " > ^ <  "},
}

// catCry is the failure cat. Its still is a crying face rather than the set's
// smiling rest frame, which would contradict the page.
var catCry = catSet{
	frames: [][]string{
		{" /\\_/\\  ", "( T.T )/", " > ^ <  "},
		{" /\\_/\\  ", "( T.T )~", " > ^ <  "},
		{" /\\_/\\  ", "( ;.; )\\", " > ^ <  "},
		{" /\\_/\\  ", "( ;.; )~", " > ^ <  "},
	},
	still: []string{" /\\_/\\  ", "( T.T ) ", " > ^ <  "},
}

// inlineCatFrames is the one-row terminal spinner; every frame is 6 columns.
var inlineCatFrames = []string{"=^.^=/", "=^.^=~", "=^.^=\\", "=^-^=~"}

// inlineCatInterval is how long each frame of the terminal spinner is shown.
const inlineCatInterval = 140 * time.Millisecond

// joinedFrames returns each frame as one newline-separated string.
func (c catSet) joinedFrames() []string {
	out := make([]string, len(c.frames))
	for i, f := range c.frames {
		out[i] = strings.Join(f, "\n")
	}
	return out
}

// joinedStill returns the still as one newline-separated string.
func (c catSet) joinedStill() string {
	return strings.Join(c.still, "\n")
}
