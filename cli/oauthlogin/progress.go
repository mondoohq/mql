// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	spinnerInterval = 120 * time.Millisecond
	// clearLine erases from the cursor to the end of the line.
	clearLine = "\033[K"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// progress writes the login's user-facing lines. On a terminal it can show a
// spinner on its own line below them; every line goes through progress, so a
// line printed while the spinner runs is written above the spinner instead of
// over it. Off a terminal the spinner message is printed once, without any
// cursor control.
type progress struct {
	out         io.Writer
	interactive bool

	mu       sync.Mutex
	spinMsg  string // shown with the spinner while it runs
	frame    int
	spinning bool
	finished bool
	done     chan struct{}
	wg       sync.WaitGroup
}

func newProgress(out io.Writer, interactive bool) *progress {
	return &progress{out: out, interactive: interactive}
}

// Println writes a full line. While the spinner runs, the spinner line is
// replaced by the text and the spinner is redrawn on the next line.
func (p *progress) Println(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.printlnLocked(format, args...)
}

func (p *progress) printlnLocked(format string, args ...any) {
	if p.spinning {
		fmt.Fprint(p.out, "\r")
	}
	fmt.Fprintf(p.out, format, args...)
	if p.spinning {
		fmt.Fprint(p.out, clearLine)
	}
	fmt.Fprint(p.out, "\n")
	if p.spinning {
		p.drawLocked()
	}
}

// AfterEnter writes a line in response to the user pressing Enter. The device
// flow turns terminal echo off while it waits, so the cursor is still on the
// spinner line, which the text replaces. It does nothing once the spinner has
// stopped.
func (p *progress) AfterEnter(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.printlnLocked(format, args...)
}

// Spin starts the spinner with msg on its own line. The returned func stops it
// and clears the spinner line, leaving the cursor at the start of that line.
func (p *progress) Spin(msg string) func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.interactive {
		fmt.Fprintln(p.out, msg)
		return func() {
			p.mu.Lock()
			p.finished = true
			p.mu.Unlock()
		}
	}
	p.spinMsg = msg
	p.spinning = true
	p.done = make(chan struct{})
	p.drawLocked()
	p.wg.Add(1)
	go p.run(p.done)

	var once sync.Once
	return func() {
		once.Do(func() {
			close(p.done)
			p.wg.Wait()
			p.mu.Lock()
			defer p.mu.Unlock()
			p.spinning = false
			p.finished = true
			fmt.Fprint(p.out, "\r"+clearLine)
		})
	}
}

func (p *progress) run(done chan struct{}) {
	defer p.wg.Done()
	t := time.NewTicker(spinnerInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			p.mu.Lock()
			if p.spinning {
				p.frame++
				p.drawLocked()
			}
			p.mu.Unlock()
		}
	}
}

func (p *progress) drawLocked() {
	fmt.Fprintf(p.out, "\r%s %s%s", spinnerFrames[p.frame%len(spinnerFrames)], p.spinMsg, clearLine)
}
