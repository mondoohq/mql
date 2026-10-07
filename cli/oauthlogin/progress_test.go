// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes of a login.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// lineContaining returns the raw output line (up to its newline) that holds s.
func lineContaining(t *testing.T, out, s string) string {
	t.Helper()
	i := strings.Index(out, s)
	require.GreaterOrEqual(t, i, 0, "output should contain %q:\n%q", s, out)
	start := strings.LastIndex(out[:i], "\n") + 1
	end := strings.Index(out[i:], "\n")
	require.GreaterOrEqual(t, end, 0, "line with %q should end with a newline:\n%q", s, out)
	return out[start : i+end]
}

func TestProgress_NotInteractive(t *testing.T) {
	var out bytes.Buffer
	p := newProgress(&out, false)
	p.Println("Open %s in a browser and enter the code.", "https://example.com/activate")
	stop := p.Spin("Waiting for authorization...")
	p.Println("a line while waiting")
	stop()
	p.AfterEnter("ignored after the wait")

	assert.Equal(t, "Open https://example.com/activate in a browser and enter the code.\n"+
		"Waiting for authorization...\n"+
		"a line while waiting\n", out.String())
	assert.NotContains(t, out.String(), "\r")
	assert.NotContains(t, out.String(), "\033")
}

func TestProgress_SpinnerNeverOverwritesPrompt(t *testing.T) {
	var out syncBuffer
	p := newProgress(&out, true)
	p.Println("Press Enter to open %s in your browser...", "https://example.com/activate")
	stop := p.Spin("Waiting for authorization...")
	time.Sleep(3 * spinnerInterval)
	p.AfterEnter("✓ Opened %s", "https://example.com/activate")
	time.Sleep(2 * spinnerInterval)
	stop()
	p.AfterEnter("ignored after the wait")
	got := out.String()

	assert.True(t, strings.HasPrefix(got, "Press Enter to open https://example.com/activate in your browser...\n"), got)
	prompt := lineContaining(t, got, "Press Enter")
	assert.NotContains(t, prompt, "\r", "nothing may be drawn over the prompt")

	// the spinner is drawn below the prompt; the Enter line replaces the
	// spinner line and the spinner moves below it
	assert.Contains(t, got, "\n\r⠋ Waiting for authorization...\033[K")
	assert.Contains(t, got, "\r✓ Opened https://example.com/activate\033[K\n\r")
	assert.NotContains(t, got, "\033[A", "the cursor never moves up into the prompt")
	// the spinner clears its own line when it stops
	assert.True(t, strings.HasSuffix(got, "\r\033[K"), "%q", got)
	assert.NotContains(t, got, "ignored")
}

func TestDeviceFlow_Interactive(t *testing.T) {
	f := newFakeAS(t)
	f.devicePollReplies = []string{"authorization_pending"}
	opts := testOptions(f, ModeDevice)
	out := &syncBuffer{}
	opts.Out = out
	opts.Interactive = true
	opts.Getenv = func(k string) string {
		if k == "DISPLAY" {
			return ":0"
		}
		return ""
	}
	inR, inW := io.Pipe()
	t.Cleanup(func() { inW.Close() })
	opts.In = inR
	opened := make(chan string, 1)
	opts.OpenBrowser = func(u string) error { opened <- u; return nil }
	go func() { _, _ = inW.Write([]byte("\n")) }()

	_, err := Login(context.Background(), opts)
	require.NoError(t, err)

	select {
	case u := <-opened:
		assert.Equal(t, "https://console.example.com/activate", u)
	default:
		t.Fatal("Enter should open the browser")
	}
	got := out.String()
	prompt := lineContaining(t, got, "Press Enter to open https://console.example.com/activate in your browser...")
	assert.NotContains(t, prompt, "\r", "nothing may be drawn over the prompt")
	assert.Contains(t, got, "✓ Opened https://console.example.com/activate")
	assert.Contains(t, got, "Waiting for authorization...")
	assert.True(t, strings.HasSuffix(got, "\r\033[K"), "the spinner clears its line: %q", got)
}
