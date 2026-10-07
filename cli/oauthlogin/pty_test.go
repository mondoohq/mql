// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin || linux

package oauthlogin

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// newTestTerminal opens a pseudo-terminal set up like an interactive shell's:
// line input with echo, and ICRNL as given. A real terminal sends "\r" for
// Enter; only ICRNL turns it into "\n".
func newTestTerminal(t *testing.T, icrnl bool) (ptmx, tty *os.File, orig unix.Termios) {
	t.Helper()
	ptmx, tty, err := openPty()
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { ptmx.Close(); tty.Close() })

	fd := int(tty.Fd())
	tio, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	require.NoError(t, err)
	tio.Lflag |= unix.ICANON | unix.ECHO | unix.ISIG
	if icrnl {
		tio.Iflag |= unix.ICRNL
	} else {
		tio.Iflag &^= unix.ICRNL
	}
	require.NoError(t, unix.IoctlSetTermios(fd, ioctlWriteTermios, tio))
	got, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	require.NoError(t, err)
	return ptmx, tty, *got
}

func termiosOf(t *testing.T, f *os.File) unix.Termios {
	t.Helper()
	tio, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	require.NoError(t, err)
	return *tio
}

func TestWaitForEnter_Terminal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		icrnl bool
		key   string
	}{
		{"CR with ICRNL", true, "\r"},
		{"CR without ICRNL", false, "\r"},
		{"LF", true, "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ptmx, tty, orig := newTestTerminal(t, tc.icrnl)

			restore := terminalKeyInput(tty)
			require.NotNil(t, restore, "a terminal switches to key input")
			keys := termiosOf(t, tty)
			assert.Zero(t, keys.Lflag&unix.ECHO, "echo is off while waiting")
			assert.Zero(t, keys.Lflag&unix.ICANON, "keys are read one by one")
			assert.NotZero(t, keys.Lflag&unix.ISIG, "Ctrl-C still interrupts")
			assert.Equal(t, orig.Iflag, keys.Iflag, "input translation is left alone")

			pressed := make(chan struct{})
			go waitForEnter(tty, func() { close(pressed) })
			_, err := ptmx.Write([]byte("x" + tc.key))
			require.NoError(t, err)
			select {
			case <-pressed:
			case <-time.After(5 * time.Second):
				t.Fatalf("Enter (%q) was not detected", tc.key)
			}

			restore()
			assert.Equal(t, orig, termiosOf(t, tty), "the terminal settings are restored exactly")
		})
	}
}

func TestDeviceFlow_TerminalEnter(t *testing.T) {
	ptmx, tty, orig := newTestTerminal(t, true)

	f := newFakeAS(t)
	f.devicePollReplies = []string{"authorization_pending", "authorization_pending"}
	opts := testOptions(f, ModeDevice)
	out := &syncBuffer{}
	opts.Out = out
	opts.In = tty
	opts.Interactive = true
	opts.Getenv = func(k string) string {
		if k == "DISPLAY" {
			return ":0"
		}
		return ""
	}
	opened := make(chan string, 1)
	opts.OpenBrowser = func(u string) error { opened <- u; return nil }

	// press Enter, as a terminal sends it, once the login waits for it
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			tio, err := unix.IoctlGetTermios(int(tty.Fd()), ioctlReadTermios)
			if err == nil && tio.Lflag&unix.ICANON == 0 {
				_, _ = ptmx.Write([]byte("\r"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	_, err := Login(context.Background(), opts)
	require.NoError(t, err)

	select {
	case u := <-opened:
		assert.Equal(t, "https://console.example.com/activate", u)
	default:
		t.Fatal("Enter should open the browser")
	}
	assert.Contains(t, out.String(), "✓ Opened https://console.example.com/activate")
	assert.Equal(t, orig, termiosOf(t, tty), "the terminal settings are restored after the login")
}
