// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"golang.org/x/text/encoding/unicode"
)

func TestParseSessionScript(t *testing.T) {
	s, ok := parseSessionScript(powershell.Encode("Get-Date"))
	require.True(t, ok)
	assert.False(t, s.file)
	text, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(s.utf16)
	require.NoError(t, err)
	assert.Equal(t, "$ProgressPreference='SilentlyContinue';Get-Date", string(text))

	for _, script := range []string{
		"exit 1",
		"if ($x) {\n  Write-Error 'no'\n  exit 1\n}",
		"[Environment]::Exit(3)",
		"$host.SetShouldExit(2)",
		"EXIT",
	} {
		s, ok := parseSessionScript(powershell.Encode(script))
		require.True(t, ok, script)
		assert.True(t, s.file, "%q may exit, so it runs from a file", script)
	}
	for _, script := range []string{"$LASTEXITCODE", "Get-Item 'HKLM:\\ExitCodes'", "$exitCode = 1", "$shouldExitCode = 1"} {
		s, ok := parseSessionScript(powershell.Encode(script))
		require.True(t, ok, script)
		assert.False(t, s.file, script)
	}

	for _, cmd := range []string{
		powershell.EncodeUnix("Get-Date"),
		powershell.Wrap("Get-Date"),
		powershell.StagedCommand(`C:\x.ps1`),
		"powershell.exe -NoProfile -EncodedCommand !!!",
		"hostname",
	} {
		_, ok := parseSessionScript(cmd)
		assert.False(t, ok, cmd)
	}
}

func TestSessionFrame(t *testing.T) {
	m := newSessionMarkers("abc", 7)
	assert.Equal(t, "<<mql-start:abc:7>>\r\n", m.start)
	assert.Equal(t, "<<mql-end:abc:7:", m.endPrefix)
	assert.Equal(t, "<<mql-err-end:abc:7>>\r\n", m.errEnd)

	frame := sessionFrame(m, "abc", sessionScript{utf16: utf16le("Get-Date")})
	assert.NotContains(t, frame, "\n", "a frame is one line")
	assert.Contains(t, frame, "Invoke-Expression")
	assert.NotContains(t, frame, "WriteAllText")

	frame = sessionFrame(m, "abc", sessionScript{utf16: utf16le("exit 3"), file: true})
	assert.NotContains(t, frame, "\n")
	assert.Contains(t, frame, "mql-abc.ps1")
	assert.Contains(t, frame, "Remove-Item")
}

func TestReadFrame(t *testing.T) {
	m := newSessionMarkers("id", 1)
	tests := []struct {
		name string
		in   string
		out  string
		code int
	}{
		{"output with a newline", "<<mql-start:id:1>>\r\nhello\r\n\r\n<<mql-end:id:1:0>>\r\n", "hello\r\n", 0},
		{"output without a newline", "<<mql-start:id:1>>\r\nnonl\r\n<<mql-end:id:1:0>>\r\n", "nonl", 0},
		{"no output", "<<mql-start:id:1>>\r\n\r\n<<mql-end:id:1:1>>\r\n", "", 1},
		{"exit code", "<<mql-start:id:1>>\r\na\r\n\r\n<<mql-end:id:1:3>>\r\n", "a\r\n", 3},
		{"stray output before the frame", "leftover\r\n<<mql-start:id:1>>\r\nx\r\n<<mql-end:id:1:0>>\r\n", "x", 0},
		{
			"markers of another command are output",
			"<<mql-start:id:1>>\r\n<<mql-end:id:2:0>>\r\n<<mql-end:other:1:0>>\r\n\r\n<<mql-end:id:1:0>>\r\n",
			"<<mql-end:id:2:0>>\r\n<<mql-end:other:1:0>>\r\n", 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, code, err := readFrame(bufio.NewReader(strings.NewReader(tc.in)), m)
			require.NoError(t, err)
			assert.Equal(t, tc.out, string(out))
			assert.Equal(t, tc.code, code)
		})
	}

	t.Run("session ends in the middle", func(t *testing.T) {
		_, _, err := readFrame(bufio.NewReader(strings.NewReader("<<mql-start:id:1>>\r\npartial")), m)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

var (
	frameStart  = regexp.MustCompile(`'<<mql-start:([0-9a-f]+:\d+)>>'`)
	frameB64    = regexp.MustCompile(`FromBase64String\('([^']*)'\)`)
	frameStaged = regexp.MustCompile(`ReadAllText\('([^']*)'`)
)

type fakeReply struct {
	stdout, stderr string
	code           int
	// die ends the session instead of answering
	die bool
}

// startFakePowershell plays a session: it reads frames from stdin and answers
// them like powershell.exe would, with the output that reply returns for the
// decoded script.
func startFakePowershell(t *testing.T, reply func(script string) fakeReply) sessionIO {
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	go func() {
		defer stdoutW.Close()
		defer stderrW.Close()
		r := bufio.NewReader(stdinR)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tag := frameStart.FindStringSubmatch(line)
			if tag == nil {
				continue // the setup line
			}
			var script string
			if staged := frameStaged.FindStringSubmatch(line); staged != nil {
				script = "staged " + staged[1]
			} else {
				raw, _ := base64.StdEncoding.DecodeString(frameB64.FindStringSubmatch(line)[1])
				text, _ := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
				script = strings.TrimSuffix(string(text), "\n$global:__mqlOk = $?")
			}
			rep := reply(script)
			if rep.die {
				stdinR.Close()
				return
			}
			fmt.Fprintf(stdoutW, "<<mql-start:%s>>\r\n%s\r\n<<mql-end:%s:%d>>\r\n", tag[1], rep.stdout, tag[1], rep.code)
			fmt.Fprintf(stderrW, "%s\r\n<<mql-err-end:%s>>\r\n", rep.stderr, tag[1])
		}
	}()
	return sessionIO{stdin: stdinW, stdout: stdoutR, stderr: stderrR}
}

func sessionConnection(t *testing.T, raw *fakeRunner, reply func(string) fakeReply) (*Connection, *int) {
	t.Setenv(persistentShellEnv, "1")
	opened := 0
	var mu sync.Mutex
	c := newFakeConnection(raw)
	c.openSession = func() (*psSession, error) {
		mu.Lock()
		opened++
		mu.Unlock()
		return newPSSession(startFakePowershell(t, reply))
	}
	return c, &opened
}

func echoScript(script string) fakeReply {
	script = strings.TrimPrefix(script, "$ProgressPreference='SilentlyContinue';")
	if script == "Write-Error x" {
		return fakeReply{stderr: "x : error", code: 1}
	}
	return fakeReply{stdout: "ran " + script + "\r\n"}
}

func TestRunCommandInSession(t *testing.T) {
	raw := &fakeRunner{shell: "%OS%\r\nDesktop\r\n"}
	c, opened := sessionConnection(t, raw, echoScript)

	for i := range 5 {
		cmd := powershell.Encode(fmt.Sprintf("Get-Date %d", i))
		res, err := c.RunCommand(cmd)
		require.NoError(t, err)
		assert.Equal(t, cmd, res.Command)
		out, _ := io.ReadAll(res.Stdout)
		assert.Equal(t, fmt.Sprintf("ran Get-Date %d\r\n", i), string(out))
		assert.Equal(t, 0, res.ExitStatus)
	}
	res, err := c.RunCommand(powershell.Encode("Write-Error x"))
	require.NoError(t, err)
	stderr, _ := io.ReadAll(res.Stderr)
	assert.Equal(t, "x : error", string(stderr))
	assert.Equal(t, 1, res.ExitStatus)

	// a staged script runs from a copy of its file
	staged := powershell.StagedCommand(`C:\Windows\Temp\users-0123456789ab.ps1`)
	res, err = c.RunCommand(staged)
	require.NoError(t, err)
	assert.Equal(t, staged, res.Command)
	out, _ := io.ReadAll(res.Stdout)
	assert.Equal(t, "ran staged C:\\Windows\\Temp\\users-0123456789ab.ps1\r\n", string(out))

	// the server's shell is Windows PowerShell, so plain commands run in the
	// session too, once the connection check has detected it
	res, err = c.RunCommand("hostname")
	require.NoError(t, err)
	out, _ = io.ReadAll(res.Stdout)
	assert.Equal(t, "ran hostname\r\n", string(out))

	assert.Equal(t, 1, *opened, "one session serves every command")
	assert.Equal(t, []string{shellProbe}, raw.sent, "no process per command")

	// a command that starts PowerShell itself runs as a process
	wrapped := powershell.Wrap("Get-Date")
	_, err = c.RunCommand(wrapped)
	require.NoError(t, err)
	assert.Equal(t, wrapped, raw.sent[len(raw.sent)-1])
}

func TestRawCommandsInSessionOnlyForPowershellShell(t *testing.T) {
	for name, probe := range map[string]string{
		"cmd.exe": "Windows_NT;$PSVersionTable.PSEdition\r\n",
		"pwsh":    "%OS%\nCore\n",
	} {
		t.Run(name, func(t *testing.T) {
			raw := &fakeRunner{shell: probe}
			c, _ := sessionConnection(t, raw, echoScript)
			_, err := c.RunCommand(powershell.Encode("Get-Date"))
			require.NoError(t, err)
			_, err = c.RunCommand("hostname")
			require.NoError(t, err)
			assert.Equal(t, "hostname", raw.sent[len(raw.sent)-1], "the server's shell runs it")
		})
	}

	t.Run("shell not detected yet", func(t *testing.T) {
		raw := &fakeRunner{shell: "%OS%\r\nDesktop\r\n"}
		c, opened := sessionConnection(t, raw, echoScript)
		_, err := c.RunCommand("hostname")
		require.NoError(t, err)
		assert.Equal(t, []string{"hostname"}, raw.sent, "a plain command never probes")
		assert.Equal(t, 0, *opened)
	})
}

func TestParseStagedScript(t *testing.T) {
	s, ok := parseStagedScript(powershell.StagedCommand(`C:\Windows\Temp\iis-0123456789ab.ps1`))
	require.True(t, ok)
	assert.Equal(t, `C:\Windows\Temp\iis-0123456789ab.ps1`, s.staged)

	for _, cmd := range []string{
		powershell.StagedCommand(""),
		powershell.StagedCommand(`C:\Program Files\x.ps1`),
		powershell.StagedCommand(`C:\it's.ps1`),
		powershell.StagedCommand(`C:\x.txt`),
		powershell.StagedCommand(`C:\x.ps1; Remove-Item C:\y`),
		powershell.Encode("Get-Date"),
		"hostname",
	} {
		_, ok := parseStagedScript(cmd)
		assert.False(t, ok, cmd)
	}
}

func TestParseRawScript(t *testing.T) {
	s, ok := parseRawScript("hostname")
	require.True(t, ok)
	assert.Equal(t, utf16le("hostname"), s.utf16)
	assert.False(t, s.file)

	s, ok = parseRawScript("cmd /c exit 3")
	require.True(t, ok)
	assert.True(t, s.file, "a command that may exit runs from a file")

	for _, cmd := range []string{"", "  ", powershell.Wrap("Get-Date"), "PowerShell.exe -c x", "pwsh -c x", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c x`} {
		_, ok := parseRawScript(cmd)
		assert.False(t, ok, cmd)
	}
}

func TestSessionFrameStaged(t *testing.T) {
	m := newSessionMarkers("abc", 7)
	frame := sessionFrame(m, "abc-7", sessionScript{staged: `C:\Windows\Temp\users-0123456789ab.ps1`})
	assert.NotContains(t, frame, "\n", "a frame is one line")
	assert.Contains(t, frame, `[IO.File]::ReadAllText('C:\Windows\Temp\users-0123456789ab.ps1', [Text.Encoding]::Default)`)
	assert.Contains(t, frame, "mql-abc-7.ps1")
	assert.Contains(t, frame, "Remove-Item -LiteralPath $__mqlFile")
	assert.NotContains(t, frame, "Invoke-Expression")
}

func TestRunCommandInSessionConcurrently(t *testing.T) {
	t.Setenv(windowsMaxCommandsEnv, "3")
	raw := &fakeRunner{shell: "%OS%\r\nDesktop\r\n"}
	c, opened := sessionConnection(t, raw, echoScript)
	_, err := c.RunCommand(powershell.Encode("first"))
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.RunCommand(powershell.Encode(fmt.Sprintf("n %d", i)))
			require.NoError(t, err)
			out, _ := io.ReadAll(res.Stdout)
			assert.Equal(t, fmt.Sprintf("ran n %d\r\n", i), string(out), "every command gets its own output")
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, *opened, 3, "no more sessions than commands may run at once")
}

func TestSessionFallsBackWhenItBreaks(t *testing.T) {
	raw := &fakeRunner{shell: "%OS%\r\nDesktop\r\n"}
	c, opened := sessionConnection(t, raw, func(script string) fakeReply {
		if strings.HasSuffix(script, "crash") {
			return fakeReply{die: true}
		}
		return echoScript(script)
	})

	// the session dies during the command: it runs again as a process
	crash := powershell.Encode("crash")
	res, err := c.RunCommand(crash)
	require.NoError(t, err)
	out, _ := io.ReadAll(res.Stdout)
	assert.Equal(t, "ran", string(out), "the process' output")
	assert.Equal(t, []string{shellProbe, directCommand(t, crash)}, raw.sent)

	// the next command starts a new session
	res, err = c.RunCommand(powershell.Encode("ok"))
	require.NoError(t, err)
	out, _ = io.ReadAll(res.Stdout)
	assert.Equal(t, "ran ok\r\n", string(out))
	assert.Equal(t, 2, *opened)

	// after sessionMaxFailures broken sessions, sessions are off
	for range sessionMaxFailures {
		_, err = c.RunCommand(crash)
		require.NoError(t, err)
	}
	assert.True(t, c.sessionPool.disabled)
	before := *opened
	_, err = c.RunCommand(powershell.Encode("ok"))
	require.NoError(t, err)
	assert.Equal(t, before, *opened, "no session once they are off")
	assert.Equal(t, directCommand(t, powershell.Encode("ok")), raw.sent[len(raw.sent)-1])
}

func TestSessionFallsBackWhenItCannotStart(t *testing.T) {
	t.Setenv(persistentShellEnv, "1")
	raw := &fakeRunner{shell: "%OS%\r\nDesktop\r\n"}
	c := newFakeConnection(raw)
	starts := 0
	c.openSession = func() (*psSession, error) {
		starts++
		return nil, errors.New("channel open failed")
	}
	for range sessionMaxFailures + 2 {
		res, err := c.RunCommand(powershell.Encode("Get-Date"))
		require.NoError(t, err)
		out, _ := io.ReadAll(res.Stdout)
		assert.Equal(t, "ran", string(out))
	}
	assert.Equal(t, sessionMaxFailures, starts)
}

func TestSessionOffByDefault(t *testing.T) {
	t.Setenv(persistentShellEnv, "")
	raw := &fakeRunner{shell: "%OS%\r\nDesktop\r\n"}
	c := newFakeConnection(raw)
	c.openSession = func() (*psSession, error) {
		t.Fatal("no session without " + persistentShellEnv)
		return nil, nil
	}
	_, err := c.RunCommand(powershell.Encode("Get-Date"))
	require.NoError(t, err)
}

func TestSessionNotOnUnix(t *testing.T) {
	t.Setenv(persistentShellEnv, "1")
	raw := &fakeRunner{shell: "%OS%\n"}
	c := newFakeConnection(raw)
	c.openSession = func() (*psSession, error) {
		t.Fatal("no session on a Unix target")
		return nil, nil
	}
	for _, cmd := range []string{"uname -s", powershell.EncodeUnix("Get-Date")} {
		_, err := c.RunCommand(cmd)
		require.NoError(t, err)
	}
}

func directCommand(t *testing.T, cmd string) string {
	t.Helper()
	d, ok := directPowershell(cmd)
	require.True(t, ok)
	return d
}
