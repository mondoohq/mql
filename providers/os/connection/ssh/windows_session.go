// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

// A persistent PowerShell session runs the scan's PowerShell scripts in one
// long-lived powershell.exe per slot, instead of starting a process per
// script. It is behind MONDOO_WINDOWS_PERSISTENT_SHELL until it has proven
// itself.
//
// # Protocol
//
// The session is `powershell.exe -NoLogo -NoProfile -NonInteractive -Command -`
// started over an SSH exec request. It reads one statement per line from
// stdin. Each script is sent as a single line (sessionFrame) that:
//
//  1. resets what a script could have left behind: $LASTEXITCODE, $Error and
//     the working directory;
//  2. writes a start marker to stdout;
//  3. runs the script, base64 encoded like -EncodedCommand, through
//     Invoke-Expression in a child scope, so its variables and functions do
//     not outlive it. Warning, verbose and debug records go to stderr, as
//     with -EncodedCommand; errors are written by the console host, as there;
//  4. writes an end marker with the exit code to stdout, and an end marker to
//     stderr.
//
// Markers carry a random session ID and a sequence number, so output cannot
// forge them. The exit code follows -EncodedCommand: 1 when the script threw
// or its last statement failed, else 0.
//
// # What falls back
//
// A script that could end the session itself (it contains `exit`) runs from a
// file in %TEMP%, where exit ends only the script, and the file is removed
// after it. A script staged on the target (powershell.Stage, run with -File)
// runs from such a file too, a copy of the staged one. Any other command runs
// in the session only when the SSH server's own shell is Windows PowerShell,
// which is what would run it otherwise, and then as that shell's -c would. A
// command that starts PowerShell itself, and anything on a server whose shell
// is not Windows PowerShell, runs as its own process. When a session breaks (the process ends, the SSH channel closes, a
// frame cannot be read) the command runs as its own process and the session
// is dropped; after sessionMaxFailures broken sessions the connection stops
// using sessions.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding/unicode"
)

const (
	persistentShellEnv = "MONDOO_WINDOWS_PERSISTENT_SHELL"

	// sessionCommand starts a session. It is an ordinary command line, so it
	// works whether the SSH server's shell is PowerShell or cmd.exe.
	sessionCommand = "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -"

	// sessionMaxFailures is how many sessions may break before the connection
	// runs every command as its own process again.
	sessionMaxFailures = 3

	// sessionMaxIdle bounds the sessions a connection keeps when commands are
	// not limited (MONDOO_SSH_WINDOWS_MAX_COMMANDS=0).
	sessionMaxIdle = 8
)

// persistentShellEnabled reads MONDOO_WINDOWS_PERSISTENT_SHELL.
func persistentShellEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(persistentShellEnv))) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

// sessionExit matches a script that could end the process it runs in: `exit`,
// [Environment]::Exit and $host.SetShouldExit. Such a script runs from a file
// in the session, where `exit` ends only the script. A false match only costs
// that file. [Environment]::Exit matches through its Exit word.
var sessionExit = regexp.MustCompile(`(?i)\bexit\b|\bSetShouldExit\b`)

// sessionScript is a script a session can run.
type sessionScript struct {
	// utf16 is the script as -EncodedCommand receives it: UTF-16LE.
	utf16 []byte
	// file runs the script from a file, because it may call exit.
	file bool
	// staged is the path of a script on the target that -File would run
	// (powershell.StagedCommand); utf16 and file are unused then.
	staged string
}

// parseSessionScript decodes an encoded Windows PowerShell command. ok is
// false for anything a session must not run.
func parseSessionScript(command string) (sessionScript, bool) {
	argv, ok := powershell.SplitInvocation(command)
	if !ok || len(argv) != 4 || argv[2] != "-EncodedCommand" {
		return sessionScript{}, false
	}
	switch strings.ToLower(argv[0]) {
	case "powershell", "powershell.exe":
	default:
		return sessionScript{}, false
	}
	raw, err := base64.StdEncoding.DecodeString(argv[3])
	if err != nil || len(raw)%2 != 0 {
		return sessionScript{}, false
	}
	text, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
	if err != nil {
		return sessionScript{}, false
	}
	return sessionScript{utf16: raw, file: sessionExit.Match(text)}, true
}

// parseStagedScript reads a command built by powershell.StagedCommand. ok is
// false for anything else, and for a path the frame could not quote safely.
func parseStagedScript(command string) (sessionScript, bool) {
	path, ok := strings.CutPrefix(command, powershell.StagedCommand(""))
	if !ok || path == "" || !strings.HasSuffix(strings.ToLower(path), ".ps1") ||
		strings.ContainsAny(path, " \t\r\n\"'`$") {
		return sessionScript{}, false
	}
	return sessionScript{staged: path}, true
}

// parseRawScript takes a command that is neither encoded nor staged, for a
// session to run as the server's Windows PowerShell would run it. A command
// that starts PowerShell itself stays a process of its own: it would read the
// session's stdin, which carries the frames.
func parseRawScript(command string) (sessionScript, bool) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return sessionScript{}, false
	}
	if first, _, _ := strings.Cut(strings.ToLower(trimmed), " "); strings.Contains(first, "powershell") || strings.Contains(first, "pwsh") {
		return sessionScript{}, false
	}
	return sessionScript{utf16: utf16le(command), file: sessionExit.MatchString(command)}, true
}

// sessionLastStatus ends every script: it keeps whether the last statement
// succeeded, which -EncodedCommand turns into the exit code. A script that
// calls exit never gets there, which is how the frame tells the two apart.
var sessionLastStatus = utf16le("\n$global:__mqlOk = $?")

// stagedLastStatus ends a staged script: -File exits 0 when the script runs to
// its end, whatever its last statement did. It is a PowerShell expression
// for the line.
const stagedLastStatus = "[char]10 + '$global:__mqlOk = $true'"

func utf16le(s string) []byte {
	b, _ := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().Bytes([]byte(s))
	return b
}

// sessionMarkers are the frame markers of one command.
type sessionMarkers struct {
	start     string // the line on stdout before the output
	endPrefix string // the line on stdout after it, before the exit code
	errEnd    string // the line on stderr after the command's stderr
}

func newSessionMarkers(id string, seq uint64) sessionMarkers {
	tag := id + ":" + strconv.FormatUint(seq, 10)
	return sessionMarkers{
		start:     "<<mql-start:" + tag + ">>\r\n",
		endPrefix: "<<mql-end:" + tag + ":",
		errEnd:    "<<mql-err-end:" + tag + ">>\r\n",
	}
}

// sessionFrame is the line that runs one script in a session. The markers are
// written with a CRLF in front, so they start a line whatever the script
// wrote last; the reader removes it again.
//
// The exit code is what -EncodedCommand would exit with: 1 when the script
// threw; the code it passed to exit when it called exit (only a file can);
// else 1 when its last statement failed and 0 when it succeeded.
//
// fileTag names the file a script that may exit runs from; it is unique per
// command, so no two commands share a file.
func sessionFrame(m sessionMarkers, fileTag string, script sessionScript) string {
	encoded := base64.StdEncoding.EncodeToString(append(append([]byte{}, script.utf16...), sessionLastStatus...))
	decode := "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + encoded + "'))"
	start := strings.TrimSuffix(m.start, "\r\n")
	errEnd := strings.TrimSuffix(m.errEnd, "\r\n")

	// the file a script that may exit runs from, written as UTF-8 with a
	// BOM, so Windows PowerShell reads it as UTF-8
	fromFile := func(text string) string {
		return "$__mqlFile = Join-Path $env:TEMP 'mql-" + fileTag + ".ps1'; " +
			"[IO.File]::WriteAllText($__mqlFile, " + text + ", [Text.Encoding]::UTF8); " +
			"& $__mqlFile"
	}
	var run, cleanup string
	switch {
	case script.staged != "":
		// A copy of the staged script, with the line that tells an exit from
		// the end. -File reads a file without a BOM in the ANSI code page,
		// which is [Text.Encoding]::Default in Windows PowerShell.
		run = fromFile("[IO.File]::ReadAllText(" + powershell.SingleQuote(script.staged) + ", [Text.Encoding]::Default) + " + stagedLastStatus)
		cleanup = " finally { Remove-Item -LiteralPath $__mqlFile -Force -ErrorAction SilentlyContinue }"
	case script.file:
		run = fromFile(decode)
		cleanup = " finally { Remove-Item -LiteralPath $__mqlFile -Force -ErrorAction SilentlyContinue }"
	default:
		run = "Invoke-Expression (" + decode + ")"
	}

	return "& { " +
		"$global:LASTEXITCODE = $null; $global:Error.Clear(); $global:__mqlOk = $null; Set-Location -LiteralPath $global:__mqlHome; " +
		"[Console]::Out.Write('" + start + "' + [char]13 + [char]10); [Console]::Out.Flush(); " +
		"$__mqlThrew = $false; " +
		"try { " + run + directStreams + " | Out-Default } " +
		"catch { $__mqlThrew = $true; $host.UI.WriteErrorLine(($_ | Out-String).TrimEnd()) }" + cleanup + "; " +
		"$__mqlCode = 0; " +
		"if ($__mqlThrew) { $__mqlCode = 1 } elseif ($null -eq $global:__mqlOk) { $__mqlCode = [int]$global:LASTEXITCODE } elseif (-not $global:__mqlOk) { $__mqlCode = 1 }; " +
		"[Console]::Out.Write([char]13 + [char]10 + '" + m.endPrefix + "' + $__mqlCode + '>>' + [char]13 + [char]10); [Console]::Out.Flush(); " +
		"[Console]::Error.Write([char]13 + [char]10 + '" + errEnd + "' + [char]13 + [char]10); [Console]::Error.Flush() }"
}

// sessionSetup runs once when a session starts. It also points the
// process's stdin handle at NUL (sessionDetachStdin).
const sessionSetup = "$global:__mqlHome = (Get-Location).Path; $ProgressPreference = 'SilentlyContinue'; " + sessionDetachStdin

// sessionDetachStdin points the session's stdin handle at NUL once
// PowerShell reads its statements. A native command inherits the stdin
// handle, and the session's stdin carries the frames: a command that reads
// stdin (sort.exe, findstr.exe, set /p) would block until the session ends
// and swallow the frames after it. As its own process over SSH such a
// command reads end-of-file instead, and with NUL it does in the session too.
// PowerShell keeps reading from the handle it opened at start. The P/Invoke
// methods are emitted at runtime, since Add-Type would start csc.exe. When
// this fails, the session runs as before. It runs in a child scope, so its
// variables do not outlive it.
const sessionDetachStdin = "try { & { $ErrorActionPreference = 'Stop'; " +
	"$t = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName 'mqlstdin'), 'Run').DefineDynamicModule('m').DefineType('MqlStdin', 'Public,Class'); " +
	"foreach ($d in @(@('SetStdHandle', [bool], @([int], [IntPtr])), @('CreateFileW', [IntPtr], @([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr])), @('SetHandleInformation', [bool], @([IntPtr], [uint32], [uint32])))) { " +
	"$t.DefinePInvokeMethod($d[0], 'kernel32.dll', 'Public,Static,PinvokeImpl', 'Standard', $d[1], [Type[]]$d[2], 'Winapi', 'Unicode').SetImplementationFlags('PreserveSig') }; " +
	"$t = $t.CreateType(); " +
	// GENERIC_READ, FILE_SHARE_READ|WRITE, OPEN_EXISTING; then inheritable
	"$h = $t::CreateFileW('NUL', [uint32]2147483648, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero); " +
	"if ($h -ne [IntPtr](-1) -and $t::SetHandleInformation($h, 1, 1)) { [void]$t::SetStdHandle(-10, $h) } " +
	"} } catch { }"

// psSession is one long-lived powershell.exe.
type psSession struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	stderr  *bufio.Reader
	id      string
	seq     uint64
}

// sessionIO is what a session needs from its transport. *ssh.Session
// provides it; tests use pipes.
type sessionIO struct {
	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader
}

func newPSSession(t sessionIO) (*psSession, error) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	s := &psSession{
		stdin:  t.stdin,
		stdout: bufio.NewReaderSize(t.stdout, 64*1024),
		stderr: bufio.NewReaderSize(t.stderr, 16*1024),
		id:     hex.EncodeToString(id),
	}
	if _, err := io.WriteString(s.stdin, sessionSetup+"\r\n"); err != nil {
		return nil, err
	}
	return s, nil
}

// run runs one script and returns its stdout, stderr and exit code. Any error
// means the session can no longer be trusted.
func (s *psSession) run(script sessionScript) ([]byte, []byte, int, error) {
	s.seq++
	m := newSessionMarkers(s.id, s.seq)
	if _, err := io.WriteString(s.stdin, sessionFrame(m, s.id+"-"+strconv.FormatUint(s.seq, 10), script)+"\r\n"); err != nil {
		return nil, nil, 0, err
	}

	var stderr []byte
	var errErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		stderr, errErr = readUntilLine(s.stderr, func(line []byte) bool { return string(line) == m.errEnd })
	}()

	stdout, code, outErr := readFrame(s.stdout, m)
	<-done
	if outErr != nil {
		return nil, nil, 0, outErr
	}
	if errErr != nil {
		return nil, nil, 0, errErr
	}
	return stdout, trimInsertedCRLF(stderr), code, nil
}

// readFrame reads one command's stdout: everything after the start marker up
// to the end marker, and the exit code from the end marker.
func readFrame(r *bufio.Reader, m sessionMarkers) ([]byte, int, error) {
	// anything before the start marker is not the command's
	stray, err := readUntilLine(r, func(line []byte) bool { return string(line) == m.start })
	if err != nil {
		return nil, 0, err
	}
	if len(stray) > 0 {
		log.Debug().Int("bytes", len(stray)).Msg("ssh> discarded session output outside a frame")
	}

	code := 0
	out, err := readUntilLine(r, func(line []byte) bool {
		rest, ok := bytes.CutPrefix(line, []byte(m.endPrefix))
		if !ok {
			return false
		}
		rest, ok = bytes.CutSuffix(rest, []byte(">>\r\n"))
		if !ok {
			return false
		}
		n, err := strconv.Atoi(string(rest))
		if err != nil {
			return false
		}
		code = n
		return true
	})
	if err != nil {
		return nil, 0, err
	}
	return trimInsertedCRLF(out), code, nil
}

// readUntilLine reads lines until isEnd matches one, and returns what came
// before it.
func readUntilLine(r *bufio.Reader, isEnd func(line []byte) bool) ([]byte, error) {
	var buf []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if isEnd(line) {
			return buf, nil
		}
		buf = append(buf, line...)
	}
}

// trimInsertedCRLF removes the CRLF the frame writes before an end marker.
func trimInsertedCRLF(b []byte) []byte {
	b, _ = bytes.CutSuffix(b, []byte("\r\n"))
	return b
}

func (s *psSession) close() {
	if s.stdin != nil {
		s.stdin.Close()
	}
	if s.session != nil {
		s.session.Close()
	}
}

// psSessionPool holds a connection's idle sessions.
type psSessionPool struct {
	mu       sync.Mutex
	idle     []*psSession
	failures int
	disabled bool
	// open starts a session; tests replace it
	open func() (*psSession, error)
}

func (p *psSessionPool) get() (*psSession, error) {
	p.mu.Lock()
	if p.disabled {
		p.mu.Unlock()
		return nil, errors.New("persistent PowerShell sessions are disabled on this connection")
	}
	if n := len(p.idle); n > 0 {
		s := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return s, nil
	}
	p.mu.Unlock()

	s, err := p.open()
	if err != nil {
		p.fail(err)
		return nil, err
	}
	return s, nil
}

func (p *psSessionPool) put(s *psSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disabled || len(p.idle) >= sessionMaxIdle {
		s.close()
		return
	}
	p.idle = append(p.idle, s)
}

// fail counts a broken session, and turns sessions off after too many.
func (p *psSessionPool) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures++
	log.Debug().Err(err).Int("failures", p.failures).Msg("ssh> persistent PowerShell session failed")
	if p.failures >= sessionMaxFailures && !p.disabled {
		log.Warn().Err(err).Msg("ssh> persistent PowerShell sessions keep failing, running a process per command")
		p.disabled = true
		for _, s := range p.idle {
			s.close()
		}
		p.idle = nil
	}
}

func (p *psSessionPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.idle {
		s.close()
	}
	p.idle = nil
}

// openPSSession starts a session over the connection's SSH client.
func (c *Connection) openPSSession() (*psSession, error) {
	if c.SSHClient == nil {
		return nil, errors.New("SSH session not established")
	}
	sess, err := c.SSHClient.NewSession()
	if err != nil {
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	if err := sess.Start(sessionCommand); err != nil {
		sess.Close()
		return nil, err
	}
	s, err := newPSSession(sessionIO{stdin: stdin, stdout: stdout, stderr: stderr})
	if err != nil {
		sess.Close()
		return nil, err
	}
	s.session = sess
	log.Debug().Str("session", s.id).Msg("ssh> started a persistent PowerShell session")
	return s, nil
}

// sessions returns the connection's session pool, or nil when sessions are
// off.
func (c *Connection) sessions() *psSessionPool {
	c.sessionsOnce.Do(func() {
		if !persistentShellEnabled() {
			return
		}
		c.sessionPool = &psSessionPool{open: c.openPSSession}
		if c.openSession != nil {
			c.sessionPool.open = c.openSession
		}
	})
	return c.sessionPool
}

// sessionScriptFor returns the script a session runs for command, and false
// when a session must not run it.
func (c *Connection) sessionScriptFor(command string) (sessionScript, bool) {
	if script, ok := parseSessionScript(command); ok {
		return script, c.remoteShell().isWindows()
	}
	if script, ok := parseStagedScript(command); ok {
		return script, c.remoteShell().isWindows()
	}
	// Any other command runs in the server's shell. The shell is read here,
	// not probed: a Unix target never gets a PowerShell command, so it is
	// never probed, and on Windows the connection check detected it.
	if c.shellDetected.Load() && c.shell == shellWindowsPowerShell {
		return parseRawScript(command)
	}
	return sessionScript{}, false
}

// runInSession runs command in a persistent session when sessions are on,
// the target is Windows and the command is one a session runs: an encoded or
// staged Windows PowerShell script, or, when the server's shell is Windows
// PowerShell, any command that does not start PowerShell itself. ok is false
// when it did not, and the caller runs the command as a process.
func (c *Connection) runInSession(command string) (*shared.Command, bool) {
	pool := c.sessions()
	if pool == nil {
		return nil, false
	}
	script, ok := c.sessionScriptFor(command)
	if !ok {
		return nil, false
	}
	s, err := pool.get()
	if err != nil {
		return nil, false
	}

	// Logged like a command that runs as its own process (runRawCommand), so
	// a debug log lists every command the scan ran and waited for, whichever
	// way it ran.
	log.Debug().Str("command", command).Str("provider", "ssh").Str("session", s.id).Msg("run command")
	start := time.Now()
	stdout, stderr, code, err := s.run(script)
	if err != nil {
		s.close()
		pool.fail(fmt.Errorf("session %s: %w", s.id, err))
		// The script may have run in part before the session broke. Scan
		// scripts only read, so it runs again, from the start, as a process.
		log.Debug().Str("session", s.id).Msg("ssh> running the command again as its own process")
		return nil, false
	}
	pool.put(s)

	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBuffer(stdout),
		Stderr:     bytes.NewBuffer(stderr),
		ExitStatus: code,
		Stats:      shared.PerfStats{Start: start, Duration: time.Since(start)},
	}, true
}
