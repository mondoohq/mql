// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Staging exists because Encode has a ceiling that a script can grow past
// without anything saying so. Encode widens the script to UTF-16 and base64
// encodes it, so the command line is roughly 2.7x the source; past
// MaxCommandLength the target rejects the command *before* PowerShell runs and
// the caller gets a non-zero exit with no stdout — which reads like the queried
// feature being absent rather than like a script that outgrew its transport.
//
// The ceiling is also not one number. Over SSH the command reaches
// CreateProcess directly and the practical limit is around 32k; over WinRM it
// is routed through cmd.exe and the limit is MaxCommandLength (8191). A script
// verified over SSH is therefore still untested against the tighter of the two.
//
// Staging removes the ceiling entirely: the script is written to a file on the
// target and run with `-File`, so the command line carries a path rather than a
// program.

const (
	// stagedDirWindows and stagedDirUnix are the directories a staged script is
	// written to. They are **client-side literals**, chosen from the asset's
	// platform, and never read off the target (no `$env:TEMP` round trip).
	//
	// That is load-bearing rather than tidy. The staged command string is the
	// identity of the `command` resource it runs through, so it is also the key
	// a recording is stored under. Asking the target for its temp directory
	// would put a host-dependent string in that key, and a recording captured on
	// one host would not replay on another — which defeats the content hash
	// below and breaks replay in the quiet direction, by simply not matching.
	stagedDirWindows = `C:\Windows\Temp`
	stagedDirUnix    = "/tmp"

	// mockConnectionType is what the replay connection reports. It is a string
	// rather than a shared.ConnectionType constant because none is declared for
	// it; see providers/os/connection/mock/mock.go.
	mockConnectionType = "mock"

	// chunkSize is the base64 payload per RunCommand round trip on the fallback
	// path. Each chunk is interpolated into a fixed ~120 character command, so
	// this stays comfortably under MaxCommandLength even on the 8191 transport.
	chunkSize = 6000
)

// StagedScript is a script written to a file on the target, and the command
// that runs it.
type StagedScript struct {
	// Path is the full path of the file on the target.
	Path string
	// Command is the command line that runs it. Pass this where you would
	// otherwise have passed Encode(script).
	Command string

	conn    shared.Connection
	written bool
	// viaFS records that the write went through the connection's filesystem,
	// which is also the cheapest way to take it off again.
	viaFS bool
}

// stagedDir picks the staging directory from the asset's platform.
//
// The asset is what the mock connection also carries, so this resolves
// identically during replay without touching the target.
func stagedDir(conn shared.Connection) string {
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil && asset.Platform.IsFamily("windows") {
		return stagedDirWindows
	}
	return stagedDirUnix
}

// StagedName returns the file name a script is staged under: the caller's name,
// the first 12 hex digits of the script's SHA-256, and `.ps1`.
//
// The hash is not decoration. `mqlCommand.id()` is the command string, so every
// staged script sharing one fixed path would collide under a single recording
// key — one script's recorded output would be replayed for another. Naming the
// file by content keeps recordings script-distinct at no cost, and makes a file
// left behind by an interrupted scan identifiable.
func StagedName(name, script string) string {
	sum := sha256.Sum256([]byte(script))
	return fmt.Sprintf("%s-%s.ps1", name, hex.EncodeToString(sum[:])[:12])
}

// StagedWindowsPath returns the path a script staged under name takes on a
// Windows target.
//
// Exported for tests that have to derive the command a staged resource will
// issue — it is the identity of the `command` resource, so it is the key a
// recording has to be filed under. Building it by hand from a literal would
// duplicate stagedDirWindows and drift from it silently.
func StagedWindowsPath(name, script string) string {
	return stagedDirWindows + `\` + StagedName(name, script)
}

// StagedCommand returns the command line that runs a staged script.
//
// `-ExecutionPolicy Bypass` is required and not defensive. `-File` is subject
// to the execution policy where `-EncodedCommand` is not, so a script that runs
// fine as an encoded command fails as a file the moment the policy is anything
// stricter than the `RemoteSigned` default. Because the default masks it, the
// failure only appears on a hardened host — which is exactly the host a
// security scan is pointed at.
func StagedCommand(path string) string {
	return fmt.Sprintf(
		"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File %s", path)
}

// Stage writes script to a file on the target and returns the command that runs
// it. `name` is a short identifier used in the file name — the resource the
// script belongs to, e.g. "iis".
//
// Two write paths, because the connections do not agree on whether their
// filesystem is writable, and the split is narrower than it looks:
//
//   - `FileSystem()` where it is. That is local (`afero.NewOsFs`) and ssh over
//     **sftp** — and only sftp. `scp.Fs.Create` returns "create not
//     implemented" exactly as the read-only shims do, so an ssh connection
//     forced onto scp takes the fallback below like a winrm one.
//   - chunked base64 over `RunCommand`, decoded on the target, everywhere else:
//     scp, winrm and `ssh --sudo`, the last two through a `cat.Fs` that stubs
//     every mutating method with "not implemented".
//
// On a mock (replay) connection nothing is written at all. The command string
// is derived entirely from the script's content and the asset's platform, both
// of which the recording carries, so the recorded output is found without the
// target ever having existed.
//
// The caller must call Remove when it is done, on the error path too.
func Stage(conn shared.Connection, name, script string) (*StagedScript, error) {
	if conn == nil {
		return nil, errors.New("cannot stage a script without a connection")
	}
	dir := stagedDir(conn)
	path := dir + pathSeparator(dir) + StagedName(name, script)
	staged := &StagedScript{Path: path, Command: StagedCommand(path), conn: conn}

	// Replay: the file is not needed and cannot be written. Returning the
	// command unwritten is the whole point — it is the recording's key.
	if conn.Type() == mockConnectionType {
		return staged, nil
	}

	if err := writeViaFileSystem(conn, path, script); err == nil {
		staged.written = true
		staged.viaFS = true
		return staged, nil
	} else {
		log.Debug().Err(err).Str("path", path).
			Msg("powershell> staging over the filesystem failed, falling back to a chunked write")
	}

	if err := writeViaCommand(conn, path, script); err != nil {
		return nil, fmt.Errorf("could not stage the powershell script on the target: %w", err)
	}
	staged.written = true
	return staged, nil
}

// pathSeparator returns the separator for the staging directory it is given.
// Taking the directory rather than the connection keeps it in step with
// stagedDir by construction, instead of by re-deriving the same choice.
func pathSeparator(dir string) string {
	if dir == stagedDirWindows {
		return `\`
	}
	return "/"
}

// writeViaFileSystem is the direct path, used wherever the connection's
// filesystem actually implements writing.
func writeViaFileSystem(conn shared.Connection, path, script string) error {
	fs := conn.FileSystem()
	if fs == nil {
		return errors.New("connection has no filesystem")
	}
	// Create the file rather than open whatever is at the path. The staging
	// directory is writable by every local user and the name is derived from the
	// script, so the path is knowable before a scan runs; O_EXCL makes a file
	// that is already there a failure instead of something this write goes
	// through. Nothing is lost by failing: the caller falls back to the chunked
	// write, which creates the file the same way.
	//
	// The create comes first and the delete only after it fails, rather than the
	// other way around, because the path is free on every scan that was not
	// interrupted. Over sftp clearing it first would spend two round trips
	// deleting nothing: pkg/sftp's Remove tries the file, then the directory,
	// before it can say the path does not exist.
	//
	// The retry is deliberately not gated on the error meaning "already exists".
	// Over sftp that gate would never open: SFTP v3 has no status code for it,
	// so a server answers EEXIST with SSH_FX_FAILURE and pkg/sftp passes it
	// through untranslated, leaving os.IsExist false on the one transport this
	// matters for. A failure that deleting cannot fix simply fails the second
	// create too. Re-planting the path between the two is not a way in
	// either — that is what the second O_EXCL is for.
	f, err := fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if rmErr := fs.Remove(path); rmErr != nil {
			// Report why the create failed, not why the speculative delete did.
			return err
		}
		f, err = fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
	if err != nil {
		return err
	}

	// No BOM and no CRLF: -File needs neither, and every byte a staged script
	// puts in a *value* is ASCII today. That last part is a constraint, not an
	// observation — PowerShell 5.1 decodes a BOM-less file with the ANSI
	// codepage, so a non-ASCII character in an emitted string would arrive
	// mangled where the -EncodedCommand path would have carried it intact. The
	// em dashes in iis.ps1 are all inside comments, where that does not show.
	if _, err := f.Write([]byte(script)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeViaCommand appends the script to the target in base64 chunks and decodes
// it there, for the connections whose filesystem is read-only.
//
// Base64 rather than the raw text because the payload is interpolated into a
// command line: base64's alphabet contains nothing a shell or PowerShell parser
// treats specially, so no quoting question arises at all. Chunked because the
// point of staging is that the script is *longer* than a command line.
func writeViaCommand(conn shared.Connection, path, script string) error {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return errors.New("connection can neither write files nor run commands")
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	tmp := path + ".b64"

	// Fresh file per run: an interrupted earlier scan could otherwise leave a
	// partial payload that this one silently appends to. New-Item without
	// -Force is the exclusive create - it fails rather than reusing whatever is
	// at the path, which matters because the staging directory is writable by
	// every local user and the name is derived from the script. The attribute
	// test is 0x400, FILE_ATTRIBUTE_REPARSE_POINT: a link at the path would
	// otherwise send the chunks somewhere else entirely.
	if err := runOne(conn, psCommand(
		fmt.Sprintf("Remove-Item -Force -ErrorAction SilentlyContinue '%s','%s'; New-Item -ItemType File -Path '%s' -ErrorAction Stop | Out-Null", tmp, path, tmp),
		// Success is an empty file this command created, and no final file yet.
		fmt.Sprintf("(Test-Path '%s') -and -not (Test-Path '%s') -and (((Get-Item '%s' -Force -ErrorAction Stop).Attributes -band 1024) -eq 0)", tmp, path, tmp))); err != nil {
		return err
	}

	for i := 0; i < len(encoded); i += chunkSize {
		end := min(i+chunkSize, len(encoded))
		// Add-Content, not a redirect: `>>` from cmd.exe writes UTF-16 and
		// appends a newline per call, both of which corrupt a base64 stream.
		// -NoNewline keeps the chunks contiguous.
		if err := runOne(conn, psCommand(
			fmt.Sprintf("Add-Content -Path '%s' -Value '%s' -NoNewline -Encoding ascii -ErrorAction Stop",
				tmp, encoded[i:end]),
			fmt.Sprintf("(Get-Item '%s' -ErrorAction Stop).Length -ge %d", tmp, end))); err != nil {
			return err
		}
	}

	// Decode on the target rather than shipping the plain text: this is the one
	// step whose size does not depend on the script.
	if err := runOne(conn, psCommand(
		fmt.Sprintf("New-Item -ItemType File -Path '%s' -ErrorAction Stop | Out-Null; [IO.File]::WriteAllBytes('%s',[Convert]::FromBase64String((Get-Content -Raw '%s' -ErrorAction Stop))); Remove-Item -Force -ErrorAction SilentlyContinue '%s'",
			path, path, tmp, tmp),
		fmt.Sprintf("(Get-Item '%s' -ErrorAction Stop).Length -eq %d", path, len(script)))); err != nil {
		return err
	}
	return nil
}

// psCommand builds one staging command: a statement, and a boolean expression
// that says whether it worked.
//
// Two things about it are counter-intuitive and both were found by running it.
//
// **The exit code has to be computed, not inherited.** `powershell -Command`
// exits 1 whenever `$?` is false at the end, and `$?` is false after a
// *suppressed* error as well as a reported one — so
// `Remove-Item -Force -ErrorAction SilentlyContinue` on a file that is not
// there exits 1 with empty stderr. Read at face value that is a failed write.
// The `check` expression replaces that with a statement about the filesystem:
// is the file gone, is it long enough, does it hold the whole script.
//
// **The command must contain no `$` at all.** Over SSH to a Windows host whose
// sshd `DefaultShell` is PowerShell — which is the normal configuration, and
// the one this resource is scanned over — the command line is parsed *twice*:
// once by the login shell, then by the `powershell.exe` it launches. The outer
// pass expands `$ErrorActionPreference` and `$_` inside the double-quoted
// argument before the inner one ever sees them, leaving a syntax error. The
// earlier version of this function used both, and the failure was invisible:
// it only ran on the cleanup path, which logs at debug and leaves the staged
// file behind on every scan. Anything needing a variable belongs in the staged
// script, not on the command line that starts it.
func psCommand(body, check string) string {
	return "powershell.exe -NoProfile -NonInteractive -Command " +
		"\"" + body + "; if (" + check + ") { exit 0 } else { exit 1 }\""
}

// runOne runs one command and turns a non-zero exit into an error. RunCommand
// itself reports a failed *command* through ExitStatus, not through err, so
// checking only err reports a failed write as a successful one.
func runOne(conn shared.Connection, cmd string) error {
	res, err := conn.RunCommand(cmd)
	if err != nil {
		return err
	}
	if res.ExitStatus != 0 {
		stderr := ""
		if res.Stderr != nil {
			raw, _ := io.ReadAll(res.Stderr)
			stderr = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("staging command exited %d: %s", res.ExitStatus, stderr)
	}
	return nil
}

// Remove deletes the staged file. It is safe to call more than once, and safe
// to call on a script that was never written.
//
// Call it on the error path too. A scan that dies between the write and the run
// leaves the file behind; the hashed name at least makes it identifiable.
func (s *StagedScript) Remove() {
	if s == nil || !s.written || s.conn == nil {
		return
	}
	s.written = false

	// A script that went on through the filesystem comes off the same way. The
	// command below starts a powershell.exe on the target, which is the most
	// expensive single step in staging, to delete a file the connection can
	// unlink in one request.
	if s.viaFS {
		if fs := s.conn.FileSystem(); fs != nil {
			err := fs.Remove(s.Path)
			if err == nil {
				return
			}
			log.Debug().Err(err).Str("path", s.Path).
				Msg("powershell> could not unlink the staged script, falling back to a command")
		}
	}

	err := runOne(s.conn, psCommand(
		fmt.Sprintf("Remove-Item -Force -ErrorAction SilentlyContinue '%s'", s.Path),
		fmt.Sprintf("-not (Test-Path '%s')", s.Path)))
	if err != nil {
		log.Debug().Err(err).Str("path", s.Path).
			Msg("powershell> could not remove the staged script")
	}
}

// CanStage reports whether staging is possible over this connection at all. A
// connection that can neither write a file nor run a command cannot be staged
// to, and the caller has to fall back to Encode and accept the ceiling.
func CanStage(conn shared.Connection) bool {
	if conn == nil {
		return false
	}
	if conn.Type() == mockConnectionType {
		return true
	}
	// Capability_File alone is not enough: every read-only shim advertises it
	// and then refuses to Create. RunCommand is what the fallback needs, and a
	// connection that can run a PowerShell script can run the write too.
	return conn.Capabilities().Has(shared.Capability_RunCommand)
}
