// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// remoteShell is the shell the SSH server runs a command in. OpenSSH on
// Windows hands every exec request to its DefaultShell as `<shell> -c
// "<command>"` (cmd.exe with /c), so the command is parsed by that shell
// before anything it starts runs.
type remoteShell int

const (
	// shellUnknown: not detected yet, or the probe failed.
	shellUnknown remoteShell = iota
	// shellPosix is sh, bash and the like: every Unix target.
	shellPosix
	// shellCmd is cmd.exe, the default DefaultShell of OpenSSH on Windows.
	shellCmd
	// shellWindowsPowerShell is powershell.exe (Windows PowerShell 5.1), the
	// DefaultShell most Windows SSH setups configure.
	shellWindowsPowerShell
	// shellPwsh is PowerShell 7 (pwsh), on Windows or elsewhere.
	shellPwsh
)

func (s remoteShell) String() string {
	switch s {
	case shellPosix:
		return "posix"
	case shellCmd:
		return "cmd"
	case shellWindowsPowerShell:
		return "powershell"
	case shellPwsh:
		return "pwsh"
	default:
		return "unknown"
	}
}

// shellProbe tells the shells apart in one command, without a double quote
// that the Windows command line around it would end on:
//
//	cmd.exe:            Windows_NT;$PSVersionTable.PSEdition
//	Windows PowerShell: %OS% and Desktop, on two lines
//	pwsh:               %OS% and Core, on two lines
//	sh:                 %OS%, and an error on stderr for the second part
const shellProbe = "echo %OS%;$PSVersionTable.PSEdition"

// parseShellProbe reads the stdout of shellProbe.
func parseShellProbe(stdout string) remoteShell {
	if strings.Contains(stdout, "Windows_NT") {
		return shellCmd
	}
	// the last line that is not empty is what the second part printed
	var last string
	for _, line := range strings.Split(stdout, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			last = line
		}
	}
	switch last {
	case "Desktop":
		return shellWindowsPowerShell
	case "Core":
		return shellPwsh
	case "%OS%":
		return shellPosix
	default:
		return shellUnknown
	}
}

// remoteShell detects the SSH server's shell once per connection. The probe
// runs on the first PowerShell command only, so a Unix target, which never
// gets one, never pays for it.
func (c *Connection) remoteShell() remoteShell {
	c.shellOnce.Do(func() {
		res, err := c.runRaw(shellProbe)
		if err != nil || res == nil {
			log.Debug().Err(err).Msg("ssh> could not detect the remote shell")
			return
		}
		var stdout []byte
		if res.Stdout != nil {
			stdout, _ = io.ReadAll(res.Stdout)
		}
		c.shell = parseShellProbe(string(stdout))
		log.Debug().Str("shell", c.shell.String()).Msg("ssh> detected the remote shell")
	})
	return c.shell
}

// runRaw runs a command exactly as given. Tests replace it.
func (c *Connection) runRaw(command string) (*shared.Command, error) {
	if c.rawRunner != nil {
		return c.rawRunner(command)
	}
	return c.runRawCommand(command)
}

// directPowershell turns a command built by powershell.Encode into one that
// the SSH server's own powershell.exe runs, instead of starting a second
// powershell.exe inside it. Every PowerShell command over SSH to a Windows
// host whose DefaultShell is PowerShell otherwise costs two processes.
//
// The script travels encoded as before: the server's shell receives it as
// `-c "<command>"`, so the command may hold no double quote. Base64 in single
// quotes holds none.
//
// The wrapper keeps what `powershell.exe -EncodedCommand` does with the
// script, measured on Windows Server 2022 and 2025:
//
//   - The exit code: `exit N` exits with N, and otherwise the process exits 1
//     when the script's last statement failed. Invoke-Expression alone would
//     exit 0 there, so the script ends with that check.
//   - Warning, verbose and debug records go to stderr, prefixed like the
//     console prints them. A shell started with -c writes them to stdout,
//     where they would end up in the output a resource parses.
//   - Output formatting, errors on stderr, the code page and the working
//     directory are the same.
//
// The one difference is the exit code of a script that ends with `exit N`:
// it arrives as N, where the double invocation turned every non-zero code of
// the inner process into 1. N is what a local scan gets.
//
// Only the Encode form is rewritten. It pins the script to Windows
// PowerShell, which the caller checks is the server's shell; the Wrap form's
// script is not encoded and is left as it is.
func directPowershell(command string) (string, bool) {
	argv, ok := powershell.SplitInvocation(command)
	if !ok || len(argv) != 4 || argv[2] != "-EncodedCommand" {
		return "", false
	}
	switch strings.ToLower(argv[0]) {
	case "powershell", "powershell.exe":
	default:
		return "", false
	}
	script, err := base64.StdEncoding.DecodeString(argv[3])
	if err != nil || len(script)%2 != 0 {
		return "", false
	}
	// both halves are UTF-16LE, so the bytes join into one script
	encoded := base64.StdEncoding.EncodeToString(append(script, directExitCheckUTF16...))
	return "Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + encoded + "')))" +
		directStreams, true
}

const (
	// directExitCheck ends the script: -EncodedCommand exits 1 when the last
	// statement failed.
	directExitCheck = "\nif (-not $?) { exit 1 }"

	// directStreams sends warning (3), verbose (4) and debug (5) records to
	// stderr, as -EncodedCommand does. Errors (2) are left alone: the console
	// host already writes them to stderr, as it does for -EncodedCommand.
	directStreams = " 3>&1 4>&1 5>&1 | ForEach-Object { if ($_ -is [Management.Automation.InformationalRecord]) " +
		"{ [Console]::Error.WriteLine(($_.GetType().Name -replace 'Record$','').ToUpper() + ': ' + $_.Message) } else { $_ } }"
)

// directExitCheckUTF16 is directExitCheck as UTF-16LE, the encoding of the
// script it is appended to.
var directExitCheckUTF16 = func() []byte {
	b := make([]byte, 0, 2*len(directExitCheck))
	for _, u := range utf16.Encode([]rune(directExitCheck)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}()

// runPowershellDirect runs command in the server's PowerShell when it is an
// encoded Windows PowerShell script and the server's shell is Windows
// PowerShell. ok is false when the command is not one, and the caller runs it
// as it is; err is then always nil. When ok is true, res and err are what
// running the command returned, exactly as runRaw returns them for a command
// that is not rewritten: err is the command failing to run, and res may be
// nil with it.
func (c *Connection) runPowershellDirect(command string) (*shared.Command, bool, error) {
	direct, ok := directPowershell(command)
	if !ok || c.remoteShell() != shellWindowsPowerShell {
		return nil, false, nil
	}
	res, err := c.runRaw(direct)
	if res != nil {
		// the command is what the caller asked for, not how it traveled
		res.Command = command
	}
	return res, true, err
}
