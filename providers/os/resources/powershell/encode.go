// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/text/encoding/unicode"
)

const (
	// MaxCommandLength is the largest command line Windows will accept. A
	// longer one is rejected before PowerShell ever runs, and the failure
	// arrives as a generic non-zero exit — which reads like the queried
	// feature not being installed rather than like a bug in the script.
	MaxCommandLength = 8191

	// MaxScriptLength is the largest script that Encode can still fit inside
	// MaxCommandLength. Encoding widens the script to UTF-16 (x2) and base64
	// encodes it (x4/3), and Encode additionally prepends a $ProgressPreference
	// assignment to the script and an interpreter invocation to the command
	// line. The measured ceiling is 3016 characters; this leaves a small margin
	// under it. Keep embedded scripts below this and assert it in a test —
	// see TestScheduledTasksScriptFitsCommandLine for the pattern.
	MaxScriptLength = 3000
)

// FitsCommandLine reports whether script still fits on a Windows command line
// once Encode has widened and base64 encoded it.
func FitsCommandLine(script string) bool {
	return len(Encode(script)) <= MaxCommandLength
}

// interpreters holds the executable names that Encode/EncodeUnix/Wrap emit as
// the leading token of a self-contained PowerShell invocation.
var interpreters = map[string]bool{
	"powershell":     true,
	"powershell.exe": true,
	"pwsh":           true,
	"pwsh.exe":       true,
}

// SplitInvocation parses a command string produced by Encode, EncodeUnix, or
// Wrap back into an argv ([binary, args...]) so a caller can exec it directly
// instead of nesting it inside another PowerShell shell. Running a
// PowerShell invocation through a `powershell -c "..."` shell spawns a
// redundant second powershell.exe, which endpoint protection (e.g.
// SentinelOne) flags as an encoded-command / LOLBIN-chain attack pattern.
//
// It recognizes the two shapes we emit:
//
//	powershell.exe -NoProfile -EncodedCommand <base64>   (Encode / EncodeUnix)
//	powershell -c "<script>"                             (Wrap)
//
// Returns ok=false for anything else so callers keep their existing behavior.
func SplitInvocation(cmd string) (argv []string, ok bool) {
	trimmed := strings.TrimSpace(cmd)
	sp := strings.IndexAny(trimmed, " \t")
	if sp < 0 {
		return nil, false
	}
	bin := trimmed[:sp]
	if !interpreters[strings.ToLower(bin)] {
		return nil, false
	}
	rest := strings.TrimSpace(trimmed[sp+1:])

	// Encode / EncodeUnix form: -NoProfile -EncodedCommand <base64>.
	// The base64 payload never contains whitespace, so this is unambiguous.
	if enc, found := strings.CutPrefix(rest, "-NoProfile -EncodedCommand "); found {
		enc = strings.TrimSpace(enc)
		if enc == "" || strings.ContainsAny(enc, " \t") {
			return nil, false
		}
		return []string{bin, "-NoProfile", "-EncodedCommand", enc}, true
	}

	// Wrap form: -c "<script>". Wrap builds this as `powershell -c "` + cmd + `"`,
	// so the script is the content between the outer double quotes.
	if script, found := strings.CutPrefix(rest, "-c "); found {
		script = strings.TrimSpace(script)
		if len(script) >= 2 && strings.HasPrefix(script, `"`) && strings.HasSuffix(script, `"`) {
			script = script[1 : len(script)-1]
			return []string{bin, "-c", script}, true
		}
	}

	return nil, false
}

// SingleQuote renders a value as a PowerShell single quoted string.
// Single quoting is what makes a Windows path safe to interpolate: no escape
// sequence is recognized inside it, so a backslash stays a backslash and a $
// is not expanded. Only the quote character itself needs escaping, by
// doubling it.
func SingleQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

// Encode encodes a long powershell script as base64 and returns the wrapped command
//
// wraps a script to deactivate progress listener
// https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7
//
// deactivates loading powershell profile
// https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/powershell
func Encode(cmd string) string {
	return encodeWith("powershell.exe", cmd, ToBase64String)
}

// EncodeUnix is equivalent to Encode for running powershell script on unix systems
func EncodeUnix(cmd string) string {
	return encodeWith("pwsh", cmd, ToBase64String)
}

// encodeWith builds `<interpreter> -NoProfile -EncodedCommand <payload>`.
//
// If the script cannot be encoded, it returns a command that fails with a
// clear message instead of one with an empty payload: `-EncodedCommand ` with
// nothing after it runs as a no-op that exits 0, which a caller would read as
// "the queried thing is absent" rather than as an error. The signature stays
// a plain string so that the many callers keep compiling.
func encodeWith(interpreter, cmd string, encode func(string) (string, error)) string {
	// avoid messages to stderr that are not required in our execution
	script := "$ProgressPreference='SilentlyContinue';" + cmd

	encodedScript, err := encode(script)
	if err != nil || encodedScript == "" {
		log.Error().Err(err).Msg("could not encode powershell command")
		return interpreter + " -NoProfile -Command \"throw 'mql: could not encode the PowerShell command'\""
	}
	return fmt.Sprintf("%s -NoProfile -EncodedCommand %s", interpreter, encodedScript)
}

// ToBase64String encodes a powershell script to a UTF16-LE, base64 encoded string
// The encoded command can be used with powershell.exe -EncodedCommand
//
// $text = Get-Content .\script.ps1 -Raw;
// $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($text));
// $encodedScript;
func ToBase64String(script string) (string, error) {
	uni := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	encoded, err := uni.NewEncoder().String(script)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(encoded)), nil
}

// Wrap runs a powershell script by calling powershell. The script is passed
// as plain text, so it must be a single line (separate commands with
// semicolons); use Encode for multi-line scripts. A script containing a
// double quote is encoded automatically, since the quote would end the -c
// argument.
func Wrap(cmd string) string {
	// A double quote in the script would end the -c "..." argument early,
	// and the rest would reach the shell as separate arguments. Such a script
	// is encoded instead; every other script keeps the plain form (and the
	// command string that mock fixtures key on).
	if strings.Contains(cmd, `"`) {
		return Encode(cmd)
	}
	return fmt.Sprintf("powershell -c \"%s\"", cmd)
}
