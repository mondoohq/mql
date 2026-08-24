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

// Encode encodes a long powershell script as base64 and returns the wrapped command
//
// wraps a script to deactivate progress listener
// https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7
//
// deactivates loading powershell profile
// https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/powershell
func Encode(cmd string) string {
	// avoid messages to stderr that are not required in our execution
	script := "$ProgressPreference='SilentlyContinue';" + cmd

	encodedScript, err := ToBase64String(script)
	if err != nil {
		// Ignore this for now to keep the method interface identical
		// lets see if this becomes an issue
		log.Error().Err(err).Msg("could not encode powershell command")
	}
	return fmt.Sprintf("powershell.exe -NoProfile -EncodedCommand %s", encodedScript)
}

// EncodeUnix is equivalent to Encode for running powershell script on unix systems
func EncodeUnix(cmd string) string {
	// avoid messages to stderr that are not required in our execution
	script := "$ProgressPreference='SilentlyContinue';" + cmd

	encodedScript, err := ToBase64String(script)
	if err != nil {
		// Ignore this for now to keep the method interface identical
		// lets see if this becomes an issue
		log.Error().Err(err).Msg("could not encode powershell command")
	}
	return fmt.Sprintf("pwsh -NoProfile -EncodedCommand %s", encodedScript)
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

// Wrap runs a powershell script by calling powershell. Note that this is not encoded and therefore does not support
// multiline scripts or special characters. You should use Encode for that or ensure the script is a single line and
// does use semicolons to separate commands.
func Wrap(cmd string) string {
	return fmt.Sprintf("powershell -c \"%s\"", cmd)
}
