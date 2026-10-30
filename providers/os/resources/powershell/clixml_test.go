// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func readCLIXML(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "clixml", name))
	require.NoError(t, err)
	require.True(t, powershell.IsCLIXML(b), "fixture %s must be CLIXML", name)
	return b
}

// The fixtures are stderr captured over WinRM from `powershell.exe -NoProfile
// -EncodedCommand ...` on the host named in the file name.
func TestDecodeCLIXML_Captured(t *testing.T) {
	tests := []struct {
		fixture string
		want    string
	}{
		{
			// windows.acl("C:\\does-not-exist"), Windows Server 2022. The same
			// query returned byte-identical stderr on Windows Server 2016 and
			// Windows 11 24H2.
			fixture: "ws2022-get-acl.txt",
			want: "Get-Acl : Cannot find path 'C:\\does-not-exist' because it does not exist.\r\n" +
				"At line:3 char:4\r\n" +
				"+ $a=Get-Acl -LiteralPath $p\r\n" +
				"+    ~~~~~~~~~~~~~~~~~~~~~~~\r\n" +
				"    + CategoryInfo          : ObjectNotFound: (:) [Get-Acl], ItemNotFoundException\r\n" +
				"    + FullyQualifiedErrorId : GetAcl_PathNotFound,Microsoft.PowerShell.Commands.GetAclCommand",
		},
		{
			// windows.dnsServer.zones on a host without the DNS Server role, Windows Server 2022
			fixture: "ws2022-dnsserver-import-module.txt",
			want: "Import-Module : The specified module 'DnsServer' was not loaded because no valid module file was found in any module \r\n" +
				"directory.\r\n" +
				"At line:2 char:1\r\n" +
				"+ Import-Module DnsServer -ErrorAction Stop\r\n" +
				"+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\r\n" +
				"    + CategoryInfo          : ResourceUnavailable: (DnsServer:String) [Import-Module], FileNotFoundException\r\n" +
				"    + FullyQualifiedErrorId : Modules_ModuleNotFound,Microsoft.PowerShell.Commands.ImportModuleCommand",
		},
		{
			// powershell("Get-Item C:\\nope").stderr, Windows Server 2022
			fixture: "ws2022-get-item.txt",
			want: "Get-Item : Cannot find path 'C:\\nope' because it does not exist.\r\n" +
				"At line:1 char:40\r\n" +
				"+ $ProgressPreference='SilentlyContinue';Get-Item C:\\nope\r\n" +
				"+                                        ~~~~~~~~~~~~~~~~\r\n" +
				"    + CategoryInfo          : ObjectNotFound: (C:\\nope:String) [Get-Item], ItemNotFoundException\r\n" +
				"    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetItemCommand",
		},
	}
	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			got := powershell.DecodeCLIXML(readCLIXML(t, tc.fixture))
			assert.Equal(t, tc.want, string(got))
		})
	}
}

// ws2022-mixed-streams.txt is the stderr of this script on Windows Server
// 2022, run without the $ProgressPreference line that Encode adds:
//
//	Write-Progress -Activity 'Scanning' -Status 'step 1' -PercentComplete 50
//	Write-Warning 'careful: warn line'
//	Write-Verbose 'verbose line' -Verbose
//	Write-Output 'to stdout'
//	Write-Error 'multi`r`nline <tag> & "quote" _x000D_ literal é 😀 tab`tend'
//	[Console]::Error.WriteLine('raw console stderr')
//	cmd.exe /c 'echo native-stderr 1>&2'
//	Write-Error 'second error'
//	exit 3
//
// It holds progress records, warning and verbose records, XML entities, an
// escaped underscore (_x005F_), a surrogate pair, and text written to stderr
// outside the XML ahead of it.
func TestDecodeCLIXML_MixedStreams(t *testing.T) {
	script := "Write-Progress -Activity 'Scanning' -Status 'step 1' -PercentComplete 50\r\n" +
		"Write-Warning 'careful: warn line'\r\n" +
		"Write-Verbose 'verbose line' -Verbose\r\n" +
		"Write-Output 'to stdout'\r\n" +
		"Write-Error 'multi`r`nline <tag> & \"quote\" _x000D_ literal é 😀 tab`tend'\r\n" +
		"[Console]::Error.WriteLine('raw console stderr')\r\n" +
		"cmd.exe /c 'echo native-stderr 1>&2'\r\n" +
		"Write-Error 'second error'\r\n"
	want := "raw console stderr\r\n" +
		"native-stderr \r\n" +
		"WARNING: careful: warn line\r\n" +
		"VERBOSE: verbose line\r\n" +
		script +
		"exit 3 : multi`r`nline <tag> & \"quote\" _x000D_ literal é 😀 tab`tend\r\n" +
		"    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException\r\n" +
		"    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException\r\n" +
		" \r\n" +
		script +
		"exit 3 : second error\r\n" +
		"    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException\r\n" +
		"    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException"

	got := string(powershell.DecodeCLIXML(readCLIXML(t, "ws2022-mixed-streams.txt")))
	assert.Equal(t, want, got)
	assert.NotContains(t, got, "Preparing modules for first use")
	assert.NotContains(t, got, "Scanning\r\n")
}

func TestDecodeCLIXML_Escapes(t *testing.T) {
	wrap := func(s string) []byte {
		return []byte("#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">" + s + "</Objs>")
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"crlf", `<S S="Error">a_x000D__x000A_b</S><S S="Error">c</S>`, "a\r\nb\r\nc"},
		{"lowercase hex", `<S S="Error">a_x000d__x000a_</S>`, "a"},
		{"escaped underscore", `<S S="Error">_x005F_x000A_</S>`, "_x000A_"},
		{"surrogate pair", `<S S="Error">_xD83D__xDE00_</S>`, "😀"},
		{"lone surrogate", `<S S="Error">_xD83D_x</S>`, "\uFFFDx"},
		{"entities", `<S S="Error">&lt;a&gt; &amp; &quot;</S>`, `<a> & "`},
		{"not an escape", `<S S="Error">_x00G0_ _x0A_</S>`, "_x00G0_ _x0A_"},
		{"debug stream", `<S S="debug">d</S>`, "DEBUG: d"},
		{"unknown stream kept", `<S S="information">i</S>`, "i"},
		{"progress dropped", `<Obj S="progress" RefId="0"><MS><PR N="Record"><AV>busy</AV></PR></MS></Obj><S S="Error">e</S>`, "e"},
		{"nested S ignored", `<Obj S="progress" RefId="0"><MS><S N="x">inner</S></MS></Obj>`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, string(powershell.DecodeCLIXML(wrap(tc.in))))
		})
	}
}

func TestDecodeCLIXML_MultipleBlocksAndNestedHeader(t *testing.T) {
	in := "#< CLIXML\r\n" +
		`<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">first_x000D__x000A_</S></Objs>` +
		"#< CLIXML\r\n" +
		`<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">second_x000D__x000A_</S></Objs>`
	assert.Equal(t, "first\r\nsecond", string(powershell.DecodeCLIXML([]byte(in))))
}

// Anything that is not CLIXML must pass through byte for byte, including the
// stderr of Linux and macOS commands.
func TestDecodeCLIXML_PassThrough(t *testing.T) {
	tests := []string{
		"",
		"ls: cannot access '/nope': No such file or directory\n",
		"sudo: a terminal is required to read the password\n\n",
		"Get-Item : Cannot find path 'C:\\nope' because it does not exist.\r\n  \r\n",
		"warning: see #< CLIXML below\n#< CLIXML\r\n<Objs></Objs>",
		" #< CLIXML\r\n<Objs><S S=\"Error\">x</S></Objs>",
		"\xff\xfe\x00binary",
	}
	for _, in := range tests {
		assert.Equal(t, []byte(in), powershell.DecodeCLIXML([]byte(in)))
	}
}

// powershell.exe writes stderr in the console's OEM code page. Captured on
// Windows 11 (code page 437) from Write-Error with "café äöüß": the letters
// arrive as the bytes 82 84 94 81 E1, which are not valid UTF-8.
func TestDecodeCLIXML_OEMCodePage(t *testing.T) {
	in := readCLIXML(t, "win11-oem437-write-error.txt")
	require.False(t, utf8.Valid(in), "the capture must hold OEM bytes")
	got := string(powershell.DecodeCLIXML(in))
	assert.True(t, strings.HasPrefix(got, "$ProgressPreference='SilentlyContinue';Write-Error"), got)
	assert.Contains(t, got, " : Pfad nicht gefunden: café äöüß\r\n")
	assert.Contains(t, got, "+ FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException")
	assert.NotContains(t, got, "_x000D_")
}

func TestDecodeCLIXML_MalformedIsUnchanged(t *testing.T) {
	full := readCLIXML(t, "ws2022-get-acl.txt")
	tests := [][]byte{
		full[:len(full)-3], // truncated before </Objs>
		[]byte("#< CLIXML\r\n<Objs><S S=\"Error\">x</Obj></Objs>"),
	}
	for _, in := range tests {
		assert.Equal(t, in, powershell.DecodeCLIXML(in))
	}
}

func TestDecodeStderr(t *testing.T) {
	t.Run("clixml buffer is rewritten", func(t *testing.T) {
		cmd := &shared.Command{Stderr: bytes.NewBuffer(readCLIXML(t, "ws2022-get-item.txt"))}
		powershell.DecodeStderr(cmd)
		assert.True(t, strings.HasPrefix(cmd.Stderr.(*bytes.Buffer).String(), "Get-Item : Cannot find path 'C:\\nope'"))
	})
	t.Run("plain buffer is untouched", func(t *testing.T) {
		in := "ls: cannot access '/nope': No such file or directory\n"
		cmd := &shared.Command{Stderr: bytes.NewBufferString(in)}
		powershell.DecodeStderr(cmd)
		assert.Equal(t, in, cmd.Stderr.(*bytes.Buffer).String())
	})
	t.Run("nil command", func(t *testing.T) {
		powershell.DecodeStderr(nil)
	})
}
