// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Command lines on Windows are one string that the program splits itself, so
// they follow CommandLineToArgvW rather than POSIX shell quoting. The command
// lines below are Get-Process Path values (what process.command reports on
// Windows) and Win32_Process CommandLine values, captured from Windows Server
// 2016 and 2022 EC2 instances.
func TestParseWindowsCommand(t *testing.T) {
	tests := []struct {
		name       string
		cmd        string
		executable string
		flags      map[string]string
	}{
		{
			// csrss, smss, System, Idle, Registry, wininit, services and
			// protected services report no Path
			name:       "no command",
			cmd:        "",
			executable: "csrss",
			flags:      map[string]string{},
		},
		{
			name:       "unquoted path with spaces",
			cmd:        `C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe`,
			executable: "amazon-ssm-agent",
			flags:      map[string]string{},
		},
		{
			name:       "unquoted path with spaces, no executable name",
			cmd:        `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MpDefenderCoreService.exe`,
			executable: "",
			flags:      map[string]string{},
		},
		{
			name:       "unquoted path without spaces",
			cmd:        `C:\Windows\system32\cmd.exe`,
			executable: "cmd",
			flags:      map[string]string{},
		},
		{
			name:       "quoted path with spaces",
			cmd:        `"C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"`,
			executable: "amazon-ssm-agent",
			flags:      map[string]string{},
		},
		{
			name:       "quoted path with spaces and arguments",
			cmd:        `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MpCmdRun.exe" SpyNetServiceDss -RestrictPrivileges -AccessKey 00000000-0000-0000-0000-000000000000 -Reinvoke`,
			executable: "MpCmdRun",
			flags: map[string]string{
				"SpyNetServiceDss":   "",
				"restrictprivileges": "",
				"accesskey":          "00000000-0000-0000-0000-000000000000",
				"reinvoke":           "",
			},
		},
		{
			name:       "quoted argument",
			cmd:        `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MpDefenderCoreService.exe" "network_client"`,
			executable: "MpDefenderCoreService",
			flags:      map[string]string{"network_client": ""},
		},
		{
			name:       "svchost",
			cmd:        `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp`,
			executable: "svchost",
			flags: map[string]string{
				"k": "LocalServiceNetworkRestricted",
				"p": "",
				"s": "Dhcp",
			},
		},
		{
			name:       "NT object path prefix",
			cmd:        `\??\C:\Windows\system32\conhost.exe 0x4`,
			executable: "conhost",
			flags:      map[string]string{"0x4": ""},
		},
		{
			name:       "bare image name, two spaces before the first argument",
			cmd:        `powershell.exe  -NoProfile -EncodedCommand JABQAHIAbwBnAA==`,
			executable: "powershell",
			flags: map[string]string{
				"noprofile":      "",
				"encodedcommand": "JABQAHIAbwBnAA==",
			},
		},
		{
			// the first .exe prefix ends argv[0]; a later program in the
			// arguments is not mistaken for it
			name:       "program in the arguments",
			cmd:        `C:\Windows\system32\cmd.exe /C powershell.exe -NoProfile`,
			executable: "cmd",
			flags: map[string]string{
				"/C":             "",
				"powershell.exe": "",
				"noprofile":      "",
			},
		},
		{
			name:       "slash switches are operands",
			cmd:        `"LogonUI.exe" /flags:0x2 /state0:0xa3a15855 /state1:0x41c64e6d`,
			executable: "LogonUI",
			flags: map[string]string{
				"/flags:0x2":         "",
				"/state0:0xa3a15855": "",
				"/state1:0x41c64e6d": "",
			},
		},
		{
			// A POSIX shell reads "\ " as an escaped space; Windows does not,
			// so the backslash stays in the value and the space still splits.
			name:       "backslashes in an argument are literal",
			cmd:        `C:\Windows\system32\DllHost.exe -config C:\Program\ Data\x.ini`,
			executable: "DllHost",
			flags: map[string]string{
				"config":     `C:\Program\`,
				`Data\x.ini`: "",
			},
		},
		{
			// extension-less argv[0]: the executable name finds its end
			name:       "unquoted path with spaces, no extension",
			cmd:        `C:\Program Files\Tool\agent --config C:\agent.yml`,
			executable: "agent",
			flags:      map[string]string{"config": `C:\agent.yml`},
		},
		{
			// reproduced on Windows 11: ping.exe run from a folder named
			// "ping 1" reported the flag "1\ping.exe"
			name:       "folder named like the program",
			cmd:        `C:\mqlprobe\ping 1\ping.exe`,
			executable: "ping",
			flags:      map[string]string{},
		},
		{
			name:       "folder named like the program, with arguments",
			cmd:        `C:\Program Files\Python 3\python.exe -m pip`,
			executable: "python",
			flags:      map[string]string{"m": "pip"},
		},
		{
			// the bare image name ends argv[0] before a later .exe argument
			name:       "no extension, argument ending in .exe",
			cmd:        `C:\Tools\wrapper --run C:\x\child.exe --flag`,
			executable: "wrapper",
			flags:      map[string]string{"run": `C:\x\child.exe`, "flag": ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := FlagSet{}
			require.NoError(t, fs.ParseWindowsCommand(tc.cmd, tc.executable))
			assert.Equal(t, tc.flags, fs.Map())
		})
	}
}

func TestSplitWindowsArgv0(t *testing.T) {
	tests := []struct {
		cmd        string
		executable string
		argv0      string
	}{
		{`C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe`, "amazon-ssm-agent", `C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe`},
		{`C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe`, "", `C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe`},
		{`"C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"`, "amazon-ssm-agent", `C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe`},
		{`C:\Windows\system32\svchost.exe -k DcomLaunch -p`, "svchost", `C:\Windows\system32\svchost.exe`},
		{`winlogon.exe`, "winlogon", `winlogon.exe`},
		// no .exe and no matching name: CommandLineToArgvW's first-space rule
		{`C:\Program Files\x y`, "", `C:\Program`},
		// an unterminated quote runs to the end of the line
		{`"C:\Program Files\x.exe -a`, "", `C:\Program Files\x.exe -a`},
	}
	for _, tc := range tests {
		argv0, _ := splitWindowsArgv0(tc.cmd, tc.executable)
		assert.Equal(t, tc.argv0, argv0, tc.cmd)
	}
}

func TestWindowsCommandLineToArgv(t *testing.T) {
	// the escaping rules of CommandLineToArgvW; Go's os package splits
	// command lines the same way and tests that against the real API
	tests := []struct {
		in   string
		args []string
	}{
		{`"a b c" d e`, []string{"a b c", "d", "e"}},
		{`"ab\"c" "\\" d`, []string{`ab"c`, `\`, "d"}},
		{`a\\\b d"e f"g h`, []string{`a\\\b`, "de fg", "h"}},
		{`a\\\"b c d`, []string{`a\"b`, "c", "d"}},
		{`a\\\\"b c" d e`, []string{`a\\b c`, "d", "e"}},
		// "" inside quotes is a literal quote that also closes the quoted
		// section, CommandLineToArgvW's behaviour (msvcrt's since 2008 keeps
		// the section open)
		{`"a ""b"" c"`, []string{`a "b`, "c"}},
		{"a\tb", []string{"a", "b"}},
		{`C:\dir\ trailing\`, []string{`C:\dir\`, `trailing\`}},
		{``, nil},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.args, windowsCommandLineToArgv(tc.in), tc.in)
	}
}
