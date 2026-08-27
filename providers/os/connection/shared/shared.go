// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type ConnectionType string

func (ct ConnectionType) String() string {
	return string(ct)
}

// Note: We generally prefer to have the types close with their connections,
// however the detectors would then have to pull in every connection as a
// dependency with all their code, just to check if the type is e.g. local
// or ssh. Keeping them in shared is more annoying (coding-wise), but
// keeps the dependency-graph very small.
const (
	Type_Local             ConnectionType = "local"
	Type_SSH               ConnectionType = "ssh"
	Type_Tar               ConnectionType = "tar"
	Type_FileSystem        ConnectionType = "filesystem"
	Type_Winrm             ConnectionType = "winrm"
	Type_Vagrant           ConnectionType = "vagrant"
	Type_DockerContainer   ConnectionType = "docker-container"
	Type_DockerImage       ConnectionType = "docker-image"
	Type_DockerFile        ConnectionType = "docker-file"
	Type_DockerRegistry    ConnectionType = "docker-registry"
	Type_DockerSnapshot    ConnectionType = "docker-snapshot"
	Type_ContainerRegistry ConnectionType = "container-registry"
	Type_RegistryImage     ConnectionType = "registry-image"
	Type_Device            ConnectionType = "device"

	ContainerProxyOption string = "container-proxy"
)

type OSFamily string

const (
	OSFamily_Darwin  OSFamily = "darwin"
	OSFamily_Unix    OSFamily = "unix"
	OSFamily_Windows OSFamily = "windows"
	OSFamily_None    OSFamily = "none"
)

type Connection interface {
	plugin.Connection
	RunCommand(command string) (*Command, error)
	FileInfo(path string) (FileInfoDetails, error)
	FileSystem() afero.Fs
	Name() string
	Type() ConnectionType
	Asset() *inventory.Asset
	UpdateAsset(asset *inventory.Asset)
	Capabilities() Capabilities
}

type ConnectionWithOSFamily interface {
	OSFamily() OSFamily
}

type SimpleConnection interface {
	plugin.Connection
	Name() string
	Type() ConnectionType
	Asset() *inventory.Asset
}

type Command struct {
	Command    string
	Stats      PerfStats
	Stdout     io.ReadWriter
	Stderr     io.ReadWriter
	ExitStatus int
}

type Capabilities byte

const (
	Capability_None       Capabilities = 0
	Capability_RunCommand Capabilities = 1 << iota
	Capability_File
	Capability_FindFile
	Capability_FileSearch
)

func (c Capabilities) Has(other Capabilities) bool {
	return c&other == other
}

func (c Capabilities) String() []string {
	res := []string{}
	if c.Has(Capability_RunCommand) {
		res = append(res, "run-command")
	}
	if c.Has(Capability_File) {
		res = append(res, "file")
	}
	if c.Has(Capability_FindFile) {
		res = append(res, "find-file")
	}
	return res
}

type FileSearch interface {
	Find(from string, r *regexp.Regexp, typ string, perm *uint32, depth *int) ([]string, error)
}

type PerfStats struct {
	Start    time.Time     `json:"start"`
	Duration time.Duration `json:"duration"`
}

type FileInfo struct {
	FName    string
	FSize    int64
	FIsDir   bool
	FModTime time.Time
	FMode    os.FileMode
	Uid      int64
	Gid      int64
}

func (f *FileInfo) Name() string {
	return f.FName
}

func (f *FileInfo) Size() int64 {
	return f.FSize
}

func (f *FileInfo) Mode() os.FileMode {
	return f.FMode
}

func (f *FileInfo) ModTime() time.Time {
	return f.FModTime
}

func (f *FileInfo) IsDir() bool {
	return f.FIsDir
}

func (f *FileInfo) Sys() any {
	return f
}

type FileInfoDetails struct {
	Size int64
	Mode FileModeDetails
	Uid  int64
	Gid  int64
	Path string
}

type FileModeDetails struct {
	os.FileMode
}

func (mode FileModeDetails) UserReadable() bool {
	return uint32(mode.FileMode)&0o0400 != 0
}

func (mode FileModeDetails) UserWriteable() bool {
	return uint32(mode.FileMode)&0o0200 != 0
}

func (mode FileModeDetails) UserExecutable() bool {
	return uint32(mode.FileMode)&0o0100 != 0
}

func (mode FileModeDetails) GroupReadable() bool {
	return uint32(mode.FileMode)&0o0040 != 0
}

func (mode FileModeDetails) GroupWriteable() bool {
	return uint32(mode.FileMode)&0o0020 != 0
}

func (mode FileModeDetails) GroupExecutable() bool {
	return uint32(mode.FileMode)&0o0010 != 0
}

func (mode FileModeDetails) OtherReadable() bool {
	return uint32(mode.FileMode)&0o0004 != 0
}

func (mode FileModeDetails) OtherWriteable() bool {
	return uint32(mode.FileMode)&0o0002 != 0
}

func (mode FileModeDetails) OtherExecutable() bool {
	return uint32(mode.FileMode)&0o0001 != 0
}

func (mode FileModeDetails) Suid() bool {
	return mode.FileMode&fs.ModeSetuid != 0
}

func (mode FileModeDetails) Sgid() bool {
	return mode.FileMode&fs.ModeSetgid != 0
}

func (mode FileModeDetails) Sticky() bool {
	return mode.FileMode&fs.ModeSticky != 0
}

func (mode FileModeDetails) UnixMode() uint32 {
	m := mode.FileMode & 0o777

	if (mode.FileMode & fs.ModeSetuid) != 0 {
		m |= 0o4000
	}

	if (mode.FileMode & fs.ModeSetgid) != 0 {
		m |= 0o2000
	}

	if (mode.FileMode & fs.ModeSticky) != 0 {
		m |= 0o1000
	}

	return uint32(m)
}

func ParseSudo(flags map[string]*llx.Primitive) *inventory.Sudo {
	sudo := flags["sudo"]
	if sudo == nil {
		return nil
	}

	active := sudo.RawData().Value.(bool)
	if !active {
		return nil
	}

	return &inventory.Sudo{
		Active:     true,
		Executable: "sudo",
	}
}

var shellEscapeRegex = regexp.MustCompile(`[^\w@%+=:,./-]`)

func ShellEscape(s string) string {
	if len(s) == 0 {
		return "''"
	}
	if shellEscapeRegex.MatchString(s) {
		return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}

	return s
}

// shellReservedWords are the words a shell treats as syntax when they open a
// command line. sudo would take one as the name of a program to run.
var shellReservedWords = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true, "fi": true,
	"for": true, "while": true, "until": true, "do": true, "done": true,
	"case": true, "esac": true, "function": true, "select": true,
	"time": true, "{": true, "!": true,
}

// needsShellForSudo reports whether cmd is something other than a plain argv,
// and so has to be handed to a shell rather than straight to sudo.
//
// sudo takes a command, not a shell command line: it binds to the first word
// and passes the rest as that command's arguments. That is right for the great
// majority of what the provider runs (`uname -s`, `rpm -qa ...`), and those
// keep their existing shape so recorded command lines still match. It is wrong
// whenever the shell would have done something with the line first.
func needsShellForSudo(cmd string) bool {
	var single, double bool
	firstWordEnd := -1

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case single:
			if c == '\'' {
				single = false
			}
			continue
		case double:
			if c == '\\' {
				i++
			} else if c == '"' {
				double = false
			}
			continue
		}

		switch c {
		case '\'':
			single = true
		case '"':
			double = true
		case '\\':
			i++
		case ' ', '\t':
			if firstWordEnd < 0 {
				firstWordEnd = i
			}
		case '|', '&', ';', '<', '>', '(', ')', '\n', '`':
			// a control operator, redirect, subshell or substitution: the
			// shell owns it, and sudo would only ever have covered the part
			// before it
			return true
		}
	}

	if single || double {
		// unbalanced quoting is not an argv we can reason about; let the shell
		// deal with it rather than handing sudo half a word
		return true
	}

	first := cmd
	if firstWordEnd >= 0 {
		first = cmd[:firstWordEnd]
	}
	first = strings.TrimSpace(first)
	if first == "" {
		return false
	}
	if shellReservedWords[first] {
		return true
	}
	// a leading VAR=value is an assignment the shell applies to the
	// environment, not a program sudo can run
	if eq := strings.IndexByte(first, '='); eq > 0 && !strings.ContainsAny(first[:eq], "/.") {
		return true
	}

	return false
}

// BuildSudoCommand elevates a command line with sudo.
//
// sudo takes a command, not a shell command line: it binds to the first word.
// Prefixing the string is therefore wrong for anything that is not a plain
// argv --
//
//	if [ -r x ]; then ...  ->  sudo if [ -r x ]; then ...   (syntax error)
//	a | b                  ->  sudo a | b                   (only a is root)
//	a > /root/f            ->  sudo a > /root/f             (redirect is not)
//
// -- and the caller cannot tell, because the shell reports the syntax error on
// stderr with a non-zero exit that reads like "the command is not available".
// The cgroups probe hit exactly that: `cgroups` reported version 0 and no
// controllers on every host scanned with --sudo, while the same host answered
// correctly without it.
//
// Such a line is run through a shell that is itself under sudo, quoted so the
// shell sees it as one word. A plain argv keeps the bare `sudo <cmd>` form, so
// the command lines the provider already issues -- and the recordings keyed on
// them -- are unchanged.
func BuildSudoCommand(sudo *inventory.Sudo, cmd string) string {
	if sudo == nil || !sudo.Active {
		return cmd
	}

	var sb strings.Builder
	sb.WriteString(sudo.Executable)

	if len(sudo.User) > 0 {
		sb.WriteString(" -u " + sudo.User)
	}

	if shell := sudo.Shell; shell != "" {
		sb.WriteString(" " + shell + " -c " + ShellEscape(cmd))
		return sb.String()
	}

	if needsShellForSudo(cmd) {
		sb.WriteString(" sh -c " + ShellEscape(cmd))
		return sb.String()
	}

	sb.WriteString(" ")
	sb.WriteString(cmd)
	return sb.String()
}

type Wrapper interface {
	Build(cmd string) string
}
