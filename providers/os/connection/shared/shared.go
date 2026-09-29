// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
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

	// The executable is left empty so the connection picks sudo or doas
	// from what the target has installed. An executable set in an
	// inventory file is kept as configured.
	return &inventory.Sudo{
		Active: true,
	}
}

// Privilege elevation executables that can be detected on a target. Both
// accept every argument BuildSudoCommand emits: an optional `-u <user>`
// followed by the command and its arguments.
const (
	ElevationSudo = "sudo"
	ElevationDoas = "doas"
)

const elevationProbeMarker = "mql-elevation-probe-done"

// ElevationProbeCommand lists the elevation executables installed on a
// POSIX target. It runs unelevated. The trailing marker shows that a POSIX
// shell ran the probe, which separates "neither executable is installed"
// from "the probe could not run", for example on a target without sh.
const ElevationProbeCommand = "sh -c 'command -v " + ElevationSudo + "; command -v " + ElevationDoas + "; echo " + elevationProbeMarker + "' < /dev/null"

// ParseElevationProbe reads the output of ElevationProbeCommand. It returns
// the executable to elevate with, preferring sudo when both are installed,
// and whether the probe ran to completion. An empty executable with
// probed == true means the target has neither sudo nor doas.
func ParseElevationProbe(stdout string) (executable string, probed bool) {
	var hasSudo, hasDoas bool
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == elevationProbeMarker {
			probed = true
			continue
		}
		switch path.Base(line) {
		case ElevationSudo:
			hasSudo = true
		case ElevationDoas:
			hasDoas = true
		}
	}
	switch {
	case hasSudo:
		return ElevationSudo, probed
	case hasDoas:
		return ElevationDoas, probed
	default:
		return "", probed
	}
}

// ResolveElevation picks the executable used to elevate commands. An
// executable configured in the inventory is kept as is. Otherwise the target
// is probed for sudo, then doas. When the probe shows that neither is
// installed, it returns an error: every command and file read would be
// prefixed with a missing executable, so no query could return correct data.
// When the probe cannot run at all, sudo is used as before.
//
// run must execute the command without elevation.
func ResolveElevation(sudo *inventory.Sudo, run func(string) (*Command, error)) error {
	if sudo.Executable != "" {
		return nil
	}

	var stdout []byte
	out, err := run(ElevationProbeCommand)
	if err == nil && out != nil {
		stdout, _ = io.ReadAll(out.Stdout)
	}

	executable, probed := ParseElevationProbe(string(stdout))
	switch {
	case executable != "":
		sudo.Executable = executable
	case probed:
		return errors.New("cannot elevate privileges: neither sudo nor doas is installed on the target")
	default:
		log.Debug().Msg("could not probe the target for sudo or doas, using sudo")
		sudo.Executable = ElevationSudo
	}
	return nil
}

var envAssignmentRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

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

func BuildSudoCommand(sudo *inventory.Sudo, cmd string) string {
	var sb strings.Builder

	if sudo == nil || !sudo.Active {
		return cmd
	}

	executable := sudo.Executable
	if executable == "" {
		executable = ElevationSudo
	}
	sb.WriteString(executable)

	if len(sudo.User) > 0 {
		sb.WriteString(" -u " + sudo.User)
	}

	if len(sudo.Shell) > 0 {
		// The shell parses leading VAR=value words itself, so doas needs no env here.
		sb.WriteString(" " + sudo.Shell + " -c " + cmd)
	} else {
		sb.WriteString(" ")
		// sudo treats leading VAR=value words as environment assignments;
		// doas would try to execute the first one as the command.
		if executable == ElevationDoas && envAssignmentRegex.MatchString(cmd) {
			sb.WriteString("env ")
		}
		sb.WriteString(cmd)
	}

	return sb.String()
}

type Wrapper interface {
	Build(cmd string) string
}
