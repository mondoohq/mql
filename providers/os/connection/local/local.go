// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package local

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type LocalConnection struct {
	plugin.Connection
	shell []string
	fs    afero.Fs
	Sudo  *inventory.Sudo
	asset *inventory.Asset

	// registryHandler lazily loads per-user registry hives (NTUSER.DAT) on
	// Windows so resources can read another user's HKCU without an active
	// session. Loaded hives are unloaded in Close().
	registryHandler     *registry.RegistryHandler
	registryHandlerLock sync.Mutex
}

// UserHiveRegistryHandler returns the connection-scoped RegistryHandler used to
// load and read per-user registry hives, creating it on first use. Hives loaded
// through it stay loaded for the lifetime of the connection (so repeated reads
// across many checks share a single `reg load`) and are unloaded in Close().
func (p *LocalConnection) UserHiveRegistryHandler() *registry.RegistryHandler {
	p.registryHandlerLock.Lock()
	defer p.registryHandlerLock.Unlock()
	if p.registryHandler == nil {
		p.registryHandler = registry.NewRegistryHandler()
	}
	return p.registryHandler
}

// Close unloads any per-user registry hives loaded during the scan. It satisfies
// the plugin.Closer interface and is invoked when the provider shuts down the
// connection.
func (p *LocalConnection) Close() {
	p.registryHandlerLock.Lock()
	defer p.registryHandlerLock.Unlock()
	if p.registryHandler != nil {
		if err := p.registryHandler.UnloadSubkeys(); err != nil {
			log.Debug().Err(err).Msg("could not unload user registry hives")
		}
		p.registryHandler = nil
	}
}

func NewConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) *LocalConnection {
	// expect unix shell by default
	res := LocalConnection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
	}
	if conf != nil {
		res.Sudo = conf.Sudo
	}

	if runtime.GOOS == "windows" {
		// It does not make any sense to use cmd as default shell
		// shell = []string{"cmd", "/C"}
		res.shell = []string{"powershell", "-c"}
	} else {
		res.shell = []string{"sh", "-c"}
	}

	return &res
}

func (p *LocalConnection) Name() string {
	return "local"
}

func (p *LocalConnection) Type() shared.ConnectionType {
	return shared.Type_Local
}

func (p *LocalConnection) Asset() *inventory.Asset {
	return p.asset
}

func (p *LocalConnection) UpdateAsset(asset *inventory.Asset) {
	p.asset = asset
}

func (p *LocalConnection) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}

func (p *LocalConnection) RunCommand(command string) (*shared.Command, error) {
	if p.Sudo != nil {
		command = shared.BuildSudoCommand(p.Sudo, command)
	}
	log.Debug().Msgf("local> run command %s", command)
	c := &CommandRunner{Shell: p.shell}
	args := []string{}

	res, err := c.Exec(command, args)
	powershell.DecodeStderr(res)
	return res, err
}

func (p *LocalConnection) FileSystem() afero.Fs {
	if p.fs != nil {
		return p.fs
	}

	if p.Sudo != nil && p.Sudo.Active {
		p.fs = cat.New(p)
	} else {
		p.fs = afero.NewOsFs()
	}

	return p.fs
}

func (p *LocalConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	fs := p.FileSystem()
	afs := &afero.Afero{Fs: fs}

	// Use Lstat as the primary call — for non-symlinks it returns the same
	// result as Stat with no extra cost. For symlinks we detect the type
	// here and call Stat once more to get the target's metadata.
	lstater, hasLstat := fs.(afero.Lstater)
	if hasLstat {
		linfo, _, err := lstater.LstatIfPossible(path)
		if err != nil {
			return shared.FileInfoDetails{}, err
		}

		if linfo.Mode()&os.ModeSymlink != 0 {
			stat, err := afs.Stat(path)
			if err != nil {
				if !os.IsNotExist(err) {
					return shared.FileInfoDetails{}, err
				}
				// Dangling symlink: target doesn't exist, use lstat info.
				uid, gid := p.fileowner(linfo)
				return shared.FileInfoDetails{
					Mode: shared.FileModeDetails{FileMode: linfo.Mode()},
					Size: linfo.Size(),
					Uid:  uid,
					Gid:  gid,
				}, nil
			}
			uid, gid := p.fileowner(stat)
			return shared.FileInfoDetails{
				Mode: shared.FileModeDetails{FileMode: stat.Mode() | os.ModeSymlink},
				Size: stat.Size(),
				Uid:  uid,
				Gid:  gid,
			}, nil
		}

		// Not a symlink — lstat result is the final answer.
		uid, gid := p.fileowner(linfo)
		return shared.FileInfoDetails{
			Mode: shared.FileModeDetails{FileMode: linfo.Mode()},
			Size: linfo.Size(),
			Uid:  uid,
			Gid:  gid,
		}, nil
	}

	// Fallback for filesystems without Lstat (e.g. cat).
	stat, err := afs.Stat(path)
	if err != nil {
		return shared.FileInfoDetails{}, err
	}
	uid, gid := p.fileowner(stat)
	return shared.FileInfoDetails{
		Mode: shared.FileModeDetails{FileMode: stat.Mode()},
		Size: stat.Size(),
		Uid:  uid,
		Gid:  gid,
	}, nil
}

type CommandRunner struct {
	shared.Command
	cmdExecutor *exec.Cmd
	Shell       []string
}

func (c *CommandRunner) Exec(usercmd string, args []string) (*shared.Command, error) {
	c.Stats.Start = time.Now()

	var cmd string
	cmdArgs := []string{}

	// When the default shell is PowerShell and the command is already a
	// self-contained PowerShell invocation (as produced by powershell.Encode /
	// powershell.Wrap), run it directly. Otherwise it would be nested inside a
	// second `powershell -c "..."`, spawning a redundant powershell.exe that
	// endpoint protection flags as an encoded-command / LOLBIN-chain attack.
	if argv, ok := unnestPowershell(c.Shell, usercmd); ok {
		cmd = argv[0]
		cmdArgs = append(cmdArgs, argv[1:]...)
	} else if len(c.Shell) > 0 {
		shellCommand, shellArgs := c.Shell[0], c.Shell[1:]
		cmd = shellCommand
		cmdArgs = append(cmdArgs, shellArgs...)
		cmdArgs = append(cmdArgs, usercmd)
	} else {
		cmd = usercmd
	}
	cmdArgs = append(cmdArgs, args...)

	// this only stores the user command, not the shell
	c.Command.Command = usercmd + " " + strings.Join(args, " ")
	c.cmdExecutor = exec.Command(cmd, cmdArgs...)

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer

	// create buffered stream
	c.Stdout = &stdoutBuffer
	c.Stderr = &stderrBuffer

	c.cmdExecutor.Stdout = c.Stdout
	c.cmdExecutor.Stderr = c.Stderr

	err := c.cmdExecutor.Run()
	c.Stats.Duration = time.Since(c.Stats.Start)

	// command completed successfully, great :-)
	if err == nil {
		return &c.Command, nil
	}

	// if the program failed, we do not return err but its exit code
	if exiterr, ok := err.(*exec.ExitError); ok {
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			c.ExitStatus = status.ExitStatus()
		}
		return &c.Command, nil
	}

	// all other errors are real errors and not expected
	return &c.Command, err
}

// unnestPowershell returns the argv to run usercmd directly, without wrapping
// it in the shell, when both the shell and the command are PowerShell. This
// avoids spawning powershell.exe inside powershell.exe. It only fires for the
// PowerShell shell (Windows local default) so unix `sh -c` behavior and plain
// commands (e.g. `hostname`) are untouched.
func unnestPowershell(shell []string, usercmd string) ([]string, bool) {
	if len(shell) == 0 {
		return nil, false
	}
	switch strings.ToLower(shell[0]) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return powershell.SplitInvocation(usercmd)
	default:
		return nil, false
	}
}
