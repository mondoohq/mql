// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"io"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

const (
	sysctlPath      = "/proc/sys/"
	procModulesPath = "/proc/modules"
)

type KernelInfo struct {
	Version   string            `json:"version"`
	Path      string            `json:"path"`
	Device    string            `json:"device"`
	Arguments map[string]string `json:"args"`
}

type KernelModule struct {
	Name   string
	Size   string // int64
	UsedBy string // int
}

type OSKernelManager interface {
	Name() string
	Parameters() (map[string]string, error)
	Modules() ([]*KernelModule, error)
	Info() (KernelInfo, error)
}

func ResolveManager(conn shared.Connection) (OSKernelManager, error) {
	var kmm OSKernelManager

	platform := conn.Asset().Platform

	// check darwin before unix since darwin is also a unix
	if platform.IsFamily("darwin") {
		kmm = &OSXKernelManager{conn: conn}
	} else if platform.IsFamily("linux") {
		kmm = &LinuxKernelManager{conn: conn}
	} else if platform.IsFamily("bsd") {
		kmm = &BsdKernelManager{conn: conn}
	} else if platform.Name == "aix" {
		kmm = &AixKernelManager{conn: conn}
	}

	if kmm == nil {
		return nil, errors.New("could not detect suitable kernel module manager for platform: " + platform.Name)
	}

	return kmm, nil
}

type LinuxKernelManager struct {
	conn shared.Connection
}

func (s *LinuxKernelManager) Name() string {
	return "Linux Kernel Module Manager"
}

func (s *LinuxKernelManager) Info() (KernelInfo, error) {
	res := KernelInfo{}

	cmdlineRaw, err := s.conn.FileSystem().Open("/proc/cmdline")
	if err != nil {
		return res, err
	}
	defer cmdlineRaw.Close()

	args, err := ParseLinuxKernelArguments(cmdlineRaw)
	if err != nil {
		return res, err
	}
	res.Path = args.Path
	res.Device = args.Device
	res.Arguments = args.Arguments

	versionRaw, err := s.conn.FileSystem().Open("/proc/version")
	if err != nil {
		return res, err
	}
	defer versionRaw.Close()

	version, err := ParseLinuxKernelVersion(versionRaw)
	if err != nil {
		return res, err
	}

	res.Version = version

	return res, nil
}

func (s *LinuxKernelManager) Parameters() (map[string]string, error) {
	if s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		cmd, err := s.conn.RunCommand("/sbin/sysctl -a")
		// in case of err, the command is not there and we fallback to /proc/sys walking
		if err == nil && cmd.ExitStatus == 0 {
			log.Debug().Msg("using sysctl to read kernel parameters")
			return ParseSysctl(cmd.Stdout, "=")
		}
	}

	log.Debug().Msg("using /proc/sys walking to read kernel parameters")
	fs := s.conn.FileSystem()
	fsUtil := afero.Afero{Fs: fs}
	kernelParameters := make(map[string]string)
	err := fsUtil.Walk(sysctlPath, func(path string, f os.FileInfo, err error) error {
		if f != nil && !f.IsDir() {
			stat, err := s.conn.FileSystem().Stat(path)
			if err != nil {
				log.Error().Err(err)
				return nil
			}
			details := shared.FileModeDetails{
				FileMode: stat.Mode(),
			}
			if !details.UserReadable() {
				return nil
			}

			f, err := s.conn.FileSystem().Open(path)
			if err != nil {
				log.Error().Err(err)
				return err
			}

			content, err := io.ReadAll(f)
			if err != nil {
				log.Error().Err(err).Msg("cannot read content")
				return nil
			}
			// remove leading sysctl path
			k := strings.ReplaceAll(path, sysctlPath, "")
			k = strings.ReplaceAll(k, "/", ".")
			kernelParameters[k] = strings.TrimSpace(string(content))
		}
		return nil
	})

	return kernelParameters, err
}

func (s *LinuxKernelManager) Modules() ([]*KernelModule, error) {
	if s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		cmd, err := s.conn.RunCommand("/sbin/lsmod")
		// lsmod does not live in /sbin on every distro: Container-Optimized OS
		// ships it as /bin/lsmod and has an empty /sbin, so the command exits
		// 127 with no output. Nothing checked the exit status, so an empty
		// parse was reported as "no modules loaded" rather than as a failure,
		// and a policy asserting a module is absent passed without ever
		// reading the module list.
		//
		// Each way of missing is logged separately: a command that could not be
		// run at all and one that ran and failed are different problems on the
		// target, and from the fallback alone they look identical.
		switch {
		case err != nil:
			log.Debug().Err(err).Msg("could not run /sbin/lsmod, falling back to /proc/modules")
		case cmd.ExitStatus != 0:
			log.Debug().Int("exit", cmd.ExitStatus).
				Msg("/sbin/lsmod exited non-zero, falling back to /proc/modules")
		default:
			log.Debug().Msg("using lsmod to read kernel modules")
			return ParseLsmod(cmd.Stdout), nil
		}
	}

	// /proc/modules is the kernel's own interface, so it needs no binary on
	// PATH and works for a filesystem-only scan that cannot run commands at
	// all. Parameters() already falls back the same way onto /proc/sys.
	log.Debug().Msg("using /proc/modules to read kernel modules")
	f, err := s.conn.FileSystem().Open(procModulesPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not read kernel modules")
	}
	defer f.Close()

	return ParseLinuxProcModules(f), nil
}

type OSXKernelManager struct {
	conn shared.Connection
}

func (s *OSXKernelManager) Name() string {
	return "macOS Kernel Manager"
}

func (s *OSXKernelManager) Info() (KernelInfo, error) {
	cmd, err := s.conn.RunCommand("uname -r")
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read kernel parameters")
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read kernel parameters")
	}

	return KernelInfo{
		Version: strings.TrimSpace(string(data)),
	}, nil
}

func (s *OSXKernelManager) Parameters() (map[string]string, error) {
	cmd, err := s.conn.RunCommand("sysctl -a")
	if err != nil {
		return nil, errors.Wrap(err, "could not read kernel parameters")
	}

	return ParseSysctl(cmd.Stdout, ":")
}

func (s *OSXKernelManager) Modules() ([]*KernelModule, error) {
	cmd, err := s.conn.RunCommand("kextstat")
	if err != nil {
		return nil, errors.Wrap(err, "could not read kernel modules")
	}

	return ParseKextstat(cmd.Stdout), nil
}

type BsdKernelManager struct {
	conn shared.Connection
}

func (s *BsdKernelManager) Name() string {
	return "BSD Kernel Manager"
}

func (s *BsdKernelManager) Info() (KernelInfo, error) {
	// Use `uname -v` to get the kernel version
	cmd, err := s.conn.RunCommand("uname -v")
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read kernel version")
	}
	version, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read kernel version")
	}

	return KernelInfo{
		Version: strings.TrimSpace(string(version)),
	}, nil
}

func (s *BsdKernelManager) Parameters() (map[string]string, error) {
	cmd, err := s.conn.RunCommand("sysctl -a")
	if err != nil {
		return nil, errors.Wrap(err, "could not read kernel parameters")
	}

	platform := s.conn.Asset().Platform
	if platform.Name == "openbsd" {
		return ParseSysctl(cmd.Stdout, "=")
	} else {
		return ParseSysctl(cmd.Stdout, ":")
	}
}

func (s *BsdKernelManager) Modules() ([]*KernelModule, error) {
	platform := s.conn.Asset().Platform
	if platform.Name == "openbsd" {
		// openbsd does not support kernel modules, so we return an empty list
		return []*KernelModule{}, nil
	} else {
		// NOTE: kldstat is supported on freebsd variants so failures are possible
		cmd, err := s.conn.RunCommand("kldstat")
		if err != nil {
			return nil, errors.Wrap(err, "could not read kernel modules")
		}
		return ParseKldstat(cmd.Stdout), nil
	}
}

type AixKernelManager struct {
	conn shared.Connection
}

func (s *AixKernelManager) Name() string {
	return "AIX Kernel Manager"
}

func (s *AixKernelManager) Info() (KernelInfo, error) {
	// Use `oslevel -s` to get the kernel version
	cmd, err := s.conn.RunCommand("oslevel -s")
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read kernel version")
	}
	version, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read kernel version")
	}

	return KernelInfo{
		Version: strings.TrimSpace(string(version)),
	}, nil
}

func (s *AixKernelManager) Parameters() (map[string]string, error) {
	return map[string]string{}, nil
}

func (s *AixKernelManager) Modules() ([]*KernelModule, error) {
	cmd, err := s.conn.RunCommand("genkex")
	if err != nil {
		return nil, errors.Wrap(err, "could not read kernel modules")
	}

	return ParseGenkex(cmd.Stdout)
}
