// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"io"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func NewOSReleaseDetector(conn shared.Connection) *OSReleaseDetector {
	return &OSReleaseDetector{
		provider: conn,
	}
}

type OSReleaseDetector struct {
	provider shared.Connection
}

func (d *OSReleaseDetector) command(command string) (string, error) {
	cmd, err := d.provider.RunCommand(command)
	if err != nil {
		log.Debug().Err(err).Msg("could not execute os release detection command")
		return "", err
	}

	content, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(content)), nil
}

// UNIX helper methods
//
// Each falls back to the kernel's own answer when the command cannot run, as
// in a distroless or scratch image that ships no shell and no uname. That
// fallback is only taken on a local connection: there the scanner runs on the
// target's kernel, so /proc/sys/kernel and the scanner's own build answer for
// the target.

// operating system name
func (d *OSReleaseDetector) unames() (string, error) {
	out, err := d.command("uname -s")
	if (err != nil || out == "") && d.provider.Type() == shared.Type_Local {
		if v := d.procKernel("ostype"); v != "" {
			return v, nil
		}
	}
	return out, err
}

// operating system release
func (d *OSReleaseDetector) unamer() (string, error) {
	out, err := d.command("uname -r")
	if (err != nil || out == "") && d.provider.Type() == shared.Type_Local {
		if v := d.procKernel("osrelease"); v != "" {
			return v, nil
		}
	}
	return out, err
}

// machine hardware name
func (d *OSReleaseDetector) unamem() (string, error) {
	out, err := d.command("uname -m")
	if (err != nil || out == "") && d.provider.Type() == shared.Type_Local && localGOOS == "linux" {
		if v := unameMachine(localGOARCH); v != "" {
			return v, nil
		}
	}
	return out, err
}

// localGOOS and localGOARCH are the scanner's own build, which is the
// target's on a local connection. Tests replace them.
var (
	localGOOS   = runtime.GOOS
	localGOARCH = runtime.GOARCH
)

// procKernel reads /proc/sys/kernel/<name>, the value uname reports for it.
func (d *OSReleaseDetector) procKernel(name string) string {
	f, err := d.provider.FileSystem().Open("/proc/sys/kernel/" + name)
	if err != nil {
		return ""
	}
	defer f.Close()
	content, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

// unameMachine spells a Go architecture the way `uname -m` does on Linux.
// 32-bit arm is left out: uname names the ISA revision (armv6l, armv7l),
// which GOARCH does not carry.
func unameMachine(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i686"
	case "ppc64le", "ppc64", "s390x", "riscv64":
		return goarch
	case "loong64":
		return "loongarch64"
	}
	return ""
}

// osrelease reads /etc/os/release and parses the file
// NAME="Ubuntu"
// VERSION="16.04.3 LTS (Xenial Xerus)"
// ID=ubuntu
// ID_LIKE=debian
// PRETTY_NAME="Ubuntu 16.04.3 LTS"
// VERSION_ID="16.04"
// HOME_URL="http://www.ubuntu.com/"
// SUPPORT_URL="http://help.ubuntu.com/"
// BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
// VERSION_CODENAME=xenial
// UBUNTU_CODENAME=xenial
func (d *OSReleaseDetector) osrelease() (map[string]string, error) {
	// Per the freedesktop os-release spec, /etc/os-release takes precedence
	// but /usr/lib/os-release should be used as a fallback. This is important
	// for systems like Bottlerocket where /etc is an overlay and /etc/os-release
	// only exists in the overlay upper layer, not on the raw root partition.
	f, err := d.provider.FileSystem().Open("/etc/os-release")
	if err != nil {
		f, err = d.provider.FileSystem().Open("/usr/lib/os-release")
		if err != nil {
			return nil, err
		}
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return ParseOsRelease(string(content))
}

func (d *OSReleaseDetector) imagerelease() (map[string]string, error) {
	f, err := d.provider.FileSystem().Open("/etc/image-release")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return ParseImageRelease(string(content))
}

// lsbconfig reads /etc/lsb-release and parses the file
// DISTRIB_ID=Ubuntu
// DISTRIB_RELEASE=16.04
// DISTRIB_CODENAME=xenial
// DISTRIB_DESCRIPTION="Ubuntu 16.04.3 LTS"
// lsb release is not the default on newer systems, but can still be used
// as a fallback mechanism
func (d *OSReleaseDetector) lsbconfig() (map[string]string, error) {
	f, err := d.provider.FileSystem().Open("/etc/lsb-release")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return ParseLsbRelease(string(content))
}

// darwin_swversion will call `/usr/bin/sw_vers` to identify the
// version of darwin. A common output would be:
// ```                                                                                                                  3d master[97c5c29]
// ProductName:	Mac OS X
// ProductVersion:	10.13.2
// BuildVersion:	17C88
// ````
func (d *OSReleaseDetector) darwin_swversion() (map[string]string, error) {
	content, err := d.command("/usr/bin/sw_vers")
	if err != nil {
		return nil, err
	}
	return ParseDarwinRelease(content)
}

var majorminor = regexp.MustCompile(`^(\d+)(?:.(\d*)){0,1}(?:.(.*)){0,1}`)

type ReleaseVersion struct {
	Major string
	Minor string
	Other string
}

func (v ReleaseVersion) MajorAtoi() (int, error) {
	return strconv.Atoi(v.Major)
}

func ParseOsVersion(v string) ReleaseVersion {
	m := majorminor.FindStringSubmatch(v)
	if len(m) == 0 {
		return ReleaseVersion{Major: v}
	}

	return ReleaseVersion{Major: m[1], Minor: m[2], Other: m[3]}
}
