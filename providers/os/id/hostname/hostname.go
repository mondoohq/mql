// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hostname

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/registry"
)

// Hostname returns the hostname of the system.

// On Linux systems we prefer `hostname -f` over `/etc/hostname` since systemd is not updating the value all the time.
// On Windows the `hostname` command (without the -f flag) works more reliable than `powershell -c "$env:computername"`
// since it will return a non-zero exit code.
// On BSD systems (FreeBSD, OpenBSD, NetBSD, DragonFlyBSD) we use `hostname` without the -f flag since BSD doesn't support it.
func Hostname(conn shared.Connection, pf *inventory.Platform) (string, bool) {
	if !pf.IsFamily(inventory.FAMILY_UNIX) && !pf.IsFamily(inventory.FAMILY_WINDOWS) {
		log.Debug().Msg("your platform is not supported for hostname detection")
		return "", false
	}

	// On unix systems we try to get the hostname via `hostname -f` first since it returns the fqdn.
	// However, BSD systems (FreeBSD, OpenBSD, NetBSD, DragonFlyBSD) don't support the -f flag,
	// so we skip this step for BSD systems (excluding Darwin/macOS which handles hostname differently).
	if pf.IsFamily(inventory.FAMILY_UNIX) && !isBSDWithoutDarwin(pf) {
		fqdn, err := runCommand(conn, "hostname -f")
		if err == nil && fqdn != "localhost" && fqdn != "" {
			return fqdn, true
		}
		log.Debug().Err(err).Msg("could not detect hostname via `hostname -f` command")

		// If the output of `hostname -f` is localhost, we try to fetch it via `getent hosts`,
		// start with the most common protocol IPv4.
		hostname, err := parseGetentHosts(conn, "127.0.0.1")
		if err == nil && hostname != "" {
			return hostname, true
		}
		log.Debug().Err(err).Str("ipversion", "IPv4").Msg("could not detect hostname")

		// When IPv4 is not configured, try IPv6.
		hostname, err = parseGetentHosts(conn, "::1")
		if err == nil && hostname != "" {
			return hostname, true
		}
		log.Debug().Err(err).Str("ipversion", "IPv6").Msg("could not detect hostname")
	}

	// On local Windows, resolve in-process to avoid spawning `powershell -c hostname`.
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		if hn, err := os.Hostname(); err == nil {
			if hn = strings.TrimSpace(hn); hn != "" {
				return hn, true
			}
		} else {
			log.Debug().Err(err).Msg("could not resolve hostname via os.Hostname, falling back to command")
		}
	}

	// This is the preferred way to get the hostname on windows, it is important to not use the -f flag here
	hostname, err := runCommand(conn, "hostname")
	if err == nil && hostname != "" {
		return hostname, true
	}
	log.Debug().Err(err).Msg("could not run `hostname` command")

	// Fallback for unix systems to the hostname files on disk, since the hostname
	// command is not available on all systems. This is also the only mechanism left
	// for static analysis: a mounted host root, a container image or a volume
	// snapshot has no command execution at all.
	if pf.IsFamily(inventory.FAMILY_LINUX) {
		afs := &afero.Afero{Fs: conn.FileSystem()}
		for _, src := range linuxHostnameFiles {
			content, err := afs.ReadFile(src.path)
			if err != nil {
				log.Debug().Err(err).Str("file", src.path).Msg("could not read hostname file")
				continue
			}

			if hn := src.parse(string(content)); hn != "" {
				return hn, true
			}
			log.Debug().Str("file", src.path).Msg("hostname file carries no hostname")
		}
	}

	// Fallback for windows systems to using registry for static analysis
	if pf.IsFamily(inventory.FAMILY_WINDOWS) && conn.Capabilities().Has(shared.Capability_FileSearch) {
		fi, err := conn.FileInfo(registry.SystemRegPath)
		if err != nil {
			log.Debug().Err(err).Msg("could not find SYSTEM registry file, cannot perform hostname lookup")
			return "", false
		}

		rh := registry.NewRegistryHandler()
		defer func() {
			err := rh.UnloadSubkeys()
			if err != nil {
				log.Debug().Err(err).Msg("could not unload registry subkeys")
			}
		}()
		err = rh.LoadSubkey(registry.System, fi.Path)
		if err != nil {
			log.Debug().Err(err).Msg("could not load SYSTEM registry key file")
			return "", false
		}
		key, err := rh.GetRegistryItemValue(registry.System, "ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName")
		if err == nil {
			return key.Value.String, true
		}

		// we also can try ControlSet002 as a fallback
		log.Debug().Err(err).Msg("unable to read windows registry, trying ControlSet002 fallback")
		key, err = rh.GetRegistryItemValue(registry.System, "ControlSet002\\Control\\ComputerName\\ComputerName", "ComputerName")
		if err == nil {
			return key.Value.String, true
		}
	}

	return "", false
}

// hostnameFile is an on-disk source that carries the system's hostname. parse
// returns the hostname the file names, or an empty string when it names none. An
// empty /etc/hostname is a real occurrence, and it has to fall through to the
// next source rather than resolve the hostname to "".
type hostnameFile struct {
	path  string
	parse func(content string) string
}

// linuxHostnameFiles lists the files consulted for the hostname, in order of
// preference.
//
// Reading the kernel value from /proc/sys/kernel/hostname is deliberately not
// among them. That sysctl is not stored data: its handler resolves the value
// against the UTS namespace of the calling process, so a scanner reading a
// bind-mounted host root gets its own hostname back rather than the host's.
var linuxHostnameFiles = []hostnameFile{
	{path: "/etc/hostname", parse: parseEtcHostname},
	// Bottlerocket never writes /etc/hostname. Its netdog sets only the kernel
	// hostname, and the environment file that set-hostname.service reads before
	// doing so is the on-disk copy of that value.
	{path: "/etc/network/hostname.env", parse: parseHostnameEnv},
	// The file twin of the `getent hosts` lookup above, for when no command can be
	// run. Bottlerocket renders the hostname into its loopback aliases, and
	// Debian-family systems traditionally carry it on the 127.0.1.1 line.
	{path: "/etc/hosts", parse: parseEtcHosts},
}

// parseEtcHostname returns the hostname an /etc/hostname file names. Per
// hostname(5) the file holds a single name; blank lines and comments are skipped
// because systemd's own parser tolerates them.
func parseEtcHostname(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}

// parseHostnameEnv returns the value of the HOSTNAME variable of a systemd
// EnvironmentFile, which is the shape Bottlerocket renders to
// /etc/network/hostname.env.
func parseHostnameEnv(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "HOSTNAME" {
			continue
		}

		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		return strings.TrimSpace(value)
	}
	return ""
}

// parseEtcHosts returns the first name mapped to a loopback address by an
// /etc/hosts file that is not a variant of "localhost". Only loopback entries
// are considered: any other line is as likely to name a different machine as it
// is to name this one.
func parseEtcHosts(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		if ip := net.ParseIP(fields[0]); ip == nil || !ip.IsLoopback() {
			continue
		}

		if host := firstNonLocalhost(fields[1:]); host != "" {
			return host
		}
	}
	return ""
}

// runCommand is a wrapper around shared.Connection.RunCommand that helps execute commands
// and read the standard output all in one function.
func runCommand(conn shared.Connection, commandString string) (string, error) {
	cmd, err := conn.RunCommand(commandString)
	if err != nil {
		return "", err
	}

	if cmd.ExitStatus != 0 {
		outErr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("failed to run command: %s", outErr)
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// parseGetentHosts runs `getent hosts <address>` and returns the first valid hostname
// that is not a variant of "localhost".
func parseGetentHosts(conn shared.Connection, ip string) (string, error) {
	output, err := runCommand(conn, fmt.Sprintf("getent hosts %s", ip))
	if err != nil {
		return "", err
	}

	fields := strings.Fields(output)

	if len(fields) < 2 {
		return "", fmt.Errorf("no hostnames found for IP %s", ip)
	}

	if host := firstNonLocalhost(fields[1:]); host != "" {
		return host, nil
	}

	return "", fmt.Errorf("no non-localhost hostname found for IP %s", ip)
}

// firstNonLocalhost returns the first name in a hosts entry's alias list that is
// not a variant of "localhost", or an empty string when every alias is one.
func firstNonLocalhost(hosts []string) string {
	for _, host := range hosts {
		if !isLocalhostVariant(host) {
			return host
		}
	}
	return ""
}

// isLocalhostVariant returns true if the given hostname is a variant of
// "localhost". The protocol-suffixed forms matter: RHEL-family systems and
// Bottlerocket both map 127.0.0.1 to "localhost localhost.localdomain localhost4
// localhost4.localdomain4", so a lookup that only knew the unsuffixed names
// answered "localhost4" where it should have kept looking.
func isLocalhostVariant(host string) bool {
	lh := strings.ToLower(host)
	if lh == "ip6-localhost" || lh == "ip6-loopback" {
		return true
	}

	name, domain, hasDomain := strings.Cut(lh, ".")
	if name != "localhost" && name != "localhost4" && name != "localhost6" {
		return false
	}
	if !hasDomain {
		return true
	}
	return domain == "localdomain" || domain == "localdomain4" || domain == "localdomain6"
}

// isBSDWithoutDarwin returns true if the platform is a BSD system but not Darwin/macOS.
// BSD systems like FreeBSD, OpenBSD, NetBSD, and DragonFlyBSD don't support `hostname -f`.
func isBSDWithoutDarwin(pf *inventory.Platform) bool {
	return pf.IsFamily(inventory.FAMILY_BSD) && !pf.IsFamily(inventory.FAMILY_DARWIN)
}
