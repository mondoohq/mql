// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
)

type Service struct {
	Name        string
	Description string
	State       State
	Type        string
	Installed   bool
	Running     bool
	Enabled     bool
	Masked      bool
	Static      bool
	Path        string
}

type State string

const (
	ServiceContinuePending State = "ServiceContinuePending"
	ServicePausePending    State = "ServicePausePending"
	ServicePaused          State = "ServicePaused"
	ServiceRunning         State = "ServiceRunning"
	ServiceStartPending    State = "ServiceStartPending"
	ServiceStopPending     State = "ServiceStopPending"
	ServiceStopped         State = "ServiceStopped"
	ServiceUnknown         State = "ServiceUnknown"
)

type OSServiceManager interface {
	Name() string
	List() ([]*Service, error)
	Get(name string) (*Service, error)
}

type serviceListLoader func() ([]*Service, error)

var ErrServiceNotFound = errors.New("service not found")

func NormalizeServiceLookupName(name string) string {
	return strings.TrimSuffix(name, ".service")
}

func serviceNotFound(name string) error {
	return fmt.Errorf("%w: %s", ErrServiceNotFound, name)
}

func getServiceFromList(name string, load serviceListLoader) (*Service, error) {
	services, err := load()
	if err != nil {
		return nil, err
	}

	return FindService(services, name)
}

type noopOsServiceManager struct{}

func (n *noopOsServiceManager) Name() string {
	return "none"
}

func (n *noopOsServiceManager) List() ([]*Service, error) {
	return nil, nil
}

func (n *noopOsServiceManager) Get(name string) (*Service, error) {
	return nil, serviceNotFound(name)
}

var amazonlinux1version = regexp.MustCompile(`^201\d`)

// initSystemPaths are the on-disk traces of an init system, in the order they
// are probed. /sbin/init alone is not enough to go on: Debian, Ubuntu, Fedora,
// openSUSE and Amazon Linux all ship systemd unit files in their images without
// shipping /sbin/init, and probing only that path put every one of them on the
// noop manager, which reports an empty service list rather than saying it could
// not look. A scan of such a target answered "no services" about a system whose
// units were sitting on disk unread.
var initSystemPaths = []string{
	"/sbin/init",
	// systemd, both the binary and the unit trees. The usr-merged and
	// non-merged layouts are both listed because /lib is only a symlink to
	// /usr/lib on some of them.
	"/usr/lib/systemd/systemd",
	"/lib/systemd/systemd",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/etc/systemd/system",
}

// hasInitSystem reports whether the target carries any init system this package
// knows how to read. It is deliberately a presence check rather than a decision
// about which manager applies: that choice belongs to the switch in
// ResolveManager, which keys off the platform.
func hasInitSystem(conn shared.Connection) bool {
	for _, path := range initSystemPaths {
		if _, err := conn.FileInfo(path); err == nil {
			return true
		}
	}
	return false
}

func ResolveManager(conn shared.Connection) (OSServiceManager, error) {
	var osm OSServiceManager

	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, errors.New("cannot find OS information for package detection")
	}

	useNoopInit := false
	if asset.Platform.IsFamily("linux") && !hasInitSystem(conn) {
		// Nothing on the target names an init system, so there are no managed
		// services to report. This happens in containers.
		useNoopInit = true
	}

	switch {
	case useNoopInit:
		osm = &noopOsServiceManager{}
	case asset.Platform.Name == "amazonlinux":
		if amazonlinux1version.MatchString(asset.Platform.Version) {
			osm = &UpstartServiceManager{SysVServiceManager{conn: conn}}
		} else {
			osm = ResolveSystemdServiceManager(conn)
		}
	// NOTE: we need to check fedora before rhel family, since its also rhel family
	case asset.Platform.Name == "fedora":
		rv := detector.ParseOsVersion(asset.Platform.Version)
		v, err := rv.MajorAtoi()
		if err != nil {
			return nil, errors.New("unknown fedora version: " + asset.Platform.Version)
		}

		if v < 15 {
			// upstart is only used since fedora 11 but we do not support those older versions
			osm = &UpstartServiceManager{SysVServiceManager{conn: conn}}
		} else {
			osm = ResolveSystemdServiceManager(conn)
		}
	case asset.Platform.IsFamily("redhat"):
		rv := detector.ParseOsVersion(asset.Platform.Version)
		v, err := rv.MajorAtoi()
		if err != nil {
			return nil, errors.New("unknown redhat version: " + asset.Platform.Version)
		}
		if v < 7 {
			osm = &UpstartServiceManager{SysVServiceManager{conn: conn}}
		} else {
			osm = ResolveSystemdServiceManager(conn)
		}
	case asset.Platform.Name == "ubuntu" || asset.Platform.Name == "linuxmint" || asset.Platform.Name == "pop":
		rv := detector.ParseOsVersion(asset.Platform.Version)
		v, err := rv.MajorAtoi()
		if err != nil {
			return nil, errors.New("unknown ubuntu version: " + asset.Platform.Version)
		}

		if v < 15 {
			osm = &UpstartServiceManager{SysVServiceManager{conn: conn}}
		} else {
			osm = ResolveSystemdServiceManager(conn)
		}
	case asset.Platform.Name == "debian":
		rv := detector.ParseOsVersion(asset.Platform.Version)
		v, err := rv.MajorAtoi()
		if err != nil {
			return nil, errors.New("unknown debian version: " + asset.Platform.Version)
		}

		if v < 7 {
			osm = &SysVServiceManager{conn: conn}
		} else {
			osm = ResolveSystemdServiceManager(conn)
		}
	case asset.Platform.Name == "suse-microos" || asset.Platform.Name == "opensuse-microos": // suse family but uses a different version scheme
		osm = ResolveSystemdServiceManager(conn)
	case asset.Platform.IsFamily("suse"):
		rv := detector.ParseOsVersion(asset.Platform.Version)
		v, err := rv.MajorAtoi()
		if err != nil {
			return nil, errors.New("unknown suse version: " + asset.Platform.Version)
		}

		// NOTE: opensuse-tumbleweed uses version numbers like 20200622
		if v < 12 {
			osm = &SysVServiceManager{conn: conn}
		} else {
			osm = ResolveSystemdServiceManager(conn)
		}
	case asset.Platform.IsFamily("darwin"): // "macos", "darwin"
		osm = &LaunchDServiceManager{conn: conn}
	case asset.Platform.Name == "freebsd" || asset.Platform.Name == "dragonflybsd":
		osm = &BsdInitServiceManager{conn: conn}
	case asset.Platform.Name == "netbsd":
		osm = &NetBsdServiceManager{conn: conn}
	case asset.Platform.Name == "openbsd":
		osm = &OpenBsdRcctlServiceManager{conn: conn}
	case asset.Platform.Name == "windows":
		osm = &WindowsServiceManager{conn: conn}
	case asset.Platform.Name == "alpine" || asset.Platform.Name == "wizos": // wizos is Alpine-based and uses OpenRC
		osm = &OpenrcServiceManager{conn: conn}
	case asset.Platform.Name == "gentoo":
		osm = &OpenrcServiceManager{conn: conn}
	case asset.Platform.Name == "aix":
		osm = &AixServiceManager{conn: conn}
	case asset.Platform.Name == "solaris":
		osm = &SolarisSmfServiceManager{conn: conn}
	case asset.Platform.IsFamily("linux"): // fallback for other linux distros which we assume are systemd
		osm = ResolveSystemdServiceManager(conn)
	}

	if osm == nil {
		return nil, errors.New("could not detect suitable service manager for platform: " + asset.Platform.Name)
	}

	return osm, nil
}

func FindService(services []*Service, name string) (*Service, error) {
	lookupName := NormalizeServiceLookupName(name)

	for i := range services {
		service := services[i]
		if service.Name == lookupName {
			return service, nil
		}
	}

	return nil, serviceNotFound(name)
}
