// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

var BsdCertFiles = []string{
	"/usr/local/etc/ssl/cert.pem",            // FreeBSD
	"/etc/ssl/cert.pem",                      // OpenBSD
	"/usr/local/share/certs/ca-root-nss.crt", // DragonFly
	"/etc/openssl/certs/ca-certificates.crt", // NetBSD
}

// The bundle paths Go's crypto/x509 reads on Solaris and illumos.
var SolarisCertFiles = []string{
	"/etc/certs/ca-certificates.crt",     // Solaris 11.2+
	"/etc/ssl/certs/ca-certificates.crt", // Joyent SmartOS
	"/etc/ssl/cacert.pem",                // OmniOS
}

var LinuxCertFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}

var LinuxCertDirectories = []string{
	"/etc/ssl/certs",               // SLES10/SLES11, https://go.dev/issue/12139
	"/system/etc/security/cacerts", // Android
	"/usr/local/share/certs",       // FreeBSD
	"/etc/pki/tls/certs",           // Fedora/RHEL
	"/etc/openssl/certs",           // NetBSD
	"/var/ssl/certs",               // AIX
}

func (s *mqlOsRootCertificates) id() (string, error) {
	return "osrootcertificates", nil
}

func initOsRootCertificates(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	var paths []string
	// Solaris 11.4 ships /etc/os-release and is detected into the linux
	// family, so it is matched by name first.
	if platform.Name == "solaris" {
		paths = SolarisCertFiles
	} else if platform.IsFamily("linux") {
		paths = LinuxCertFiles
	} else if platform.IsFamily("bsd") {
		paths = BsdCertFiles
	} else {
		return nil, nil, errors.New("root certificates are not supported on this platform: " + platform.Name + " " + platform.Version)
	}

	// Take the first bundle that exists, which is what Go's own root pool does.
	// Collecting every path that exists instead would count one bundle several
	// times over: on RHEL 9 all three of /etc/pki/tls/certs/ca-bundle.crt,
	// /etc/ssl/cert.pem and /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
	// are the same 146 certificates, two of them by symlink.
	files := []any{}
	for i := range paths {
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(paths[i]),
		})
		if err != nil {
			return nil, nil, err
		}

		file := f.(*mqlFile)
		if !file.GetExists().Data {
			log.Trace().Str("path", paths[i]).Msg("os.rootcertificates> file does not exist")
			continue
		}
		perm := file.GetPermissions()
		if perm.Error != nil {
			log.Trace().Err(perm.Error).Str("path", paths[i]).Msg("os.rootcertificates> failed to get permissions")
			continue
		}
		// A directory is not a bundle. Anything else is: the permissions come
		// from an lstat, so the canonical bundle path being a symlink -- which
		// it is on every SUSE, where /etc/ssl/ca-bundle.pem points into
		// /var/lib/ca-certificates -- must not be mistaken for "not a file".
		// Requiring isFile reported zero trusted roots on all of SLES 12, 15
		// and 16 and openSUSE Leap, which reads as a host that trusts nothing.
		if perm.Data.GetIsDirectory().Data {
			continue
		}

		files = append(files, file)
		break
	}

	args["files"] = llx.ArrayData(files, types.Resource("file"))

	return args, nil, nil
}

func (s *mqlOsRootCertificates) content(files []any) ([]any, error) {
	contents := []any{}

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			// a bundle we cannot read is one bundle's worth of certificates
			// missing, not a reason to report none at all
			log.Warn().Err(content.Error).Str("path", file.Path.Data).
				Msg("os.rootcertificates> could not read certificate bundle")
			continue
		}
		contents = append(contents, content.Data)
	}

	return contents, nil
}

// certificatesField creates the shared certificates resource for one trust-store
// file and reads a single field off it.
func (p *mqlOsRootCertificates) certificatesField(content string, field string) (*llx.RawData, error) {
	certificates, err := p.MqlRuntime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(content),
	})
	if err != nil {
		return nil, err
	}

	data, err := p.MqlRuntime.GetSharedData("certificates", certificates.MqlID(), field)
	if err != nil {
		return nil, err
	}
	if data.Error != nil {
		return nil, data.Error
	}

	return data, nil
}

// unparseable reports how many certificate blocks across all trust-store files
// could not be decoded. The blocks are skipped so the rest of the store still
// resolves, and this count is what tells a policy the list is incomplete.
func (p *mqlOsRootCertificates) unparseable(contents []any) (int64, error) {
	var total int64
	for i := range contents {
		content, ok := contents[i].(string)
		if !ok {
			continue
		}

		data, err := p.certificatesField(content, "unparseable")
		if err != nil {
			return 0, err
		}

		skipped, ok := data.Value.(int64)
		if !ok {
			continue
		}
		total += skipped
	}

	return total, nil
}

func (p *mqlOsRootCertificates) list(contents []any) ([]any, error) {
	var res []any
	for i := range contents {
		content, ok := contents[i].(string)
		if !ok {
			continue
		}

		list, err := p.certificatesField(content, "list")
		if err != nil {
			return nil, err
		}

		certs, ok := list.Value.([]any)
		if !ok {
			continue
		}
		res = append(res, certs...)
	}

	return res, nil
}
