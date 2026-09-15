// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/types"
)

var BsdCertFiles = []string{
	"/usr/local/etc/ssl/cert.pem",            // FreeBSD
	"/etc/ssl/cert.pem",                      // OpenBSD
	"/usr/local/share/certs/ca-root-nss.crt", // DragonFly
	"/etc/openssl/certs/ca-certificates.crt", // NetBSD
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
	if platform.IsFamily("linux") {
		paths = LinuxCertFiles
	} else if platform.IsFamily("bsd") {
		paths = BsdCertFiles
	} else {
		return nil, nil, errors.New("root certificates are not unsupported on this platform: " + platform.Name + " " + platform.Version)
	}

	// search the first file that exists, it mimics the behavior go is doing
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
			log.Trace().Err(err).Str("path", paths[i]).Msg("os.rootcertificates> file does not exist")
			continue
		}
		perm := file.GetPermissions()
		if perm.Error != nil {
			log.Trace().Err(err).Str("path", paths[i]).Msg("os.rootcertificates> failed to get permissions")
			continue
		}
		if !perm.Data.GetIsFile().Data {
			continue
		}

		files = append(files, file)
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
			return nil, content.Error
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
