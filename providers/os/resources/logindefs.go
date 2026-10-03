// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/logindefs"
)

func initLogindefs(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in logindefs initialization, it must be a string")
		}

		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")
		delete(args, "path")
	}

	return args, nil, nil
}

const (
	defaultLoginDefsConfig = "/etc/login.defs"
	vendorLoginDefsConfig  = "/usr/etc/login.defs"
)

func (s *mqlLogindefs) id() (string, error) {
	file := s.GetFile()
	if file.Data == nil {
		return "", errors.New("no file for logindefs")
	}
	return file.Data.Path.Data, nil
}

func (s *mqlLogindefs) file() (*mqlFile, error) {
	path := defaultLoginDefsConfig
	if conn, ok := s.MqlRuntime.Connection.(shared.Connection); ok {
		path = resolveVendorConfigPath(conn.FileSystem(), defaultLoginDefsConfig)
	}

	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// borrowed from ssh resource
func (s *mqlLogindefs) content(file *mqlFile) (string, error) {
	c := file.GetContent()
	return c.Data, c.Error
}

func (s *mqlLogindefs) params(content string) (map[string]any, error) {
	params := logindefs.Parse(strings.NewReader(content))

	if conn, ok := s.MqlRuntime.Connection.(shared.Connection); ok {
		file := s.GetFile()
		if file.Data != nil && isSystemLoginDefs(file.Data.Path.Data) {
			platform := conn.Asset().GetPlatform()
			fs := conn.FileSystem()
			// Elsewhere than SUSE, whether shadow reads drop-ins depends on its
			// build. Probe useradd only when there is a drop-in directory.
			econf := false
			if fs != nil && (platform == nil || !platform.IsFamily("suse")) {
				if _, err := fs.Stat(logindefs.EtcDropInDir); err == nil {
					econf = logindefs.ShadowLinksLibeconf(fs)
				}
			}
			mode := loginDefsDropInMode(platform, file.Data.Path.Data, econf)
			if mode != loginDefsNoDropIns {
				layers, err := s.dropInParams(fs, mode == loginDefsVendorAndEtcDropIns)
				if err != nil {
					return nil, err
				}
				params = logindefs.Overlay(append([]map[string]string{params}, layers...)...)
			}
		}
	}

	res := make(map[string]any, len(params))
	for k, v := range params {
		res[k] = v
	}
	return res, nil
}

// loginDefsDropIns says which login.defs.d directories the shadow tools read
// after the main login.defs.
type loginDefsDropIns int

const (
	// loginDefsNoDropIns: login.defs is read alone.
	loginDefsNoDropIns loginDefsDropIns = iota
	// loginDefsEtcDropIns: /etc/login.defs.d only. shadow built with libeconf
	// but without a vendor directory: RHEL 10, CentOS Stream 10, AlmaLinux 10
	// and Fedora 44 apply /etc/login.defs.d/*.defs and ignore
	// /usr/etc/login.defs.d, even when /usr/etc/login.defs exists.
	loginDefsEtcDropIns
	// loginDefsVendorAndEtcDropIns: /usr/etc/login.defs.d (when the vendor
	// login.defs exists), then /etc/login.defs.d. SUSE builds shadow with
	// libeconf and a vendor directory.
	loginDefsVendorAndEtcDropIns
)

func isSystemLoginDefs(mainPath string) bool {
	return mainPath == defaultLoginDefsConfig || mainPath == vendorLoginDefsConfig
}

// loginDefsDropInMode picks the drop-in directories the shadow tools read on
// top of mainPath. econf says whether useradd links libeconf. Debian and
// Ubuntu (through shadow 4.17) and RHEL 7 to 9 do not, so their useradd reads
// login.defs alone even when a login.defs.d directory exists. Drop-ins only
// extend the system login.defs, never a file passed by path.
func loginDefsDropInMode(platform *inventory.Platform, mainPath string, econf bool) loginDefsDropIns {
	if !isSystemLoginDefs(mainPath) {
		return loginDefsNoDropIns
	}
	if platform != nil && platform.IsFamily("suse") {
		return loginDefsVendorAndEtcDropIns
	}
	if econf {
		return loginDefsEtcDropIns
	}
	return loginDefsNoDropIns
}

// dropInParams parses the login.defs drop-ins in the order shadow applies
// them. The vendor drop-in directory is read only when withVendor is set and
// the vendor login.defs exists: SLES 15 and Leap 15 build shadow without a
// vendor directory and ignore /usr/etc/login.defs.d.
func (s *mqlLogindefs) dropInParams(fs afero.Fs, withVendor bool) ([]map[string]string, error) {
	if fs == nil {
		return nil, nil
	}

	var vendorNames []string
	if withVendor {
		if _, err := fs.Stat(vendorLoginDefsConfig); err == nil {
			names, err := loginDefsDropInNames(fs, logindefs.VendorDropInDir)
			if err != nil {
				return nil, err
			}
			vendorNames = names
		}
	}
	etcNames, err := loginDefsDropInNames(fs, logindefs.EtcDropInDir)
	if err != nil {
		return nil, err
	}

	var layers []map[string]string
	for _, p := range logindefs.DropInPaths(vendorNames, etcNames) {
		f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, err
		}
		content := f.(*mqlFile).GetContent()
		if content.Error != nil {
			return nil, fmt.Errorf("failed to read %s: %w", p, content.Error)
		}
		layers = append(layers, logindefs.Parse(strings.NewReader(content.Data)))
	}
	return layers, nil
}

// loginDefsDropInNames lists the entries of dir that are not directories. A missing directory has
// no drop-ins; one that cannot be read is an error, since its files may change
// the effective settings.
func loginDefsDropInNames(fs afero.Fs, dir string) ([]string, error) {
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
