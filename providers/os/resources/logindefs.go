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
		if file.Data != nil && readsLoginDefsDropIns(conn.Asset().GetPlatform(), file.Data.Path.Data) {
			layers, err := s.dropInParams(conn.FileSystem())
			if err != nil {
				return nil, err
			}
			params = logindefs.Overlay(append([]map[string]string{params}, layers...)...)
		}
	}

	res := make(map[string]any, len(params))
	for k, v := range params {
		res[k] = v
	}
	return res, nil
}

// readsLoginDefsDropIns reports whether the shadow tools on the platform read
// login.defs.d drop-ins on top of mainPath. SUSE builds shadow with libeconf,
// which reads /etc/login.defs.d/*.defs (and /usr/etc/login.defs.d on releases
// with a vendor directory) after the main file. Debian, Ubuntu and RHEL do
// not: Debian's shadow has no libeconf build dependency, so its useradd reads
// login.defs alone even when a login.defs.d directory exists. Drop-ins only
// extend the system login.defs, never a file passed by path.
func readsLoginDefsDropIns(platform *inventory.Platform, mainPath string) bool {
	if platform == nil || !platform.IsFamily("suse") {
		return false
	}
	return mainPath == defaultLoginDefsConfig || mainPath == vendorLoginDefsConfig
}

// dropInParams parses the login.defs drop-ins in the order shadow applies
// them. The vendor drop-in directory is read only when the vendor login.defs
// exists: SLES 15 and Leap 15 build shadow without a vendor directory and
// ignore /usr/etc/login.defs.d.
func (s *mqlLogindefs) dropInParams(fs afero.Fs) ([]map[string]string, error) {
	if fs == nil {
		return nil, nil
	}

	var vendorNames []string
	if _, err := fs.Stat(vendorLoginDefsConfig); err == nil {
		names, err := loginDefsDropInNames(fs, logindefs.VendorDropInDir)
		if err != nil {
			return nil, err
		}
		vendorNames = names
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
