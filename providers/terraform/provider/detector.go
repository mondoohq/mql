// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/terraform/connection"
	"go.mondoo.com/mql/utils/urlx"
)

func (s *Service) detect(asset *inventory.Asset, _ *connection.Connection) error {
	var name string
	var techSegments []string
	connType := asset.Connections[0].Type
	switch connType {
	case StateConnectionType:
		name = "terraform-state"
		techSegments = []string{"iac", "terraform", "state"}
	case PlanConnectionType:
		name = "terraform-plan"
		techSegments = []string{"iac", "terraform", "plan"}
	case HclConnectionType:
		fallthrough
	default:
		name = "terraform-hcl"
		techSegments = []string{"iac", "terraform", "hcl"}
	}
	platform := PlatformByName(name)
	p := &inventory.Platform{TechnologyUrlSegments: techSegments}
	platform.Apply(p)
	asset.MergePlatform(p)

	// name the asset after what was actually connected to, so a plan file does not
	// get announced as HCL
	titlePrefix := platform.Title + " "

	// we always prefer the git url since it is more reliable
	url, ok := asset.Connections[0].Options["ssh-url"]
	if ok {
		domain, org, repo, err := urlx.ParseGitSshUrl(url)
		if err != nil {
			return err
		}
		platformID := "//platformid.api.mondoo.app/runtime/terraform/domain/" + domain + "/org/" + org + "/repo/" + repo
		if len(asset.PlatformIds) == 0 {
			asset.PlatformIds = []string{platformID}
		}
		asset.Connections[0].PlatformId = asset.PlatformIds[0]
		asset.Name = titlePrefix + org + "/" + repo
		return nil
	}

	projectPath, ok := asset.Connections[0].Options["path"]
	if ok {
		absPath, _ := filepath.Abs(projectPath)
		h := sha256.New()
		h.Write([]byte(absPath))
		hash := hex.EncodeToString(h.Sum(nil))
		platformID := "//platformid.api.mondoo.app/runtime/terraform/hash/" + hash
		if len(asset.PlatformIds) == 0 {
			asset.PlatformIds = []string{platformID}
		}
		asset.Connections[0].PlatformId = asset.PlatformIds[0]
		asset.Name = titlePrefix + parseNameFromPath(projectPath)
		return nil
	}

	return errors.New("could not determine platform id for Terraform asset")
}

func parseNameFromPath(file string) string {
	// if it is a local file (which may not be true)
	name := ""
	fi, err := os.Stat(file)
	if err == nil {
		if fi.IsDir() && fi.Name() != "." {
			name = "directory " + fi.Name()
		} else if fi.IsDir() {
			name = fi.Name()
		} else {
			name = filepath.Base(fi.Name())
			extension := filepath.Ext(name)
			name = strings.TrimSuffix(name, extension)
		}
	} else {
		// it is not a local file, so we try to be a bit smart
		name = path.Base(file)
		extension := path.Ext(name)
		name = strings.TrimSuffix(name, extension)
	}

	// if the path is . we read the current directory
	if name == "." {
		abspath, err := filepath.Abs(name)
		if err == nil {
			name = parseNameFromPath(abspath)
		}
	}

	return name
}
