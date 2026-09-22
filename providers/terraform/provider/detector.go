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

func (s *Service) detect(asset *inventory.Asset, conn *connection.Connection) error {
	// The dialect selects between the terraform-* and opentofu-* platforms. For
	// HCL it was detected from the files on disk; for state and plan files it
	// comes from the connector the user invoked.
	dialect := connection.DialectTerraform
	if conn != nil {
		dialect = conn.Dialect()
	}
	tool := string(dialect)

	var kind string
	connType := asset.Connections[0].Type
	switch connType {
	case StateConnectionType:
		kind = "state"
	case PlanConnectionType:
		kind = "plan"
	case HclConnectionType:
		fallthrough
	default:
		kind = "hcl"
	}

	name := tool + "-" + kind
	// The asset URL tree is keyed on the terraform category for both tools, so
	// that OpenTofu assets stay grouped with the Terraform ones they are
	// interchangeable with.
	techSegments := []string{"iac", "terraform", kind}

	p := &inventory.Platform{TechnologyUrlSegments: techSegments}
	PlatformByName(name).Apply(p)
	asset.MergePlatform(p)

	// we always prefer the git url since it is more reliable
	url, ok := asset.Connections[0].Options["ssh-url"]
	if ok {
		domain, org, repo, err := urlx.ParseGitSshUrl(url)
		if err != nil {
			return err
		}
		// NOTE: the platform ID deliberately stays on the terraform runtime for
		// both tools. It identifies the repository, not the tool applying it, so
		// a project that migrates from Terraform to OpenTofu stays the same
		// asset and keeps its history rather than forking into a second one.
		platformID := "//platformid.api.mondoo.app/runtime/terraform/domain/" + domain + "/org/" + org + "/repo/" + repo
		if len(asset.PlatformIds) == 0 {
			asset.PlatformIds = []string{platformID}
		}
		asset.Connections[0].PlatformId = asset.PlatformIds[0]
		// Only name an asset that has no name. A caller who passed --asset-name
		// has already named this asset, and detection running afterwards must
		// not take that back; the platform ID above guards for the same reason.
		if asset.Name == "" {
			asset.Name = p.Title + " " + org + "/" + repo
		}
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
		if asset.Name == "" {
			asset.Name = p.Title + " " + parseNameFromPath(projectPath)
		}
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
