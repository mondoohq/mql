// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ConnectionType is the connection type of the iac meta-target.
const ConnectionType = "iac"

// OptionIgnore is the connection option carrying the ignored directory names,
// comma-separated. Set from --iac-ignore; absent means the defaults.
const OptionIgnore = "iac-ignore"

// SourceKind names where a tree was read from. Only KindFile is reachable
// today; the rest are named so the schema's `kind` field has a stated
// vocabulary rather than one invented per phase.
const (
	KindFile           = "file"
	KindGit            = "git"
	KindArchive        = "archive"
	KindContainerImage = "container-image"
	KindSSH            = "ssh"
	KindOCI            = "oci"
)

// DefaultIgnore are the directory names a walk skips unless told otherwise.
// These hold code that is not yours and would emit assets nobody asked to
// audit. `.terraform` is the load-bearing one: it caches downloaded modules,
// each a directory full of .tf files.
var DefaultIgnore = []string{
	".git", ".terraform", ".terragrunt-cache", ".venv",
	"node_modules", "vendor", "target", "dist",
}

// Source is where an infrastructure-as-code tree was read from.
type Source struct {
	Kind   string
	Origin string
	Ref    string
}

// IacConnection holds what walking the tree found. It reads no API and parses
// no format: everything here was decided by the providers that were probed.
type IacConnection struct {
	plugin.Connection
	asset *inventory.Asset

	source     Source
	detections []*Detection
}

func NewIacConnection(id uint32, asset *inventory.Asset, source Source) *IacConnection {
	return &IacConnection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
		source:     source,
	}
}

func (c *IacConnection) Name() string { return ConnectionType }

func (c *IacConnection) Asset() *inventory.Asset { return c.asset }

func (c *IacConnection) Source() Source { return c.source }

func (c *IacConnection) Detections() []*Detection { return c.detections }

// SetDetections records what the walk found. Called once, from Connect.
func (c *IacConnection) SetDetections(detections []*Detection) {
	c.detections = detections
}

// DetectionByAnchor returns the detection with the given anchor id.
func (c *IacConnection) DetectionByAnchor(anchorID string) *Detection {
	for _, d := range c.detections {
		if d.AnchorID() == anchorID {
			return d
		}
	}
	return nil
}

// PlatformID is the identity of a local tree: the hash of its absolute path,
// the scheme kustomize and docker-file already use for a local path.
func PlatformID(absPath string) string {
	h := sha256.New()
	h.Write([]byte(absPath))
	return "//platformid.api.mondoo.app/runtime/iac/hash/" + hex.EncodeToString(h.Sum(nil))
}

// AssetName is what a project is called in a report. The directory name, since
// the absolute path is long and its hash is already the identity.
func AssetName(absPath string) string {
	base := filepath.Base(absPath)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "IaC project"
	}
	return "IaC project " + base
}
