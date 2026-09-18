// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"bytes"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"

	"github.com/aws-cloudformation/rain/cft"
	"github.com/aws-cloudformation/rain/cft/parse"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

var (
	_ plugin.Connection = (*CloudformationConnection)(nil)
	_ plugin.Closer     = (*CloudformationConnection)(nil)
)

type CloudformationConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	// Add custom connection fields here
	path        string
	content     string
	cftTemplate cft.Template
	closer      func()
}

func NewCloudformationConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*CloudformationConnection, error) {
	conn := &CloudformationConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}
	// initialize your connection here
	if len(asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	// If a git clone is performed below, clean up the temporary directory on any
	// error path. Close() is a no-op when nothing was cloned, and the guard is
	// disarmed once the connection is returned and takes ownership of cleanup.
	cleanupClone := true
	defer func() {
		if cleanupClone {
			conn.Close()
		}
	}()

	cc := asset.Connections[0]
	path := cc.Options["path"]
	// When discovered from a git repository (e.g. by the GitHub provider) the
	// asset carries the repo URL plus a repo-relative path to the template.
	// Clone the repo and resolve the template within the checkout. We keep the
	// repo-relative path in the options so the detector can build a stable,
	// human-friendly asset name and platform ID from the repo rather than the
	// temporary clone directory.
	if _, ok := cc.Options["http-url"]; ok {
		clonePath, closer, err := plugin.NewGitClone(asset)
		if err != nil {
			return nil, err
		}
		conn.closer = closer
		path = filepath.Join(clonePath, path)
	}
	conn.path = path

	// Read the raw bytes up front and parse from them, so we can later extract
	// the source text a resource/output/parameter spans for file-context.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Convert to a string once here; nodeContext extracts source ranges from it
	// for every resource/output/parameter, and a per-call []byte->string copy of
	// a large template would be wasteful.
	conn.content = string(data)

	// Look for the marker before parsing, not after. This opt-in matches every
	// .yaml, .yml, .json and .template in a tree, so most of what reaches here
	// is somebody else's file -- and a Helm template full of Go templating is
	// not valid YAML at all, so a parse-first gate would report "invalid YAML"
	// for every chart in a repository instead of simply not claiming it.
	//
	// With the marker present, a parse failure is what it looks like: a
	// CloudFormation template that is broken, which stays a reported error.
	if !hasTemplateMarker(data) {
		return nil, fmt.Errorf("%s is not a CloudFormation or SAM template, it declares no CloudFormation section: %w", path, plugin.ErrNoMatch)
	}

	cftTemplate, err := parse.Reader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if cftTemplate == nil {
		return nil, errors.New("cftTemplate is nil")
	}
	conn.cftTemplate = *cftTemplate

	// The textual marker above can fire on a file that merely mentions one of
	// the words, so confirm it against the parsed document: parse.Reader
	// accepts any well-formed YAML or JSON, and a Kubernetes manifest or a
	// settings file would otherwise connect as an empty stack that passes every
	// policy.
	if !hasAnySection(cftTemplate) {
		return nil, fmt.Errorf("%s is not a CloudFormation or SAM template, it declares no CloudFormation section: %w", path, plugin.ErrNoMatch)
	}

	cleanupClone = false
	return conn, nil
}

// templateSections is CloudFormation's top-level vocabulary.
//
// Deliberately the whole set rather than just Resources: a template fragment
// carrying only Parameters, Mappings or Outputs is a real thing to scan, and
// SAM templates lead with Transform. What no foreign document has is any of
// these at the top level -- a Kubernetes manifest has apiVersion and kind, a
// Helm chart has name and version, a settings file has whatever its app calls
// things.
var templateSections = []cft.Section{
	cft.AWSTemplateFormatVersion, cft.Resources, cft.Description, cft.Metadata,
	cft.Parameters, cft.Rules, cft.Mappings, cft.Conditions, cft.Transform,
	cft.Outputs,
	// SAM's Globals section, which cft has no constant for.
	"Globals",
}

// hasTemplateMarker reports whether the raw document mentions a CloudFormation
// section at all. Deliberately textual and deliberately generous: it only
// decides whether the file is worth parsing, and hasAnySection is what actually
// decides whether it is a template.
//
// It runs before the parse because this opt-in matches every .yaml, .yml,
// .json and .template in a tree, so most of what reaches here is somebody
// else's file -- and a Helm template full of Go templating is not valid YAML at
// all, so a parse-first gate would report "invalid YAML" for every chart in a
// repository rather than simply not claiming it.
func hasTemplateMarker(data []byte) bool {
	for _, section := range templateSections {
		if bytes.Contains(data, []byte(section)) {
			return true
		}
	}
	return false
}

// hasAnySection reports whether the parsed template's root mapping carries any
// CloudFormation section.
func hasAnySection(template *cft.Template) bool {
	for _, section := range templateSections {
		if hasSection(template, section) {
			return true
		}
	}
	return false
}

// hasSection reports whether the template's root mapping carries the named
// section.
//
// Written out rather than calling cft.Template.HasSection, which indexes
// Node.Content[0] unguarded: an empty file and one holding only comments both
// parse into a template with no content at all, and the iac walk offers every
// *.yaml in a tree to this connection.
func hasSection(template *cft.Template, section cft.Section) bool {
	if template == nil || template.Node == nil || len(template.Node.Content) == 0 {
		return false
	}
	root := template.Node.Content[0]
	if root == nil || root.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == string(section) {
			return true
		}
	}
	return false
}

// Close cleans up any temporary directory created by a git clone.
func (c *CloudformationConnection) Close() {
	if c.closer != nil {
		c.closer()
	}
}

func (c *CloudformationConnection) Name() string {
	return "cloudformation"
}

func (c *CloudformationConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *CloudformationConnection) CftTemplate() cft.Template {
	return c.cftTemplate
}

// Path returns the template file path this connection was opened with.
func (c *CloudformationConnection) Path() string {
	return c.path
}

// Content returns the raw text of the template file, used to extract the
// source text a resource/output/parameter spans for file-context. The string
// is converted once at connection time so repeated range extractions don't
// each re-copy the whole template.
func (c *CloudformationConnection) Content() string {
	return c.content
}
