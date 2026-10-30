// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ansible/play"
	"go.mondoo.com/mql/providers/ansible/project"
)

var _ plugin.Connection = (*AnsibleConnection)(nil)

// AnsibleConnection connects to either a single playbook file or a whole
// Ansible project directory. The path's type at connect time decides the mode:
// a file populates playbook (single-playbook analysis, the original behavior),
// a directory populates proj (project-wide static analysis).
type AnsibleConnection struct {
	plugin.Connection
	Conf     *inventory.Config
	asset    *inventory.Asset
	path     string
	isDir    bool
	playbook play.Playbook
	proj     *project.Project
}

func NewAnsibleConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*AnsibleConnection, error) {
	if asset == nil || len(asset.Connections) == 0 {
		return nil, errors.New("ansible: no connection options for asset")
	}
	cc := asset.Connections[0]
	path := ""
	if cc.Options != nil {
		path = cc.Options["path"]
	}
	if path == "" {
		return nil, errors.New("ansible: no playbook path provided (set the `path` option)")
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ansible: cannot access %q: %w", path, err)
	}

	conn := &AnsibleConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		path:       path,
		isDir:      fi.IsDir(),
	}

	if fi.IsDir() {
		proj, err := project.Load(path)
		if err != nil {
			return nil, fmt.Errorf("ansible: cannot load project %q: %w", path, err)
		}
		// project.Load treats every missing artifact as empty rather than as an
		// error, so it succeeds on any directory at all and would connect an
		// Ansible project made of nothing -- which then passes every policy. A
		// directory with none of the four is simply not an Ansible project.
		if isEmptyProject(proj) {
			return nil, fmt.Errorf("ansible: %s has no ansible.cfg, roles, inventory or playbooks: %w", path, plugin.ErrNoMatch)
		}
		conn.proj = proj
		return conn, nil
	}

	playbook, err := loadPlaybookFile(path)
	if err != nil {
		return nil, err
	}
	conn.playbook = playbook
	return conn, nil
}

// isEmptyProject reports whether loading the directory found nothing that makes
// it an Ansible project. Playbooks count because project.loadPlaybooks already
// content-gates them with looksLikePlaybook, so a folder of unrelated YAML does
// not qualify on their account.
func isEmptyProject(proj *project.Project) bool {
	return proj == nil ||
		(proj.Config == nil &&
			len(proj.Roles) == 0 &&
			proj.Inventory == nil &&
			len(proj.Playbooks) == 0)
}

func loadPlaybookFile(path string) (play.Playbook, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ansible: cannot open playbook %q: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("ansible: cannot read playbook %q: %w", path, err)
	}

	playbook, err := play.DecodePlaybook(data)
	if err != nil {
		// Two very different files fail here, and telling them apart is what
		// keeps a broken playbook from being silently dropped. A Playbook is a
		// slice, so any YAML *mapping* -- a Kubernetes manifest, a
		// CloudFormation template, a CI config -- fails to decode, and that is
		// a statement about what the file is. YAML that does not parse at all
		// is a file that is meant to be one of ours and is broken, which stays
		// a reported error.
		if !isYAML(data) {
			return nil, fmt.Errorf("ansible: cannot decode playbook %q: %w", path, err)
		}
		return nil, fmt.Errorf("ansible: %s is not a playbook: %v: %w", path, err, plugin.ErrNoMatch)
	}

	// A YAML list of unrelated dicts decodes cleanly into a playbook whose
	// plays say nothing, so the connect would succeed and the asset report
	// nothing. This is the same rule the project loader applies when deciding
	// which files under a directory are playbooks, so the two paths cannot
	// disagree about one file.
	if !project.LooksLikePlaybook(data) {
		return nil, fmt.Errorf("ansible: %s is not a playbook, no play declares hosts or imports one: %w", path, plugin.ErrNoMatch)
	}

	return playbook, nil
}

// isYAML reports whether the bytes parse as YAML at all, whatever shape they
// take.
func isYAML(data []byte) bool {
	var probe any
	return yaml.Unmarshal(data, &probe) == nil
}

func (c *AnsibleConnection) Name() string {
	return "ansible"
}

func (c *AnsibleConnection) Asset() *inventory.Asset {
	return c.asset
}

// IsProject reports whether the connection targets a project directory.
func (c *AnsibleConnection) IsProject() bool {
	return c.isDir
}

// Playbook returns the parsed single playbook (file mode). It is empty in
// project mode.
func (c *AnsibleConnection) Playbook() play.Playbook {
	return c.playbook
}

// Project returns the parsed project model (directory mode), or nil in file
// mode.
func (c *AnsibleConnection) Project() *project.Project {
	return c.proj
}

// BaseDir is the directory that relative include/import paths in the connected
// playbook resolve against: the project root in directory mode, or the
// playbook file's directory in file mode.
func (c *AnsibleConnection) BaseDir() string {
	if c.isDir {
		return c.path
	}
	return filepath.Dir(c.path)
}
