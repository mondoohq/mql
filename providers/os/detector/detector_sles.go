// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"bufio"
	"encoding/xml"
	"io"
	"path"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type SlesProduct struct {
	Summary  string        `xml:"summary"`
	Register RegisterEntry `xml:"register"`
}

type RegisterEntry struct {
	Target string `xml:"target"`
	Flavor string `xml:"flavor"`
}

func getActivatedSlesModules(conn shared.Connection) []string {
	afs := &afero.Afero{Fs: conn.FileSystem()}
	ok, err := afs.DirExists("/etc/products.d")
	if err != nil || !ok {
		return []string{}
	}

	files, err := afs.ReadDir("/etc/products.d")
	if err != nil {
		return []string{}
	}

	modules := []string{}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".prod") {
			continue
		}

		content, err := afs.ReadFile("/etc/products.d/" + file.Name())
		if err != nil {
			continue
		}

		var product SlesProduct
		err = xml.Unmarshal(content, &product)
		if err != nil {
			continue
		}

		// We are only interested in modules and extensions
		if product.Register.Flavor != "module" && product.Register.Flavor != "extension" {
			continue
		}

		// We need to trim the prefix "SUSE " for some modules, to match the ecosystem
		// The same applies to the " Module" suffix
		moduleName := strings.TrimPrefix(product.Summary, "SUSE ")
		moduleName = strings.TrimSuffix(moduleName, " Module")
		modules = append(modules, moduleName)
	}

	return modules
}

// isSlMicro reports whether an os-release that says ID=sles describes SUSE
// Linux Micro. From 6.2 on, SUSE Linux Micro shares ID=sles and the SLES
// VERSION_ID, and only SUSE_SUPPORT_PRODUCT tells the two apart.
func isSlMicro(osr map[string]string) bool {
	return osr["SUSE_SUPPORT_PRODUCT"] == "SUSE Linux Micro"
}

// renameSlMicro reports a SUSE Linux Micro system that set ID=sles under its
// own name and version. The distro id becomes sl-micro, the ID that 6.0 and 6.1
// set, so package URLs carry distro=sl-micro-<version> on every 6.x release.
// The title is replaced only while it is the SLES one SUSE writes, so a
// product built on top, such as Harvester, keeps its own.
func renameSlMicro(pf *inventory.Platform, osr map[string]string) {
	pf.Name = "sl-micro"
	if pf.Labels != nil {
		pf.Labels[LabelDistroID] = "sl-micro"
	}
	if pf.Metadata != nil {
		pf.Metadata[LabelDistroID] = "sl-micro"
	}
	if version := osr["SUSE_SUPPORT_PRODUCT_VERSION"]; version != "" {
		pf.Version = version
	}
	if prettyName := osr["SUSE_PRETTY_NAME"]; prettyName != "" && strings.HasPrefix(pf.Title, "SUSE Linux Enterprise Server") {
		pf.Title = prettyName
	}
}

// harvesterReleasePath is written by the Harvester installer and exists only
// on Harvester nodes.
const harvesterReleasePath = "/etc/harvester-release.yaml"

// harvesterVersion returns the Harvester release of a node, or "" when the
// system is not a Harvester node.
func harvesterVersion(conn shared.Connection) string {
	f, err := conn.FileSystem().Open(harvesterReleasePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	return parseHarvesterVersion(f)
}

// parseHarvesterVersion reads the top-level harvester key of
// /etc/harvester-release.yaml, for example "harvester: v1.8.2".
func parseHarvesterVersion(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok || key != "harvester" {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return ""
}

func getSlesBaseProduct(conn shared.Connection) string {
	fs := conn.FileSystem()
	linkreader, ok := fs.(afero.LinkReader)
	var link string
	if ok {
		var err error
		link, err = linkreader.ReadlinkIfPossible("/etc/products.d/baseproduct")
		if err != nil || link == "" {
			return ""
		}
	} else {
		cmd, err := conn.RunCommand("readlink /etc/products.d/baseproduct")
		if err != nil || cmd.ExitStatus != 0 {
			return ""
		}
		lBytes, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			return ""
		}
		link = strings.TrimSpace(string(lBytes))
	}

	// Get file name from the symlink
	name := path.Base(link)

	// trim the ".prod" suffix
	name = strings.TrimSuffix(name, ".prod")
	return strings.ToLower(name)
}
