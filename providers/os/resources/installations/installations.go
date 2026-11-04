// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package installations finds software installed outside a package manager
// by its layout on disk: an Oracle Database home unpacked from a zip archive,
// a server copied into /opt. Every detector reads files only, so it finds the
// same installations on a running host, in a container image and on a disk
// snapshot.
//
// A product is one Detector, a row in Detectors. A detector names the places
// install roots are recorded or kept (Locators), confirms that a candidate
// root really is the product (Accept), and reads its version (Version, tried
// in order). Adding a product means adding a row and its measured fixtures.
package installations

import (
	"errors"
	"path"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// How an install root was found, as installation.locatedBy reports it.
const (
	// LocatedByRegistry is a file in which the vendor's installer records its
	// installations, such as Oracle's central inventory.
	LocatedByRegistry = "registry"
	// LocatedByPath is a directory the vendor documents as the install location.
	LocatedByPath = "path"
)

// Evidence a version was read from, as installation.versionSource reports it.
// installMetadata is shared with binary.versionSource.
const (
	// SourcePatchInventory is the record of patches the vendor's patch tool
	// applied to the installation.
	SourcePatchInventory = "patchInventory"
	// SourceInstallMetadata is metadata the installer wrote into the install root.
	SourceInstallMetadata = "installMetadata"
)

// Installation is one install root of one product.
type Installation struct {
	Name          string
	Vendor        string
	Path          string
	Version       string
	VersionSource string
	// VersionFile is the file the version was read from, empty with Version.
	VersionFile string
	LocatedBy   string
	Purl        string
	CPEs        []string
}

// Candidate is a directory that may be an install root.
type Candidate struct {
	Root      string
	LocatedBy string
}

// Locator returns the candidate install roots one source knows about. A
// source that is not on the asset returns no candidates and no error.
type Locator func(fs afero.Fs) ([]Candidate, error)

// Version is a version and the evidence it was read from.
type Version struct {
	Value  string
	Source string
	File   string
}

// VersionReader reads the version of the installation at root. ok is false
// when root carries none of the evidence this reader looks for.
type VersionReader func(fs afero.Fs, root string) (v Version, ok bool, err error)

// Detector recognizes one product.
type Detector struct {
	// Name is the product name reported for it, e.g. "oracle-database"
	Name string
	// Vendor is the vendor reported for it, e.g. "Oracle"
	Vendor string
	// Locate lists the sources of candidate roots, most authoritative first.
	// A root found by several keeps the locatedBy of the first.
	Locate []Locator
	// Accept confirms that root is an installation of this product.
	Accept func(fs afero.Fs, root string) (bool, error)
	// Version lists the version readers; the first that finds evidence wins.
	Version []VersionReader
	// Identify returns the package URL and CPEs for a version, which may be
	// empty.
	Identify func(version string) (purl string, cpes []string)
}

// Detectors is every product this package recognizes.
var Detectors = []Detector{
	oracleDatabase,
}

// Detect runs the detectors against fs.
//
// One unreadable source must not hide the installations other sources
// found, so a failure is logged and skipped. Only when nothing was found and
// something failed is the failure returned, so that a scan which could not
// read where installations are recorded is an error rather than an empty
// list.
func Detect(fs afero.Fs, detectors []Detector) ([]Installation, error) {
	res := []Installation{}
	var errs []error
	for i := range detectors {
		found, err := detectors[i].detect(fs)
		res = append(res, found...)
		errs = append(errs, err...)
	}
	if len(errs) == 0 {
		return res, nil
	}
	if len(res) == 0 {
		return res, errors.Join(errs...)
	}
	for _, err := range errs {
		log.Warn().Err(err).Msg("installations> skipped a source that could not be read")
	}
	return res, nil
}

func (d *Detector) detect(fs afero.Fs) ([]Installation, []error) {
	var errs []error
	seen := map[string]struct{}{}
	res := []Installation{}
	for _, locate := range d.Locate {
		candidates, err := locate(fs)
		if err != nil {
			errs = append(errs, err)
		}
		for _, c := range candidates {
			root := path.Clean(c.Root)
			if _, ok := seen[root]; ok {
				continue
			}
			seen[root] = struct{}{}

			ok, err := d.Accept(fs, root)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !ok {
				continue
			}

			inst := Installation{
				Name:      d.Name,
				Vendor:    d.Vendor,
				Path:      root,
				LocatedBy: c.LocatedBy,
			}
			v, err := d.version(fs, root)
			if err != nil {
				// The root is an installation even when its version cannot
				// be read, so it is reported without one.
				errs = append(errs, err)
			}
			inst.Version = v.Value
			inst.VersionSource = v.Source
			inst.VersionFile = v.File
			inst.Purl, inst.CPEs = d.Identify(inst.Version)
			res = append(res, inst)
		}
	}
	return res, errs
}

func (d *Detector) version(fs afero.Fs, root string) (Version, error) {
	var errs []error
	for _, read := range d.Version {
		v, ok, err := read(fs, root)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ok {
			// A reader that failed before this one may have held the more
			// precise version, so its error is still returned.
			return v, errors.Join(errs...)
		}
	}
	return Version{}, errors.Join(errs...)
}
