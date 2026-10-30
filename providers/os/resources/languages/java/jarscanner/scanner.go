// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jarscanner

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/java/manifestmf"
	"go.mondoo.com/mql/providers/os/resources/languages/java/pomproperties"
)

// MaxArchiveSize is the maximum size of a JAR/WAR/EAR file to scan (100MB).
const MaxArchiveSize = 100 * 1024 * 1024

// maxNestingDepth limits how deeply nested JARs are scanned to prevent zip bombs.
const maxNestingDepth = 3

// archiveExtensions are the file extensions we scan.
var archiveExtensions = []string{".jar", ".war", ".ear", ".par", ".sar", ".nar"}

// nestedLibDirs are directories inside archives that contain nested JARs.
var nestedLibDirs = []string{
	"WEB-INF/lib/",  // WAR files
	"BOOT-INF/lib/", // Spring Boot fat JARs
	"lib/",          // Generic nested libs
}

// ScanArchive extracts package metadata from a single JAR/WAR/EAR file.
// It reads the file via afero.Fs into memory, then scans the ZIP contents
// for pom.properties and MANIFEST.MF.
func ScanArchive(afs *afero.Afero, archivePath string) ([]*languages.Package, error) {
	// Check file size first
	info, err := afs.Stat(archivePath)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxArchiveSize {
		log.Warn().Str("path", archivePath).Int64("size", info.Size()).Msg("skipping oversized archive")
		return nil, nil
	}

	// Read the entire file into memory for ZIP processing.
	// This is required because archive/zip needs io.ReaderAt, which may not
	// be available over remote filesystems (SSH, WinRM).
	data, err := afs.ReadFile(archivePath)
	if err != nil {
		return nil, err
	}

	return scanZipData(data, archivePath, 0)
}

// scanZipData scans ZIP data for Java package metadata.
// depth tracks nesting level to prevent zip bomb attacks.
func scanZipData(data []byte, evidencePath string, depth int) ([]*languages.Package, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	var packages []*languages.Package
	var manifestPkg *languages.Package

	for _, file := range reader.File {
		name := file.Name

		// Extract pom.properties (preferred source of Maven coordinates)
		if strings.HasSuffix(name, "/pom.properties") && strings.HasPrefix(name, "META-INF/maven/") {
			pkg, err := extractPomProperties(file, evidencePath)
			if err != nil {
				log.Debug().Err(err).Str("entry", name).Msg("failed to parse pom.properties in archive")
				continue
			}
			if pkg != nil {
				packages = append(packages, pkg)
			}
		}

		// Always parse MANIFEST.MF as a fallback candidate
		if name == "META-INF/MANIFEST.MF" {
			pkg, err := extractManifest(file, evidencePath)
			if err != nil {
				log.Debug().Err(err).Msg("failed to parse MANIFEST.MF in archive")
			} else {
				manifestPkg = pkg
			}
		}

		// Scan nested JARs (WAR, fat JARs) if within depth limit
		if isNestedJar(name) && depth < maxNestingDepth {
			nestedPkgs, err := extractNestedJar(file, evidencePath+"!"+name, depth+1)
			if err != nil {
				log.Debug().Err(err).Str("entry", name).Msg("failed to scan nested JAR")
				continue
			}
			packages = append(packages, nestedPkgs...)
		}
	}

	// If no pom.properties found, use MANIFEST.MF as fallback
	if len(packages) == 0 && manifestPkg != nil {
		packages = append(packages, manifestPkg)
	}

	return packages, nil
}

func extractPomProperties(file *zip.File, evidencePath string) (*languages.Package, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	extractor := &pomproperties.Extractor{EntryPath: file.Name}
	bom, err := extractor.Parse(rc, evidencePath)
	if err != nil {
		return nil, err
	}

	return bom.Root(), nil
}

func extractManifest(file *zip.File, evidencePath string) (*languages.Package, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	extractor := &manifestmf.Extractor{}
	bom, err := extractor.Parse(rc, evidencePath)
	if err != nil {
		return nil, err
	}

	return bom.Root(), nil
}

func extractNestedJar(file *zip.File, evidencePath string, depth int) ([]*languages.Package, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	// Limit read size to prevent zip bomb memory exhaustion
	data, err := io.ReadAll(io.LimitReader(rc, MaxArchiveSize))
	if err != nil {
		return nil, err
	}

	return scanZipData(data, evidencePath, depth)
}

// isNestedJar returns true if the ZIP entry is a JAR inside a known lib directory.
func isNestedJar(name string) bool {
	if !strings.HasSuffix(strings.ToLower(name), ".jar") {
		return false
	}
	for _, dir := range nestedLibDirs {
		if strings.HasPrefix(name, dir) {
			return true
		}
	}
	return false
}

// IsArchive returns true if the file has a JAR/WAR/EAR extension.
func IsArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return slices.Contains(archiveExtensions, ext)
}
