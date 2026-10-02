// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wheelegg

import (
	"bufio"
	"fmt"
	"io"
	"net/textproto"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

// extractMimeDeps returns the names of the "Requires-Dist" requirements that
// apply in env. A requirement with an environment marker applies unless the
// marker is false there; one that only an extra brings in
// (`extra == "socks"`) is optional and left out.
func extractMimeDeps(deps []string, env python.MarkerEnvironment) []string {
	parsedDeps := []string{}
	// a project is often listed once per Python version range
	// (`idna<3; python_version < "3"`, `idna<4; python_version >= "3"`), and
	// both can apply where the version is not known
	seen := map[string]bool{}
	for _, dep := range deps {
		name, marker := python.ParseRequirement(dep)
		if name == "" || !python.MarkerMayHold(marker, env) || seen[python.NormalizeName(name)] {
			continue
		}
		seen[python.NormalizeName(name)] = true
		parsedDeps = append(parsedDeps, name)
	}
	return parsedDeps
}

// parseProjectUrls parses Project-URL header values which have the format "Label, URL"
func parseProjectUrls(values []string) map[string]string {
	urls := make(map[string]string, len(values))
	for _, v := range values {
		label, url, ok := strings.Cut(v, ",")
		if ok {
			urls[strings.TrimSpace(label)] = strings.TrimSpace(url)
		}
	}
	return urls
}

// ParseMIME parses METADATA or PKG-INFO. Requirements are evaluated with what
// the file's path tells about the environment, see ParseMIMEInEnvironment.
func ParseMIME(r io.Reader, pythonMIMEFilepath string) (*python.PackageDetails, error) {
	return ParseMIMEInEnvironment(r, pythonMIMEFilepath, python.SiteMarkerEnvironment(pythonMIMEFilepath, ""))
}

// ParseMIMEInEnvironment parses METADATA or PKG-INFO, keeping the
// Requires-Dist requirements that apply in env.
func ParseMIMEInEnvironment(r io.Reader, pythonMIMEFilepath string, env python.MarkerEnvironment) (*python.PackageDetails, error) {
	textReader := textproto.NewReader(bufio.NewReader(r))
	mimeData, err := textReader.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("error reading MIME data: %s", err)
	}

	deps := extractMimeDeps(mimeData.Values("Requires-Dist"), env)
	projectUrls := parseProjectUrls(mimeData.Values("Project-URL"))

	return &python.PackageDetails{
		Name:           mimeData.Get("Name"),
		Summary:        metadataValue(mimeData, "Summary"),
		Author:         metadataValue(mimeData, "Author"),
		AuthorEmail:    metadataValue(mimeData, "Author-email"),
		License:        metadataLicense(mimeData),
		Version:        mimeData.Get("Version"),
		RequiresPython: mimeData.Get("Requires-Python"),
		ProjectUrls:    projectUrls,
		Dependencies:   deps,
		File:           pythonMIMEFilepath,
		Purl:           python.NewPackageUrl(mimeData.Get("Name"), mimeData.Get("Version")),
		Cpes:           python.NewCpes(mimeData.Get("Name"), mimeData.Get("Version")),
	}, nil
}

// metadataUnknown is what distutils and older setuptools wrote into PKG-INFO
// for every field a project left unset (Summary, Author, Author-email,
// License). It states nothing.
const metadataUnknown = "UNKNOWN"

// metadataValue returns a header's value, "" when it is absent or UNKNOWN.
func metadataValue(h textproto.MIMEHeader, key string) string {
	v := h.Get(key)
	if strings.TrimSpace(v) == metadataUnknown {
		return ""
	}
	return v
}
