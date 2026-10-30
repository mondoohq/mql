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

// extractMimeDeps will go through each of the listed dependencies
// from the "Requires-Dist" values, and strip off everything but
// the name of the package/dependency itself
func extractMimeDeps(deps []string) []string {
	parsedDeps := []string{}
	for _, dep := range deps {
		// the semicolon indicates an optional dependency
		if strings.Contains(dep, ";") {
			continue
		}
		parsedDep := strings.Split(dep, " ")
		if len(parsedDep) > 0 {
			parsedDeps = append(parsedDeps, parsedDep[0])
		}
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

func ParseMIME(r io.Reader, pythonMIMEFilepath string) (*python.PackageDetails, error) {
	textReader := textproto.NewReader(bufio.NewReader(r))
	mimeData, err := textReader.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("error reading MIME data: %s", err)
	}

	deps := extractMimeDeps(mimeData.Values("Requires-Dist"))
	projectUrls := parseProjectUrls(mimeData.Values("Project-URL"))

	return &python.PackageDetails{
		Name:           mimeData.Get("Name"),
		Summary:        mimeData.Get("Summary"),
		Author:         mimeData.Get("Author"),
		AuthorEmail:    mimeData.Get("Author-email"),
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
