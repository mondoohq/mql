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
	mimeData, err := readMetadataHeader(r)
	if err != nil {
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

// readMetadataHeader reads the header block of METADATA or PKG-INFO the way
// Python's email parser does, which is what pip and importlib.metadata use.
//
// net/textproto rejected the whole file over one line it does not accept, and
// the package lost all of its metadata. Two real cases:
//
//   - passlib 1.7.4 writes its Keywords over several lines, and only the first
//     one is indented ("Keywords: password secret hash security" then
//     "crypt md5-crypt"). Python ends the header block at the first line that
//     is neither a header nor a continuation, keeps what came before, and
//     reads the rest as the description. So does this.
//   - PyGObject 3.52.3 pastes the LGPL into License, page breaks (form feeds)
//     included. A control character is fine in a Python header value.
//
// Otherwise it gives what textproto gave: keys are canonicalized, the block
// ends at the first empty line, and a continuation line is trimmed and joined
// to its header with a single space.
func readMetadataHeader(r io.Reader) (textproto.MIMEHeader, error) {
	h := textproto.MIMEHeader{}
	br := bufio.NewReader(r)
	var key string
	var value strings.Builder
	flush := func() {
		if key != "" {
			h.Add(key, value.String())
		}
		key = ""
		value.Reset()
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			// the empty line between the headers and the description
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if key == "" {
				// a continuation with no header to continue
				break
			}
			value.WriteByte(' ')
			value.WriteString(strings.Trim(line, " \t"))
		} else {
			name, val, ok := strings.Cut(line, ":")
			if !ok || !validMetadataKey(name) {
				// not a header: the description starts here
				break
			}
			flush()
			key = name
			value.WriteString(strings.TrimRight(strings.TrimLeft(val, " \t"), " \t"))
		}
		if err == io.EOF {
			break
		}
	}
	flush()
	return h, nil
}

// validMetadataKey reports whether name is a header field name: printable
// ASCII, no space, no colon (RFC 5322, as Python's email parser reads it).
func validMetadataKey(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
