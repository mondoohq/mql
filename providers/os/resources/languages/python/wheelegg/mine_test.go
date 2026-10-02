// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wheelegg

import (
	"bufio"
	"bytes"
	"io"
	"net/textproto"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

func TestMimeParser(t *testing.T) {

	content := `Metadata-Version: 2.1
Name: pyftpdlib
Version: 1.5.7
Summary: Very fast asynchronous FTP server library
Home-page: https://github.com/giampaolo/pyftpdlib/
Author: Giampaolo Rodola'
Author-email: g.rodola@gmail.com
License: MIT
Keywords: ftp,ftps,server,ftpd,daemon,python,ssl,sendfile,asynchronous,nonblocking,eventdriven,rfc959,rfc1123,rfc2228,rfc2428,rfc2640,rfc3659
Platform: Platform Independent
Classifier: Development Status :: 5 - Production/Stable
Classifier: Environment :: Console
Classifier: Intended Audience :: Developers
Classifier: Intended Audience :: System Administrators
Classifier: License :: OSI Approved :: MIT License
Classifier: Operating System :: OS Independent
Classifier: Programming Language :: Python
Classifier: Topic :: Internet :: File Transfer Protocol (FTP)
Classifier: Topic :: Software Development :: Libraries :: Python Modules
Classifier: Topic :: System :: Filesystems
Classifier: Programming Language :: Python
Classifier: Programming Language :: Python :: 2
Classifier: Programming Language :: Python :: 3
Provides-Extra: ssl
License-File: LICENSE
`
	pkg, err := ParseMIME(strings.NewReader(content), "/usr/lib/python3.11/site-packages/pyftpdlib-1.5.7-py3.11.egg-info/PKG-INFO")
	require.NoError(t, err)

	assert.Equal(t, "Giampaolo Rodola'", pkg.Author)
	assert.Equal(t, "g.rodola@gmail.com", pkg.AuthorEmail)
	assert.Equal(t, "pyftpdlib", pkg.Name)
	assert.Equal(t, "1.5.7", pkg.Version)
	assert.Equal(t, "MIT", pkg.License)
}

func TestMimeParserRequiresPythonAndProjectUrls(t *testing.T) {
	content := `Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
Author-email: Kenneth Reitz <me@kennethreitz.org>
License: Apache-2.0
Requires-Python: >=3.7
Project-URL: Homepage, https://requests.readthedocs.io
Project-URL: Source, https://github.com/psf/requests
Project-URL: Documentation, https://requests.readthedocs.io
Requires-Dist: charset-normalizer (<4,>=2)
Requires-Dist: idna (<4,>=2.5)
Requires-Dist: urllib3 (<3,>=1.21.1)
`
	pkg, err := ParseMIME(strings.NewReader(content), "/usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA")
	require.NoError(t, err)

	assert.Equal(t, "requests", pkg.Name)
	assert.Equal(t, "2.31.0", pkg.Version)
	assert.Equal(t, ">=3.7", pkg.RequiresPython)
	assert.Equal(t, map[string]string{
		"Homepage":      "https://requests.readthedocs.io",
		"Source":        "https://github.com/psf/requests",
		"Documentation": "https://requests.readthedocs.io",
	}, pkg.ProjectUrls)
	assert.Equal(t, []string{"charset-normalizer", "idna", "urllib3"}, pkg.Dependencies)
}

// requests 2.27.1 from a Python 3.11 venv on Debian 12. Every requirement
// with a marker used to be dropped, so idna and charset-normalizer were missing
// although Python 3.11 needs them.
func TestMimeParserRequiresDistMarkers(t *testing.T) {
	f, err := os.Open("testdata/requests-2.27.1-METADATA")
	require.NoError(t, err)
	defer f.Close()
	const path = "/opt/g03venv/lib/python3.11/site-packages/requests-2.27.1.dist-info/METADATA"
	pkg, err := ParseMIMEInEnvironment(f, path, python.SiteMarkerEnvironment(path, "linux"))
	require.NoError(t, err)

	assert.Equal(t, []string{"urllib3", "certifi", "charset-normalizer", "idna"}, pkg.Dependencies)
}

func TestExtractMimeDepsNameShapes(t *testing.T) {
	env := python.SiteMarkerEnvironment("/usr/lib/python3/dist-packages", "linux")
	assert.Equal(t,
		[]string{"pyparsing", "importlib-metadata", "requests"},
		extractMimeDeps([]string{
			"pyparsing (<3,>=2.4.2) ; python_version < \"3.0\"",
			"pyparsing (!=3.0.0,!=3.0.1,!=3.0.2,!=3.0.3,<4,>=2.4.2) ; python_version > \"3.0\"",
			"importlib-metadata; python_version < '3.8'",
			"requests>=2.0",
			"pytest; extra == 'test'",
		}, env))
}

// configobj 5.0.6 as packaged on Debian 9: setuptools wrote "UNKNOWN" for the
// unset License, and the trove classifier states the license.
func TestMimeParserUnknownLicense(t *testing.T) {
	f, err := os.Open("testdata/configobj-5.0.6-PKG-INFO")
	require.NoError(t, err)
	defer f.Close()
	pkg, err := ParseMIME(f, "/usr/lib/python3/dist-packages/configobj-5.0.6.egg-info/PKG-INFO")
	require.NoError(t, err)

	assert.Equal(t, "BSD License", pkg.License)

	pkg, err = ParseMIME(strings.NewReader("Metadata-Version: 1.0\nName: old\nVersion: 1.0\nSummary: UNKNOWN\nAuthor: UNKNOWN\nAuthor-email: UNKNOWN\nLicense: UNKNOWN\n"), "/x/old-1.0.egg-info/PKG-INFO")
	require.NoError(t, err)
	assert.Empty(t, pkg.License)
	assert.Empty(t, pkg.Summary)
	assert.Empty(t, pkg.Author)
	assert.Empty(t, pkg.AuthorEmail)
}

// On files net/textproto accepts, readMetadataHeader reads the same header
// as textproto did: canonical keys, continuation lines joined with a space,
// the block ending at the first empty line.
func TestReadMetadataHeaderMatchesTextproto(t *testing.T) {
	for _, f := range []string{"testdata/requests-2.27.1-METADATA", "testdata/configobj-5.0.6-PKG-INFO"} {
		t.Run(f, func(t *testing.T) {
			raw, err := os.ReadFile(f)
			require.NoError(t, err)

			want, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
			// a PKG-INFO without a description ends without an empty line
			if err != io.EOF {
				require.NoError(t, err)
			}
			require.NotEmpty(t, want)
			got, err := readMetadataHeader(bytes.NewReader(raw))
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

// passlib 1.7.4 continues Keywords on unindented lines. textproto failed with
// `missing colon: "crypt md5-crypt"` and the package was reported from its
// directory name alone. Python's email parser (pip, importlib.metadata) ends
// the header block at that line and keeps the headers before it.
func TestMimeParserUnindentedContinuation(t *testing.T) {
	for _, f := range []string{
		// openSUSE Leap 16.0, SLES 16.0: python313-passlib
		"testdata/passlib-1.7.4-METADATA",
		// openSUSE Leap 15.6: python3-passlib, egg-info
		"testdata/passlib-1.7.4-PKG-INFO",
	} {
		t.Run(f, func(t *testing.T) {
			r, err := os.Open(f)
			require.NoError(t, err)
			defer r.Close()

			pkg, err := ParseMIME(r, "/usr/lib/python3.13/site-packages/passlib-1.7.4.dist-info/METADATA")
			require.NoError(t, err)
			assert.Equal(t, "passlib", pkg.Name)
			assert.Equal(t, "1.7.4", pkg.Version)
			assert.Equal(t, "comprehensive password hashing framework supporting over 30 schemes", pkg.Summary)
			assert.Equal(t, "Eli Collins", pkg.Author)
			assert.Equal(t, "elic@assurancetechnologies.com", pkg.AuthorEmail)
			assert.Equal(t, "BSD", pkg.License)
			// every Requires-Dist comes after the broken line, and all of them
			// are extras, which pip does not see either
			assert.Empty(t, pkg.Dependencies)
		})
	}
}

// PyGObject 3.52.3 (SLES 16.0) pastes the LGPL into License, form feeds
// included. textproto rejected the line and every header after it.
func TestMimeParserControlCharacterInValue(t *testing.T) {
	r, err := os.Open("testdata/pygobject-3.52.3-METADATA")
	require.NoError(t, err)
	defer r.Close()

	pkg, err := ParseMIME(r, "/usr/lib64/python3.13/site-packages/pygobject-3.52.3.dist-info/METADATA")
	require.NoError(t, err)
	assert.Equal(t, "PyGObject", pkg.Name)
	assert.Equal(t, "3.52.3", pkg.Version)
	assert.Equal(t, "Python bindings for GObject Introspection", pkg.Summary)
	assert.Equal(t, "James Henstridge <james@daa.com.au>", pkg.AuthorEmail)
	assert.Equal(t, "<4.0,>=3.9", pkg.RequiresPython)
	assert.Equal(t, []string{"pycairo"}, pkg.Dependencies)
	assert.Equal(t, "https://pygobject.gnome.org", pkg.ProjectUrls["Homepage"])
	// the pasted license text is not a license name; the classifier answers
	assert.Equal(t, "GNU Lesser General Public License v2 or later (LGPLv2+)", pkg.License)
}

func TestReadMetadataHeaderEdges(t *testing.T) {
	h, err := readMetadataHeader(strings.NewReader("Name: a\r\nVersion: 1\r\n\r\nName: body\r\n"))
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, h.Values("Name"), "CRLF, and the description is not read as headers")
	assert.Equal(t, "1", h.Get("Version"))

	h, err = readMetadataHeader(strings.NewReader("Name: a\n  continued\n\tand tabbed  \nVersion: 1"))
	require.NoError(t, err)
	assert.Equal(t, "a continued and tabbed", h.Get("Name"))
	assert.Equal(t, "1", h.Get("Version"), "a last line without newline")

	h, err = readMetadataHeader(strings.NewReader(" orphan continuation\nName: a\n"))
	require.NoError(t, err)
	assert.Empty(t, h)

	h, err = readMetadataHeader(strings.NewReader("Name: a\nBad Key: b\nVersion: 1\n"))
	require.NoError(t, err)
	assert.Equal(t, "a", h.Get("Name"))
	assert.Empty(t, h.Get("Version"), "a key with a space ends the block, as in Python")
}
