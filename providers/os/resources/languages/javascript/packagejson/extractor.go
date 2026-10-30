// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagejson

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*packageJson)(nil)
)

type Extractor struct{}

func (p *Extractor) Name() string {
	return "packagejson"
}

func (p *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var packageJson packageJson
	err = json.Unmarshal(data, &packageJson)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		packageJson.evidence = append(packageJson.evidence, filename)
	}

	return &packageJson, nil
}

func (p *packageJson) Root() *languages.Package {
	// root package
	root := &languages.Package{
		Name:         p.Name,
		Version:      p.Version,
		Description:  p.Description,
		Author:       p.authorName(),
		License:      p.licenseExpression(),
		Purl:         javascript.NewPackageUrl(p.Name, p.Version),
		Cpes:         javascript.NewCpes(p.Name, p.Version),
		EvidenceList: javascript.NewEvidenceList(p.evidence),
	}

	return root
}

// authorName surfaces only the name portion of package.json `author`,
// matching the npm convention. Returns empty when author is omitted.
func (p *packageJson) authorName() string {
	if p.Author == nil {
		return ""
	}
	return p.Author.Name
}

// licenseExpression returns the SPDX expression the package.json states.
//
// `license` is the current field and wins whenever it names a license. Packages
// published before npm settled on it instead carry a `licenses` array, whose
// members are `{"type": ..., "url": ...}` objects; a package listing several is
// offering a choice among them, which LicenseExpression renders as SPDX's OR.
//
// npm deprecated `licenses` in 2014, but a registry does not rewrite what was
// published: packages carrying only the array are still installed today, and
// reading only `license` reported them as stating no license at all.
func (p *packageJson) licenseExpression() string {
	if p.License != nil {
		if expr := languages.LicenseExpression([]string{p.License.Value}); expr != "" {
			return expr
		}
	}

	values := make([]string, 0, len(p.Licenses))
	for _, l := range p.Licenses {
		values = append(values, l.Value)
	}
	return languages.LicenseExpression(values)
}

func (p *packageJson) Direct() languages.Packages {
	return nil
}

// exactVersionSpec matches a dependency spec that names exactly one version:
// a full semver version, optionally written with a leading "=" or "v", as npm
// accepts it. Anything else is a range, a dist-tag, a URL or a path.
var exactVersionSpec = regexp.MustCompile(`^=?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$`)

// pinnedVersion returns the version a dependency spec pins, or "" when the spec
// allows more than one version ("^4.3.4", "~1.2.0", "4", "4.x", "*", "latest",
// "file:..", "git+https://..").
func pinnedVersion(spec string) string {
	m := exactVersionSpec.FindStringSubmatch(strings.TrimSpace(spec))
	if m == nil {
		return ""
	}
	return m[1]
}

func (p *packageJson) Transitive() languages.Packages {
	// transitive dependencies, includes the root package
	var transitive languages.Packages

	r := p.Root()
	if r != nil {
		transitive = append(transitive, r)
	}

	// A dependency in package.json is a declaration, not an installed package:
	// "^4.3.4" or "4" says which versions would be accepted, not which one is
	// on disk. Installed packages are read from node_modules or a lockfile.
	// Only a spec that pins one exact version names the version npm installs.
	for k, spec := range p.Dependencies {
		v := pinnedVersion(spec)
		if v == "" {
			continue
		}
		transitive = append(transitive, &languages.Package{
			Name:         k,
			Version:      v,
			Purl:         javascript.NewPackageUrl(k, v),
			Cpes:         javascript.NewCpes(k, v),
			EvidenceList: javascript.NewEvidenceList(p.evidence),
		})
	}

	return transitive
}
