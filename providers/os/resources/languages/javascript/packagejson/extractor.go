// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagejson

import (
	"encoding/json"
	"io"

	"go.mondoo.com/mql/v13/providers/os/resources/languages"
	"go.mondoo.com/mql/v13/providers/os/resources/languages/javascript"
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

func (p *packageJson) Transitive() languages.Packages {
	// transitive dependencies, includes the root package
	var transitive languages.Packages

	r := p.Root()
	if r != nil {
		transitive = append(transitive, r)
	}

	for k, v := range p.Dependencies {
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
