// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/carabiner-dev/spdx3"
	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/simplelicensing"
	"github.com/carabiner-dev/spdx3/profiles/software"
	spdx3types "github.com/carabiner-dev/spdx3/types"
	"github.com/package-url/packageurl-go"
)

// spdx3ContextPrefix starts the JSON-LD context URL of every SPDX 3 release,
// e.g. https://spdx.org/rdf/3.0.1/spdx-context.jsonld.
const spdx3ContextPrefix = "https://spdx.org/rdf/3."

// spdx3SupportedVersion is the SPDX 3 release the decoder reads, the one
// github.com/carabiner-dev/spdx3 models.
const spdx3SupportedVersion = "3.0.1"

func NewSPDX3() *Spdx3 {
	return &Spdx3{}
}

// Spdx3 decodes SPDX 3 documents serialized as JSON-LD. SPDX 3 has no
// tag-value form.
type Spdx3 struct {
	opts renderOpts
}

func (s *Spdx3) Parse(r io.ReadSeeker) (*Sbom, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	version, ok := spdx3Version(data)
	if !ok {
		return nil, errors.New("not an SPDX 3 document")
	}
	format := "SPDX " + version
	if version != spdx3SupportedVersion {
		return nil, &RecognizedFormatError{
			Format: format,
			Err:    fmt.Errorf("SPDX %s is not supported, only SPDX %s", version, spdx3SupportedVersion),
		}
	}

	env, err := spdx3.NewParser().Parse(bytes.NewReader(data))
	if err != nil {
		return nil, &RecognizedFormatError{Format: format, Err: err}
	}
	return spdx3ToSbom(env, version), nil
}

// spdx3Version returns the SPDX release a JSON document declares through its
// top-level @context, which is a single URL or a list of them. It reports
// false for anything that is not an SPDX 3 JSON-LD document, including SPDX 2
// JSON, which has no @context.
func spdx3Version(data []byte) (string, bool) {
	var top struct {
		Context json.RawMessage `json:"@context"`
	}
	if err := json.Unmarshal(data, &top); err != nil || len(top.Context) == 0 {
		return "", false
	}

	var contexts []string
	var single string
	if err := json.Unmarshal(top.Context, &single); err == nil {
		contexts = []string{single}
	} else {
		var list []json.RawMessage
		if err := json.Unmarshal(top.Context, &list); err != nil {
			return "", false
		}
		for _, item := range list {
			// A list may also hold inline context objects, which name no
			// release.
			if err := json.Unmarshal(item, &single); err == nil {
				contexts = append(contexts, single)
			}
		}
	}

	for _, c := range contexts {
		rest, ok := strings.CutPrefix(c, spdx3ContextPrefix)
		if !ok {
			continue
		}
		minor, _, _ := strings.Cut(rest, "/")
		return "3." + minor, true
	}
	return "", false
}

// spdx3ToSbom maps an SPDX 3 document onto the SBOM model, reading what the
// SPDX 2 decoder reads from the equivalent SPDX 2 fields.
func spdx3ToSbom(env *spdx3.Envelope, version string) *Sbom {
	bom := &Sbom{
		Generator: &Generator{},
		Asset:     &Asset{Platform: &Platform{}},
		Packages:  []*Package{},
	}

	// Packages first, keyed by their spdxId, so the relationships below can
	// find them however the graph is ordered.
	pkgByID := map[string]*Package{}
	for _, node := range env.Graph {
		switch n := node.(type) {
		case *software.Package:
			pkg := spdx3Package(n)
			bom.Packages = append(bom.Packages, pkg)
			if id := n.GetSPDXID(); id != "" {
				pkgByID[id] = pkg
			}
			if n.PrimaryPurpose == software.SoftwarePurposeOperatingSystem {
				bom.Asset.Platform = &Platform{
					Name:    pkg.Name,
					Version: pkg.Version,
					Title:   pkg.Description,
					Family:  familyMap[pkg.Name],
					Cpes:    pkg.Cpes,
				}
			}
		case *core.SpdxDocument:
			bom.Asset.Name = n.Name
			spdx3ReadGenerator(bom.Generator, n.CreationInfo)
		}
	}

	declared := map[*Package][]string{}
	concluded := map[*Package][]string{}
	deps := map[string][]string{}
	for _, node := range env.Graph {
		rel, ok := spdx3Relationship(node)
		if !ok || rel.From == nil {
			continue
		}
		from, ok := pkgByID[rel.From.GetSPDXID()]
		if !ok {
			continue
		}
		for _, to := range rel.To {
			switch rel.RelationshipType {
			case core.RelationshipTypeHasDeclaredLicense:
				if v := spdx3LicenseValue(to); v != "" {
					declared[from] = append(declared[from], v)
				}
			case core.RelationshipTypeHasConcludedLicense:
				if v := spdx3LicenseValue(to); v != "" {
					concluded[from] = append(concluded[from], v)
				}
			case core.RelationshipTypeDependsOn:
				if dep, ok := pkgByID[to.GetSPDXID()]; ok && dep != from {
					deps[BomRefFor(from)] = append(deps[BomRefFor(from)], BomRefFor(dep))
				}
			}
		}
	}

	for _, pkg := range bom.Packages {
		spdx3ReadLicensing(pkg, declared[pkg], concluded[pkg])
	}
	for _, from := range slices.Sorted(maps.Keys(deps)) {
		refs := slices.Compact(slices.Sorted(slices.Values(deps[from])))
		bom.Dependencies = append(bom.Dependencies, &Dependency{Ref: from, DependencyRefs: refs})
	}

	spdx3Platform(bom, version)
	return bom
}

// spdx3Relationship returns the relationship a graph node is, including the
// subclasses that add lifecycle scope or assessment data to one.
func spdx3Relationship(node spdx3types.Node) (*core.Relationship, bool) {
	switch n := node.(type) {
	case *core.Relationship:
		return n, true
	case *core.LifecycleScopedRelationship:
		return &n.Relationship, true
	}
	return nil, false
}

func spdx3Package(n *software.Package) *Package {
	pkg := &Package{
		Name:        n.Name,
		Version:     n.PackageVersion,
		Description: n.Description,
		Purl:        n.PackageUrl,
		Cpes:        []string{},
	}
	for _, id := range n.ExternalIdentifier {
		switch id.ExternalIdentifierType {
		case core.ExternalIdentifierTypeCpe23, core.ExternalIdentifierTypeCpe22:
			pkg.Cpes = append(pkg.Cpes, id.Identifier)
		case core.ExternalIdentifierTypePackageUrl:
			// software_packageUrl is the property the spec gives a package's
			// purl; an identifier of type packageUrl says the same thing and
			// is what some producers write instead.
			if pkg.Purl == "" {
				pkg.Purl = id.Identifier
			}
		}
	}
	if purl, err := packageurl.FromString(pkg.Purl); pkg.Purl != "" && err == nil {
		pkg.Type = purl.Type
	}
	if c := strings.TrimSpace(n.CopyrightText); c != "" && !strings.EqualFold(c, "NOASSERTION") {
		pkg.Copyright = []string{c}
	}
	if n.SuppliedBy != nil {
		pkg.Supplier = strings.TrimSpace(n.SuppliedBy.GetName())
	}
	return pkg
}

// spdx3LicenseValue returns the license a licensing relationship points at:
// the expression of a simple license expression, or the name of any other
// license element.
func spdx3LicenseValue(node spdx3types.Node) string {
	if node == nil {
		return ""
	}
	if le, ok := node.(*simplelicensing.LicenseExpression); ok {
		return importedLicenseValue(le.LicenseExpression)
	}
	return importedLicenseValue(node.GetName())
}

// spdx3ReadLicensing records a package's declared and concluded licenses the
// way the other importers do (see readNodeLicensing): one entry per stated
// license, no location and no confidence, and the legacy scalar set to the
// first declared license, else the first concluded one.
func spdx3ReadLicensing(pkg *Package, declared, concluded []string) {
	for _, v := range declared {
		if entry := DeclaredLicense(v); entry != nil {
			pkg.Licenses = append(pkg.Licenses, entry)
		}
	}
	for _, v := range concluded {
		if entry := ConcludedLicense(v, "", 0); entry != nil {
			pkg.Licenses = append(pkg.Licenses, entry)
		}
	}
	switch {
	case len(declared) > 0:
		pkg.License = declared[0]
	case len(concluded) > 0:
		pkg.License = concluded[0]
	}
}

// spdx3ReadGenerator names the generator after the first tool the document was
// created with, and its vendor after the first agent that created it.
func spdx3ReadGenerator(g *Generator, ci *core.CreationInfo) {
	if ci == nil {
		return
	}
	for _, tool := range ci.CreatedUsing {
		if name := strings.TrimSpace(tool.GetName()); name != "" {
			g.Name, g.Version = spdxSplitTool(name)
			break
		}
	}
	for _, agent := range ci.CreatedBy {
		if name := strings.TrimSpace(agent.GetName()); name != "" {
			g.Vendor = name
			break
		}
	}
}

// spdx3Platform sets the platform of an imported SPDX 3 document the way the
// SPDX 2 decoder does when no package is marked as the operating system: the
// distro qualifier of the package URLs names it, and the asset is named for
// that distro. Failing both, the platform is the document format.
func spdx3Platform(bom *Sbom, version string) {
	if bom.Asset.Platform.GetName() != "" {
		return
	}

	var pf *Platform
	var name string
	for _, pkg := range bom.Packages {
		if pkg.Purl == "" {
			continue
		}
		purl, err := packageurl.FromString(pkg.Purl)
		if err != nil {
			continue
		}
		var distro string
		if pf, distro = purlDistroPlatform(purl, pf); distro != "" {
			name = distro
		}
	}

	if pf == nil {
		bom.Asset.Platform = &Platform{
			Name:    "spdx",
			Version: "SPDX-" + version,
			Title:   "SPDX",
		}
		return
	}
	bom.Asset.Platform = pf
	if name != "" {
		bom.Asset.Name = name
	}
}
