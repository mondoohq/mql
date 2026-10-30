// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/reader"
	protobom_sbom "github.com/protobom/protobom/pkg/sbom"
)

func NewProtobom() *Protobom {
	return &Protobom{}
}

type Protobom struct {
	opts renderOpts
}

func (s *Protobom) Parse(f io.ReadSeeker) (*Sbom, error) {
	reader := reader.New()

	document, err := reader.ParseStream(f)
	if err != nil {
		return nil, err
	}

	return s.convertToSbom(document), nil
}

// readNodeLicensing carries a node's licensing across into the package.
//
// This is an importer: the document being read was produced by somebody else,
// and dropping what it stated about a package's licensing loses information
// that cannot be recovered from anywhere else in the file. Every field below
// was already parsed and then discarded.
//
// protobom keeps the same declared/concluded distinction the model does.
// `licenses` is what the package says about itself and `license_concluded` is
// what the document's producer determined, so they map onto the two
// acquisitions rather than being merged into one list.
func readNodeLicensing(pkg *Package, node *protobom_sbom.Node) {
	for _, l := range node.GetLicenses() {
		if entry := DeclaredLicense(importedLicenseValue(l)); entry != nil {
			pkg.Licenses = append(pkg.Licenses, entry)
		}
	}

	// No location: the model documents it as the file a license was read from,
	// and protobom has no field holding one. license_comments is free-form
	// prose about how the license fields were arrived at -- "concluded from
	// LICENSE" is a sentence, not a path -- so putting it there would make the
	// field mean two different things depending on who wrote it.
	//
	// No confidence either, and that is a zero rather than a default. The
	// format carries no score, and the model spells "nobody measured this" as
	// 0: reporting 1.0 would put an imported conclusion that was never scored
	// alongside one that scored perfectly, which is the distinction the field
	// exists to preserve. Both renderers say nothing about a zero.
	if entry := ConcludedLicense(importedLicenseValue(node.GetLicenseConcluded()), "", 0); entry != nil {
		pkg.Licenses = append(pkg.Licenses, entry)
	}

	// The legacy scalar keeps being written, as every other producer in this
	// package does, so a consumer that has not migrated to the list still sees
	// a license. It takes the first DECLARED entry, which is the convention the
	// field's own documentation asks producers to follow, falling back to the
	// concluded value when the document declared none: a scalar that stayed
	// empty while a license was in fact stated is the failure the fallback
	// exists to prevent.
	for _, l := range pkg.Licenses {
		if l.GetAcquisition() == LicenseAcquisition_LICENSE_ACQUISITION_DECLARED {
			pkg.License = licenseValueOf(l)
			break
		}
	}
	if pkg.License == "" {
		pkg.License = importedLicenseValue(node.GetLicenseConcluded())
	}

	if c := strings.TrimSpace(node.GetCopyright()); c != "" {
		pkg.Copyright = []string{c}
	}

	for _, person := range node.GetSuppliers() {
		if name := strings.TrimSpace(person.GetName()); name != "" {
			pkg.Supplier = name
			break
		}
	}
}

// importedLicenseValue returns a license value from an imported document, or ""
// when the document is using SPDX's vocabulary to say it has none to give.
//
// NONE and NOASSERTION are how the spec states absence: one means the package is
// under no license, the other that the document does not know. Neither is a
// license, but both are identifier-shaped, so nothing about their spelling stops
// them becoming a license named "NONE" -- reported to a consumer as a fact about
// the package, and indistinguishable from one the document actually stated.
//
// protobom already drops NOASSERTION and passes NONE through, so only one of the
// two reaches this today. Both are handled because which sentinels a parser
// filters is its decision and not a contract, and the failure is silent in
// either direction.
func importedLicenseValue(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "NONE") || strings.EqualFold(value, "NOASSERTION") {
		return ""
	}
	return value
}

// licenseValueOf returns whichever of the three mutually exclusive value fields
// an entry carries, which is what the scalar holds.
func licenseValueOf(l *License) string {
	switch {
	case l.GetExpression() != "":
		return l.GetExpression()
	case l.GetSpdxId() != "":
		return l.GetSpdxId()
	default:
		return l.GetName()
	}
}

func (s *Protobom) convertToSbom(doc *protobom_sbom.Document) *Sbom {
	bom := &Sbom{
		// Platform is set below only for a document that names an operating
		// system, and most do not. It is initialized here rather than left nil
		// because every renderer reads it unguarded, so an imported document
		// carrying no OS crashed whatever it was handed to -- including this
		// package's own CycloneDX and SPDX renderers, which is the obvious
		// thing to do with a document you just parsed.
		Asset:    &Asset{Platform: &Platform{}},
		Packages: make([]*Package, 0),
	}

	// The name is read after the nil check rather than before it. Reading it
	// first made the guard below unreachable: a document with no metadata
	// panicked on the line above it.
	if doc == nil || doc.Metadata == nil {
		return bom
	}
	bom.Asset.Name = doc.Metadata.Name

	if len(doc.Metadata.Tools) > 0 {
		bom.Generator = &Generator{
			Name:    doc.Metadata.Tools[0].Name,
			Version: doc.Metadata.Tools[0].Version,
			Vendor:  doc.Metadata.Tools[0].Vendor,
		}
	}

	if doc.GetNodeList() == nil || len(doc.GetNodeList().GetNodes()) == 0 {
		return bom // no nodes, return empty SBOM
	}

	// Node ID -> the bom-ref the package will be known by, so the edges below
	// can be translated out of protobom's node space into the same reference
	// space Sbom.Dependencies uses everywhere else (BomRefFor).
	refByNode := map[string]string{}

	for _, node := range doc.GetNodeList().GetNodes() {
		pkg := &Package{
			Name:    node.Name,
			Version: node.Version,
		}
		readNodeLicensing(pkg, node)

		for key, identifier := range node.GetIdentifiers() {
			if key == int32(protobom_sbom.SoftwareIdentifierType_PURL) {
				pkg.Purl = identifier
				if purl, err := packageurl.FromString(identifier); err == nil {
					pkg.Type = purl.Type
				}
			} else if key == int32(protobom_sbom.SoftwareIdentifierType_CPE23) {
				pkg.Cpes = append(pkg.Cpes, identifier)
			} else if key == int32(protobom_sbom.SoftwareIdentifierType_CPE22) {
				pkg.Cpes = append(pkg.Cpes, identifier)
			}
		}

		if !s.opts.IncludeCPE {
			// if CPEs are not included, clear them
			pkg.Cpes = nil
		}

		// A FILE node describes a file inside a package, not a package, so it is
		// the one thing that must not become one.
		if node.GetType() == protobom_sbom.Node_FILE {
			continue
		}

		// primary_package_purpose is OPTIONAL in SPDX 2.3 and most producers omit
		// it -- mql's own SPDX renderer among them. Keying the import on it
		// dropped EVERY package whose purpose was unstated, so an SPDX document
		// round-tripped through this package arrived empty: `Render` then `Parse`
		// of a three-package SBOM returned zero. `xgrep scan --sbom <spdx>` read
		// that as a project with no dependencies rather than as a document it
		// could not interpret, which is the silent-empty failure the format's
		// optional fields are most likely to produce.
		//
		// The node TYPE is the discriminator that always holds: protobom states
		// PACKAGE or FILE for every node, where purpose is advisory. Purpose is
		// still read, for the one thing it uniquely says -- that a package is the
		// operating system, which makes it the asset's platform as well.
		if purposes := node.GetPrimaryPurpose(); len(purposes) > 0 &&
			purposes[0] == protobom_sbom.Purpose_OPERATING_SYSTEM {
			bom.Asset.Platform = &Platform{
				Name:    pkg.Name,
				Version: pkg.Version,
				Title:   pkg.Description,
			}
			bom.Asset.Platform.Family = familyMap[pkg.Name]
			bom.Asset.Platform.Cpes = pkg.Cpes
		}
		bom.Packages = append(bom.Packages, pkg)
		// Only a node that became a package can be an edge endpoint: an edge
		// naming anything else is dropped below rather than emitted as a
		// reference to something the SBOM does not contain.
		if id := node.GetId(); id != "" {
			refByNode[id] = BomRefFor(pkg)
		}
	}

	bom.Dependencies = protobomDependencies(doc, refByNode)

	return bom
}

// protobomDependencies reads the package->package graph out of a protobom
// document's edges, the read counterpart to the SPDX renderer's DEPENDS_ON
// relationships (spdx.go).
//
// Without this the graph was write-only on the SPDX side: the renderer emitted
// every edge and the parser read nodes alone, so an SBOM round-tripped through
// SPDX lost its dependency structure entirely while CycloneDX kept it. The
// CycloneDX reader gained its counterpart in #10659; this is the same fix on
// the other format, and the two now agree.
//
// Both directions are read because a producer may state either and they carry
// the same fact: SPDX has DEPENDS_ON and DEPENDENCY_OF, and protobom maps them
// to Edge_dependsOn and Edge_dependencyOf. A dependencyOf edge is INVERTED on
// import -- its `From` is the dependency and each `To` is a dependent -- so
// that both spellings land in one direction downstream.
//
// Deliberately NOT read: Edge_devDependency and the other typed edges. This
// field carries the production dependency graph, and folding a dev-scoped edge
// into it would state that a dev-only package is depended on in production,
// which is a stronger claim than the document made.
func protobomDependencies(doc *protobom_sbom.Document, refByNode map[string]string) []*Dependency {
	if doc.GetNodeList() == nil || len(refByNode) == 0 {
		return nil
	}
	// Accumulated by source ref, since two edges may share one `From` and a
	// dependencyOf edge contributes to a `From` that is not its own.
	refs := map[string][]string{}
	seen := map[[2]string]bool{}
	add := func(from, to string) {
		if from == "" || to == "" || from == to || seen[[2]string{from, to}] {
			return
		}
		seen[[2]string{from, to}] = true
		refs[from] = append(refs[from], to)
	}

	for _, e := range doc.GetNodeList().GetEdges() {
		from, ok := refByNode[e.GetFrom()]
		if !ok {
			continue
		}
		for _, toNode := range e.GetTo() {
			to, ok := refByNode[toNode]
			if !ok {
				continue
			}
			switch e.GetType() {
			case protobom_sbom.Edge_dependsOn:
				add(from, to)
			case protobom_sbom.Edge_dependencyOf:
				add(to, from)
			}
		}
	}
	if len(refs) == 0 {
		return nil
	}
	// Sorted so a document's edge order does not decide the output's, which
	// keeps a re-render byte-stable and a test assertable.
	out := make([]*Dependency, 0, len(refs))
	for _, from := range slices.Sorted(maps.Keys(refs)) {
		slices.Sort(refs[from])
		out = append(out, &Dependency{Ref: from, DependencyRefs: refs[from]})
	}
	return out
}
