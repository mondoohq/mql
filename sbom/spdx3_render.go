// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/carabiner-dev/spdx3"
	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/simplelicensing"
	"github.com/carabiner-dev/spdx3/profiles/software"
)

func (s *Spdx3) ApplyOptions(opts ...renderOption) {
	for _, opt := range opts {
		opt(&s.opts)
	}
}

// Convert builds an SPDX 3.0.1 document. It carries what the SPDX 2.3
// renderer does, in SPDX 3's terms: packages with their purl, CPEs, hashes,
// supplier and copyright; licenses as hasDeclaredLicense and
// hasConcludedLicense relationships; and dependencies as dependsOn
// relationships.
func (s *Spdx3) Convert(bom *Sbom) (any, error) {
	if bom == nil {
		return nil, errors.New("no SBOM to convert to SPDX 3")
	}
	return newSpdx3Writer(bom).build(bom), nil
}

func (s *Spdx3) Render(w io.Writer, bom *Sbom) error {
	doc, err := s.Convert(bom)
	if err != nil {
		return err
	}
	env, ok := doc.(*spdx3.Envelope)
	if !ok {
		return errors.New("SPDX 3 conversion did not produce a document")
	}
	return (&spdx3.Renderer{}).Render(env, w)
}

// spdx3Writer carries what building one document needs.
type spdx3Writer struct {
	namespace string
	env       *spdx3.Envelope
	counter   int

	// One element per distinct license expression and per supplier, shared by
	// every package that references it.
	licenses  map[string]*simplelicensing.LicenseExpression
	suppliers map[string]*core.Organization
}

func newSpdx3Writer(bom *Sbom) *spdx3Writer {
	return &spdx3Writer{
		namespace: spdxDocumentNamespace(spdxDocumentName(bom)),
		env:       spdx3.NewEnvelope(),
		licenses:  map[string]*simplelicensing.LicenseExpression{},
		suppliers: map[string]*core.Organization{},
	}
}

// newID mints an element identifier within the document's namespace. SPDX 3
// identifies every element with an IRI.
func (w *spdx3Writer) newID(kind string) string {
	w.counter++
	return fmt.Sprintf("%s#%s-%d", w.namespace, kind, w.counter)
}

func (w *spdx3Writer) build(bom *Sbom) *spdx3.Envelope {
	creation := w.creationInfo(bom.GetGenerator())

	// bom_ref → package element, so the dependency graph, which references
	// packages by bom_ref, can be written as relationships. A package present
	// at several install locations shares a bom_ref and is written once, as
	// the SPDX 2.3 and CycloneDX renderers do.
	byRef := map[string]*software.Package{}
	var packages []*software.Package
	for _, pkg := range bom.GetPackages() {
		ref := BomRefFor(pkg)
		if _, ok := byRef[ref]; ok {
			continue
		}
		p := w.pkg(pkg)
		byRef[ref] = p
		packages = append(packages, p)
		w.env.Graph.AddNode(p)
		w.pkgLicenses(pkg, p)
	}

	dependedOn := map[*software.Package]bool{}
	for _, dep := range bom.GetDependencies() {
		from, ok := byRef[dep.GetRef()]
		if !ok {
			continue
		}
		for _, ref := range dep.GetDependencyRefs() {
			to, ok := byRef[ref]
			if !ok || to == from {
				continue
			}
			w.env.Graph.Relate(w.newID("relationship"), from, core.RelationshipTypeDependsOn, to)
			dependedOn[to] = true
		}
	}

	// The bill of materials is about the packages nothing else in it depends
	// on; the rest are reached through their relationships. With no
	// dependency information every package is top-level.
	sbomElement := software.NewSbom(w.newID("sbom"), software.SbomTypeAnalyzed)
	for _, p := range packages {
		if !dependedOn[p] {
			sbomElement.AddRootElement(p)
		}
	}
	w.env.Graph.AddNode(sbomElement)

	document := core.NewSpdxDocument(w.namespace)
	document.Name = spdxDocumentName(bom)
	document.ProfileConformance = []core.ProfileIdentifierType{
		core.ProfileIdentifierTypeCore,
		core.ProfileIdentifierTypeSoftware,
		core.ProfileIdentifierTypeSimpleLicensing,
	}
	document.AddRootElement(sbomElement)
	w.env.Graph.AddNode(document)

	// Said once, and shared by every element.
	w.env.Graph.SetCreationInfo(creation)
	return w.env
}

// creationInfo credits the generator: its vendor as the organization that
// created the document, the generator itself as the tool used. SPDX 3 requires
// a creator, so a generator naming no vendor is credited as a software agent
// under its own name, and one naming nothing at all as an anonymous
// organization, the placeholder the SPDX 2.3 renderer writes.
func (w *spdx3Writer) creationInfo(g *Generator) *core.CreationInfo {
	creation := core.NewCreationInfo(time.Now().UTC())

	tool := spdxToolIdentifier(g)
	switch vendor := strings.TrimSpace(g.GetVendor()); {
	case vendor != "":
		agent := core.NewOrganization(w.newID("agent"), vendor)
		w.env.Graph.AddNode(agent)
		creation.CreatedBy = append(creation.CreatedBy, agent)
	case tool != "":
		agent := core.NewSoftwareAgent(w.newID("agent"), tool)
		w.env.Graph.AddNode(agent)
		creation.CreatedBy = append(creation.CreatedBy, agent)
	default:
		agent := core.NewOrganization(w.newID("agent"), spdxAnonymousCreator)
		w.env.Graph.AddNode(agent)
		creation.CreatedBy = append(creation.CreatedBy, agent)
	}

	if tool != "" {
		element := core.NewTool(w.newID("tool"), tool)
		w.env.Graph.AddNode(element)
		creation.CreatedUsing = append(creation.CreatedUsing, element)
	}
	return creation
}

func (w *spdx3Writer) pkg(pkg *Package) *software.Package {
	p := software.NewPackage(w.namespace+"#"+string(NewSPDXPackageID(pkg)), pkg.GetName())
	p.PackageVersion = pkg.GetVersion()
	p.Description = pkg.GetDescription()

	// software_packageUrl is the property SPDX 3 gives a package's purl. It is
	// also written as a packageUrl identifier, which is where some readers
	// look for it.
	if purl := pkg.GetPurl(); purl != "" {
		p.PackageUrl = purl
		p.ExternalIdentifier = append(p.ExternalIdentifier, spdx3Identifier(core.ExternalIdentifierTypePackageUrl, purl))
	}
	// CPEs are always written, as the SPDX 2.3 renderer writes them.
	for _, cpe := range pkg.GetCpes() {
		p.ExternalIdentifier = append(p.ExternalIdentifier, spdx3Identifier(core.ExternalIdentifierTypeCpe23, cpe))
	}

	for _, h := range pkg.GetHashes() {
		if alg, ok := spdx3HashAlgorithm(h.GetAlg()); ok && h.GetValue() != "" {
			p.VerifiedUsing = append(p.VerifiedUsing, core.NewHash(alg, h.GetValue()))
		}
	}

	if c := strings.TrimSpace(strings.Join(pkg.GetCopyright(), "\n")); c != "" {
		p.CopyrightText = c
	}
	if supplier := strings.TrimSpace(pkg.GetSupplier()); supplier != "" {
		p.SuppliedBy = w.supplier(supplier)
	}

	// SPDX 3 has no package file name. It says the same with a File element
	// related to the package, which would add an element per package the
	// model holds no further information about, so the location is left out.
	return p
}

func spdx3Identifier(t core.ExternalIdentifierType, value string) core.ExternalIdentifier {
	return core.ExternalIdentifier{
		Type:                   "ExternalIdentifier",
		ExternalIdentifierType: t,
		Identifier:             value,
	}
}

// spdx3HashAlgorithm translates a hash algorithm from the CycloneDX spelling
// the model uses ("SHA-256", "SHA3-256", "BLAKE2b-256") into the SPDX 3
// vocabulary ("sha256", "sha3_256", "blake2b256"). An algorithm SPDX 3 has no
// name for is reported as not ok and left out.
func spdx3HashAlgorithm(alg string) (core.HashAlgorithm, bool) {
	name := strings.ToLower(strings.TrimSpace(alg))
	if rest, ok := strings.CutPrefix(name, "sha3-"); ok {
		name = "sha3_" + rest
	}
	name = strings.ReplaceAll(name, "-", "")
	switch a := core.HashAlgorithm(name); a {
	case core.HashAlgorithmMd5, core.HashAlgorithmSha1, core.HashAlgorithmSha224,
		core.HashAlgorithmSha256, core.HashAlgorithmSha384, core.HashAlgorithmSha512,
		core.HashAlgorithmSha3_224, core.HashAlgorithmSha3_256, core.HashAlgorithmSha3_384,
		core.HashAlgorithmSha3_512, core.HashAlgorithmBlake2b256, core.HashAlgorithmBlake2b384,
		core.HashAlgorithmBlake2b512, core.HashAlgorithmBlake3:
		return a, true
	}
	return "", false
}

func (w *spdx3Writer) supplier(name string) *core.Organization {
	if org, ok := w.suppliers[name]; ok {
		return org
	}
	org := core.NewOrganization(w.newID("agent"), name)
	w.env.Graph.AddNode(org)
	w.suppliers[name] = org
	return org
}

// pkgLicenses states a package's licenses, which SPDX 3 does with a
// relationship to a license element rather than with a field.
//
// The concluded license is written only when one was concluded. The SPDX 2.3
// renderer repeats the declared license there, because licenseConcluded is a
// field every package has and many readers take it as the package's license.
// In SPDX 3 a missing hasConcludedLicense relationship states nothing, so the
// repeat is not needed, and leaving it out keeps a round trip from importing
// a conclusion nobody made.
func (w *spdx3Writer) pkgLicenses(pkg *Package, p *software.Package) {
	// Free-form license names become LicenseRef-* identifiers, as in the SPDX
	// 2.3 rendering; an SPDX 3 license expression accepts them without a
	// separate definition.
	unused := extractedLicenseSet{}
	declared := spdxLicense(declaredLicenses(pkg), pkg.GetLicense(), unused)
	concluded := spdxLicense(concludedLicenses(pkg), "", unused)

	if license := w.license(declared); license != nil {
		w.env.Graph.Relate(w.newID("relationship"), p, core.RelationshipTypeHasDeclaredLicense, license)
	}
	if license := w.license(concluded); license != nil {
		w.env.Graph.Relate(w.newID("relationship"), p, core.RelationshipTypeHasConcludedLicense, license)
	}
}

// license returns the element for a license expression, writing each distinct
// expression once. NONE and NOASSERTION are not licenses and get no element.
func (w *spdx3Writer) license(expression string) *simplelicensing.LicenseExpression {
	expression = strings.TrimSpace(expression)
	if expression == "" || strings.EqualFold(expression, "NONE") || strings.EqualFold(expression, spdxNoAssertionValue) {
		return nil
	}
	if license, ok := w.licenses[expression]; ok {
		return license
	}
	license := &simplelicensing.LicenseExpression{

		SPDXID:            w.newID("license"),
		Type:              "simplelicensing_LicenseExpression",
		LicenseExpression: expression,
	}
	w.env.Graph.AddNode(license)
	w.licenses[expression] = license
	return license
}
