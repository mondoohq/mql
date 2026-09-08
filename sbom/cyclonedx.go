// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
)

func NewCycloneDX(format string) *CycloneDX {
	switch format {
	case FormatCycloneDxXML:
		return &CycloneDX{
			Format: cyclonedx.BOMFileFormatXML,
		}
	default:
		return &CycloneDX{
			Format: cyclonedx.BOMFileFormatJSON,
		}
	}
}

var _ Decoder = &CycloneDX{}

type CycloneDX struct {
	opts   renderOpts
	Format cyclonedx.BOMFileFormat
}

func (ccx *CycloneDX) convertToCycloneDx(bom *Sbom) (*cyclonedx.BOM, error) {
	sbom := cyclonedx.NewBOM()
	sbom.SerialNumber = uuid.New().URN()
	// The subject's name, which the root component below is required to carry.
	// Read through the getters: a hand-built BOM need not populate Asset or
	// Generator, and a renderer that dies on a missing metadata field reports
	// nothing about the packages it could have listed.
	subject := unnamedSubject
	if name := strings.TrimSpace(bom.GetAsset().GetName()); name != "" {
		subject = name
	}

	sbom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools:     cycloneDXTools(bom.GetGenerator()),
		Component: &cyclonedx.Component{
			// Deterministic (was a per-render UUID) so the document's root
			// component id is stable across renders.
			BOMRef: "root:" + subject,
			// TODO: understand the device type
			// Type: cyclonedx.ComponentTypeContainer,
			Type: cyclonedx.ComponentTypeDevice,
			Name: subject,
		},
	}

	components := []cyclonedx.Component{}
	// emitted tracks the component bom-refs already added, so a document never
	// contains a duplicate bom-ref (invalid CycloneDX) when two packages share a
	// purl, and so the dependency graph below can drop edges to absent components.
	emitted := map[string]bool{}

	// add os as component, when the asset names one.
	//
	// A scanned host always does. A document parsed from somebody else's SBOM
	// often does not, because most SBOMs describe an application rather than a
	// machine, and emitting the component anyway produced an operating system
	// with no name -- `"bom-ref": "os:"` -- that a consumer has to recognise as
	// junk and filter.
	//
	// The nil check is not redundant with it. Platform is a pointer, and this
	// was the only renderer that dereferenced it unguarded: SPDX and the table
	// both render a BOM without one, and cnquery_bom.go guards the same field,
	// so the package already treats a nil platform as something that reaches it.
	if platform := bom.GetAsset().GetPlatform(); platform.GetName() != "" {
		cpe := ""
		if len(platform.GetCpes()) > 0 {
			cpe = platform.GetCpes()[0]
		}

		osRef := "os:" + platform.GetName()
		emitted[osRef] = true
		components = append(components, cyclonedx.Component{
			BOMRef:  osRef,
			Type:    cyclonedx.ComponentTypeOS,
			Name:    platform.GetName(),
			Version: platform.GetVersion(),
			CPE:     cpe,
		})
	}

	// add os packages as components
	for i := range bom.Packages {
		pkg := bom.Packages[i]
		cpe := ""
		if len(pkg.Cpes) > 0 && ccx.opts.IncludeCPE {
			cpe = pkg.Cpes[0]
		}

		fileLocations := []cyclonedx.EvidenceOccurrence{}

		// pkg.Location is deprecated, use pkg.Evidences instead
		if pkg.Location != "" {
			fileLocations = append(fileLocations, cyclonedx.EvidenceOccurrence{
				Location: pkg.Location,
			})
		}

		if pkg.EvidenceList != nil && ccx.opts.IncludeEvidence {
			for i := range pkg.EvidenceList {
				e := pkg.EvidenceList[i]
				if e.Type == EvidenceType_EVIDENCE_TYPE_FILE {
					fileLocations = append(fileLocations, cyclonedx.EvidenceOccurrence{
						Location: e.Value,
					})
				}
			}
		}

		var evidence *cyclonedx.Evidence
		if len(fileLocations) > 0 {
			evidence = &cyclonedx.Evidence{
				Occurrences: &fileLocations,
			}
		}

		ref := BomRefFor(pkg)
		if emitted[ref] {
			// Same purl already emitted (a package present at multiple install
			// locations) — dedup so bom-refs stay unique.
			continue
		}
		emitted[ref] = true

		// Concluded licenses and copyright are also stated as evidence, which is
		// what CycloneDX's evidence block is for: they were read out of the
		// files the package ships rather than asserted by it. It is a second
		// view of what component.licenses already carries, not the only home
		// for it, so it follows the same opt-in as the occurrences above rather
		// than being the one part of the block that appears unasked.
		if ccx.opts.IncludeEvidence {
			if concluded := cycloneDXLicenseList(concludedLicenses(pkg)); concluded != nil {
				if evidence == nil {
					evidence = &cyclonedx.Evidence{}
				}
				evidence.Licenses = concluded
			}
			if len(pkg.Copyright) > 0 {
				if evidence == nil {
					evidence = &cyclonedx.Evidence{}
				}
				copyrights := make([]cyclonedx.Copyright, 0, len(pkg.Copyright))
				for _, c := range pkg.Copyright {
					copyrights = append(copyrights, cyclonedx.Copyright{Text: c})
				}
				evidence.Copyright = &copyrights
			}
		}

		bomPkg := cyclonedx.Component{
			BOMRef:      ref,
			Type:        cyclonedx.ComponentTypeLibrary,
			Name:        pkg.Name,
			Version:     pkg.Version,
			PackageURL:  pkg.Purl,
			CPE:         cpe,
			Evidence:    evidence,
			Description: pkg.Description,
			Licenses:    cycloneDXComponentLicenses(pkg),
			Copyright:   strings.Join(pkg.Copyright, "\n"),
		}
		if pkg.Supplier != "" {
			bomPkg.Supplier = &cyclonedx.OrganizationalEntity{Name: pkg.Supplier}
		}
		if pkg.Scope == PackageScopeDev {
			bomPkg.Scope = cyclonedx.ScopeExcluded
		}
		if len(pkg.Hashes) > 0 {
			hashes := make([]cyclonedx.Hash, 0, len(pkg.Hashes))
			for _, h := range pkg.Hashes {
				hashes = append(hashes, cyclonedx.Hash{
					Algorithm: cyclonedx.HashAlgorithm(h.Alg),
					Value:     h.Value,
				})
			}
			bomPkg.Hashes = &hashes
		}

		components = append(components, bomPkg)
	}

	sbom.Components = &components

	// Emit the package→package dependency graph (CycloneDX `dependencies`), each
	// endpoint referenced by the component bom-ref set above.
	if len(bom.Dependencies) > 0 {
		deps := make([]cyclonedx.Dependency, 0, len(bom.Dependencies))
		for _, d := range bom.Dependencies {
			// Skip edges whose source isn't an emitted component, and prune
			// targets that aren't — a document must not reference an absent
			// bom-ref (matches the SPDX renderer's defensive behavior).
			if !emitted[d.Ref] {
				continue
			}
			dependsOn := make([]string, 0, len(d.DependencyRefs))
			for _, r := range d.DependencyRefs {
				if emitted[r] {
					dependsOn = append(dependsOn, r)
				}
			}
			deps = append(deps, cyclonedx.Dependency{
				Ref:          d.Ref,
				Dependencies: &dependsOn,
			})
		}
		sbom.Dependencies = &deps
	}

	return sbom, nil
}

func (s *CycloneDX) ApplyOptions(opts ...renderOption) {
	for _, opt := range opts {
		opt(&s.opts)
	}
}

func (ccx *CycloneDX) Convert(bom *Sbom) (any, error) {
	return ccx.convertToCycloneDx(bom)
}

func (ccx *CycloneDX) Render(w io.Writer, bom *Sbom) error {
	sbom, err := ccx.convertToCycloneDx(bom)
	if err != nil {
		return err
	}
	enc := cyclonedx.NewBOMEncoder(w, ccx.Format)
	enc.SetPretty(true)
	return enc.Encode(sbom)
}

func (ccx *CycloneDX) Parse(r io.ReadSeeker) (*Sbom, error) {
	doc := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{},
	}
	err := cyclonedx.NewBOMDecoder(r, ccx.Format).Decode(doc)
	if err != nil {
		return nil, err
	}

	return ccx.convertCycloneDxToSbom(doc)
}

func (ccx *CycloneDX) convertCycloneDxToSbom(bom *cyclonedx.BOM) (*Sbom, error) {
	if bom == nil {
		return nil, nil
	}

	// check if the BOM is empty
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Components == nil {
		return nil, errors.New("not a valid cyclone dx BOM")
	}

	rootComponent := bom.Metadata.Component
	title := rootComponent.Description
	version := rootComponent.Version
	if title == "" {
		title = "CycloneDX"
	}
	if version == "" {
		version = bom.SpecVersion.String()
	}
	sbom := &Sbom{
		Asset: &Asset{
			Name: rootComponent.Name,
			Platform: &Platform{
				Name:    "cyclonedx",
				Version: version,
				Title:   title,
			},
		},
		Packages: make([]*Package, 0),
	}

	switch rootComponent.Type {
	case cyclonedx.ComponentTypeOS:
		hostnameId := "//platformid.api.mondoo.app/hostname/" + rootComponent.Name
		sbom.Asset.PlatformIds = append(sbom.Asset.PlatformIds, hostnameId)
	case cyclonedx.ComponentTypeContainer:
		// we need to figure out where to get the container ID from properly. For now, we use the BOMRef
		bomRefId := "//platformid.api.mondoo.app/runtime/docker/images/" + rootComponent.BOMRef
		sbom.Asset.PlatformIds = append(sbom.Asset.PlatformIds, bomRefId)
	}

	if bom.Metadata.Tools != nil {
		if bom.Metadata.Tools.Components != nil {
			// last one wins :-) - we only support one tool
			for _, component := range *bom.Metadata.Tools.Components {
				sbom.Generator = &Generator{
					Name:    component.Name,
					Version: component.Version,
					Vendor:  component.Author,
				}
			}
		}

		// if we have no generator info, fallback to trying tools. these are deprecated
		// but might still be present
		if sbom.Generator == nil && bom.Metadata.Tools.Tools != nil {
			for _, tool := range *bom.Metadata.Tools.Tools {
				sbom.Generator = &Generator{
					Name:    tool.Name,
					Version: tool.Version,
					Vendor:  tool.Vendor,
				}
			}
		}
	}

	for _, component := range *bom.Components {
		pkg := &Package{
			Name:        component.Name,
			Version:     component.Version,
			Purl:        component.PackageURL,
			Description: component.Description,
			// The document's own identity for this component, kept because it
			// is what `dependencies` keys on. A producer chooses its own
			// bom-refs -- a purl, a UUID, an internal id -- and dropping them
			// while keeping the edges verbatim left every edge naming a
			// component the consumer could no longer resolve. BomRefFor
			// prefers this field, so a render/parse/render round-trip now also
			// preserves the refs instead of rewriting them.
			BomRef: component.BOMRef,
		}

		// parse purl to gather package type
		if component.PackageURL != "" {
			url, err := packageurl.FromString(component.PackageURL)
			if err == nil {
				pkg.Type = url.Type
			}
		}

		if component.CPE != "" {
			pkg.Cpes = []string{component.CPE}
		}

		if component.Evidence != nil && component.Evidence.Occurrences != nil && ccx.opts.IncludeEvidence {
			pkg.EvidenceList = make([]*Evidence, 0)
			for _, e := range *component.Evidence.Occurrences {
				pkg.EvidenceList = append(pkg.EvidenceList, &Evidence{
					Type:  EvidenceType_EVIDENCE_TYPE_FILE,
					Value: e.Location,
				})
			}
		}

		switch component.Type {
		case cyclonedx.ComponentTypeOS:
			sbom.Asset.Platform.Name = component.Name
			sbom.Asset.Platform.Version = component.Version
			sbom.Asset.Platform.Title = component.Description
			sbom.Asset.Platform.Family = familyMap[strings.ToLower(component.Name)]
			if len(component.CPE) > 0 {
				sbom.Asset.Platform.Cpes = []string{component.CPE}
			}
			sbom.Packages = append(sbom.Packages, pkg)
		case cyclonedx.ComponentTypeLibrary:
			sbom.Packages = append(sbom.Packages, pkg)
		case cyclonedx.ComponentTypeApplication:
			sbom.Packages = append(sbom.Packages, pkg)
		}
	}

	sbom.Dependencies = cycloneDXDependencies(bom)

	return sbom, nil
}

// cycloneDXDependencies reads the document's package -> package edge graph.
//
// The renderer has always WRITTEN `dependencies`/`dependsOn`; the reader
// discarded it, so Sbom.Dependencies came back empty from Parse and a
// render/parse round-trip silently lost the whole graph. That graph is the only
// thing that distinguishes a transitive dependency something reaches from one
// nothing reaches, so losing it costs a consumer the distinction entirely.
//
// Edges are kept as the document states them, with two exceptions. A self-edge
// is dropped: it is a no-op that some producers emit, and carrying it invites a
// consumer's traversal to loop. An entry with no targets is dropped rather than
// stored as an empty list, because CycloneDX uses it to say "this component was
// considered and depends on nothing", which is the absence of edges rather than
// an edge.
//
// Refs are NOT validated against the component set here. A dangling ref is a
// producer bug, but which components exist is the caller's question and a
// reader that silently drops edges would hide it.
func cycloneDXDependencies(bom *cyclonedx.BOM) []*Dependency {
	if bom.Dependencies == nil || len(*bom.Dependencies) == 0 {
		return nil
	}
	out := make([]*Dependency, 0, len(*bom.Dependencies))
	for _, d := range *bom.Dependencies {
		if d.Ref == "" || d.Dependencies == nil {
			continue
		}
		refs := make([]string, 0, len(*d.Dependencies))
		for _, r := range *d.Dependencies {
			if r == "" || r == d.Ref {
				continue
			}
			refs = append(refs, r)
		}
		if len(refs) == 0 {
			continue
		}
		out = append(out, &Dependency{Ref: d.Ref, DependencyRefs: refs})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

var familyMap = map[string][]string{
	"windows": {"windows", "os"},
	"macos":   {"darwin", "bsd", "unix", "os"},
	"debian":  {"linux", "unix", "os"},
	"ubuntu":  {"linux", "unix", "os"},
	"centos":  {"linux", "unix", "os"},
	"alpine":  {"linux", "unix", "os"},
	"fedora":  {"linux", "unix", "os"},
	"rhel":    {"linux", "unix", "os"},
}

// cycloneDXTools renders the tool that produced the document, or nothing when
// no tool is named.
//
// A component's name is required by the schema, so a generator that names no
// tool cannot be rendered as one: the entry would be a component called "",
// which is the nameless-component shape a consumer has to recognise as junk and
// filter. `tools` is optional, so leaving it out says the same thing honestly.
// The reader already tolerates its absence.
func cycloneDXTools(g *Generator) *cyclonedx.ToolsChoice {
	name := strings.TrimSpace(g.GetName())
	if name == "" {
		return nil
	}
	return &cyclonedx.ToolsChoice{
		Components: &[]cyclonedx.Component{
			{
				Type:    cyclonedx.ComponentTypeApplication,
				Author:  strings.TrimSpace(g.GetVendor()),
				Name:    name,
				Version: strings.TrimSpace(g.GetVersion()),
			},
		},
	}
}

// cycloneDXComponentLicenses renders every license the model carries onto the
// component, each saying how it was arrived at.
//
// Declared and concluded live in one list because `acknowledgement` tells them
// apart, which is what the attribute is for. Putting the concluded ones only
// under evidence would make a consumer reading component.licenses believe the
// package is licensed as it claims, in exactly the case the two disagree and
// the shipped text is the grant.
func cycloneDXComponentLicenses(pkg *Package) *cyclonedx.Licenses {
	if l := cycloneDXLicenseList(pkg.Licenses); l != nil {
		return l
	}
	// No structured list: the legacy scalar is all there is, and it renders as
	// it always did.
	return cycloneDXLicenses(pkg.License)
}

// declaredLicenses returns the package's declared entries. An entry whose
// acquisition the producer did not set counts as declared: it is what the
// scalar always meant, so an unset value keeps the old reading rather than
// silently demoting a license to evidence.
func declaredLicenses(pkg *Package) []*License {
	var out []*License
	for _, l := range pkg.Licenses {
		if l.GetAcquisition() != LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED {
			out = append(out, l)
		}
	}
	return out
}

// concludedLicenses returns the entries read from the files a package ships.
func concludedLicenses(pkg *Package) []*License {
	var out []*License
	for _, l := range pkg.Licenses {
		if l.GetAcquisition() == LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED {
			out = append(out, l)
		}
	}
	return out
}

// cycloneDXLicenseList renders license entries into the CycloneDX shape each
// one's populated field calls for, dropping entries that carry no value.
//
// The three shapes are mutually exclusive in the schema, which is why the
// producer says which kind it has rather than the renderer guessing: a value
// already known to be an expression must not be emitted as an id.
//
// How a license was arrived at travels with it, as CycloneDX 1.6's
// `acknowledgement`. Saying it on the license is what lets a declared and a
// concluded one sit in the same list: the alternative is to encode the
// difference in *where* they are placed, which needs somewhere to put the
// concluded ones and says nothing to a consumer reading a single entry.
//
// A conclusion's confidence and the file it was read from become license
// properties, the schema's own extension point. Neither has a first-class field
// in 1.6, and both are the difference between a certainty and an inference, so
// dropping them loses the reason a consumer would trust one conclusion over
// another.
func cycloneDXLicenseList(licenses []*License) *cyclonedx.Licenses {
	out := make(cyclonedx.Licenses, 0, len(licenses))
	for _, l := range licenses {
		var choice cyclonedx.LicenseChoice
		switch {
		case strings.TrimSpace(l.GetExpression()) != "":
			choice = cyclonedx.LicenseChoice{Expression: strings.TrimSpace(l.GetExpression())}
		case strings.TrimSpace(l.GetSpdxId()) != "":
			choice = cyclonedx.LicenseChoice{
				License: &cyclonedx.License{ID: strings.TrimSpace(l.GetSpdxId())},
			}
		case strings.TrimSpace(l.GetName()) != "":
			choice = cyclonedx.LicenseChoice{
				License: &cyclonedx.License{Name: strings.TrimSpace(l.GetName())},
			}
		default:
			continue
		}

		if ack := cycloneDXAcknowledgement(l.GetAcquisition()); ack != "" {
			// An expression carries it on the choice, an id or a name on the
			// license itself: the schema puts the attribute in both places and
			// only one of the two is populated for any given entry.
			if choice.License != nil {
				choice.License.Acknowledgement = ack
			} else {
				choice.Acknowledgement = &ack
			}
		}
		if props := cycloneDXLicenseProperties(l); props != nil {
			if choice.License != nil {
				choice.License.Properties = props
			} else {
				choice.Properties = props
			}
		}

		out = append(out, choice)
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

// cycloneDXAcknowledgement maps the model's acquisition onto the schema's
// vocabulary, which uses the same two words. An unspecified acquisition renders
// nothing rather than guessing at "declared": the producer did not say, and an
// omitted attribute is how the schema spells that.
func cycloneDXAcknowledgement(a LicenseAcquisition) cyclonedx.LicenseAcknowledgement {
	switch a {
	case LicenseAcquisition_LICENSE_ACQUISITION_DECLARED:
		return cyclonedx.LicenseAcknowledgementDeclared
	case LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED:
		return cyclonedx.LicenseAcknowledgementConcluded
	default:
		return ""
	}
}

// cycloneDXLicenseProperties carries the parts of a conclusion the schema has no
// field for, and only when they say something.
//
// A declared license's confidence is 1.0 by construction -- it is a statement,
// not a measurement -- so emitting it would be noise on every license in every
// document. It is written only for a conclusion, where it is the difference
// between a certainty and an inference.
//
// Full confidence is left out for the same reason, and on the same rule the
// SPDX renderer applies. The model documents 1.0 as the value a license carries
// when it is a statement rather than a measurement, so a conclusion at 1.0 is
// asserting no measurement, which is what an entry with no score attached
// already says. A property that states nothing would still be read by a
// consumer ranking conclusions as a score somebody took.
func cycloneDXLicenseProperties(l *License) *[]cyclonedx.Property {
	props := []cyclonedx.Property{}
	if c := l.GetConfidence(); l.GetAcquisition() == LicenseAcquisition_LICENSE_ACQUISITION_CONCLUDED && c > 0 && c < 1 {
		props = append(props, cyclonedx.Property{
			Name:  "mondoo:license:confidence",
			Value: strconv.FormatFloat(l.GetConfidence(), 'g', -1, 64),
		})
	}
	if loc := strings.TrimSpace(l.GetLocation()); loc != "" {
		props = append(props, cyclonedx.Property{
			Name:  "mondoo:license:location",
			Value: loc,
		})
	}
	if len(props) == 0 {
		return nil
	}
	return &props
}

// cycloneDXLicenses renders a package's declared license as a CycloneDX license
// list, or nil when there is none.
//
// CycloneDX models a license three mutually exclusive ways, and choosing the
// wrong one fails schema validation:
//
//   - expression, for a full SPDX expression such as "MIT OR Apache-2.0";
//   - license.id, for a bare SPDX identifier;
//   - license.name, for anything that is neither.
//
// Package license strings in the wild are all three, so the shape is decided
// per value rather than assumed. A string containing an SPDX operator is an
// expression; one that looks like a bare identifier is an id; everything else —
// "BSD-like", "see LICENSE" — is a name, which is honest rather than lossy.
func cycloneDXLicenses(license string) *cyclonedx.Licenses {
	license = strings.TrimSpace(license)
	if license == "" {
		return nil
	}
	if isSPDXExpression(license) {
		return &cyclonedx.Licenses{{Expression: license}}
	}
	if isSPDXIdentifierShaped(license) {
		return &cyclonedx.Licenses{{License: &cyclonedx.License{ID: license}}}
	}
	return &cyclonedx.Licenses{{License: &cyclonedx.License{Name: license}}}
}

// isSPDXExpression reports whether a license string joins operands with SPDX
// operators, which is what makes it an expression rather than an identifier.
//
// The operators are matched case-SENSITIVELY, because that is what the grammar
// defines: SPDX spells them as upper-case keywords, so a license whose *name*
// contains the ordinary English word — "Sleepycat and others" — is not a
// conjunction. Upper-casing before the comparison read that as an expression
// and emitted it as one, which is not parseable SPDX and is exactly the
// malformed document the three mutually exclusive fields exist to prevent.
//
// Parentheses are deliberately not a signal on their own either. "BSD (see
// LICENSE)" is a free-text name, and grouping only ever exists to order
// operators, so a genuinely grouped expression contains one anyway and is
// caught above.
func isSPDXExpression(s string) bool {
	for _, t := range strings.Fields(s) {
		switch t {
		case "AND", "OR", "WITH":
			return true
		}
	}
	return false
}

// isSPDXIdentifierShaped reports whether a license string could be a bare SPDX
// identifier: one token of the characters identifiers actually use.
//
// It deliberately does not check the value against the SPDX list. This package
// renders whatever the extractors found and must not silently drop a license it
// does not recognize; an unlisted identifier still belongs in the document, and
// a consumer validating against the SPDX list will say so more usefully than a
// renderer that omitted it.
func isSPDXIdentifierShaped(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '+' || r == '_':
		default:
			return false
		}
	}
	return true
}
