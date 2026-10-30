// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_1"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spdx/tools-golang/tagvalue"
)

func NewSPDX(format string) *Spdx {
	return &Spdx{
		Version: "2.3",
		Format:  format,
	}
}

var _ Decoder = &Spdx{}

type Spdx struct {
	opts    renderOpts
	Version string
	Format  string
}

func (s *Spdx) ApplyOptions(opts ...renderOption) {
	for _, opt := range opts {
		opt(&s.opts)
	}
}

func (s *Spdx) convertToSpdx(bom *Sbom) *spdx.Document {
	extractedLicenses := extractedLicenseSet{}
	name := spdxDocumentName(bom)
	doc := &spdx.Document{
		SPDXVersion:                spdx.Version,
		SPDXIdentifier:             "DOCUMENT",
		ExternalDocumentReferences: nil,
		DocumentComment:            "",

		// The three fields below are mandatory in SPDX 2.x and were left at
		// their zero values, which made every document this renderer produced
		// invalid: a consumer validating against the schema rejects it, and one
		// that does not gets a nameless document it cannot refer to.
		DataLicense:       spdxDataLicense,
		DocumentName:      name,
		DocumentNamespace: spdxDocumentNamespace(name),

		CreationInfo: &spdx.CreationInfo{
			Creators: spdxCreators(bom.GetGenerator()),
			Created:  time.Now().UTC().Format(time.RFC3339),
		},
	}

	// bom_ref → SPDX element id, so the dependency graph (which references
	// components by bom_ref) can be translated to SPDX DEPENDS_ON relationships.
	refToID := map[string]spdx.ElementID{}
	// emitted dedups by bom-ref: a package present at multiple install locations
	// shares a purl, so emit it once (matching the CycloneDX renderer). Without
	// this, duplicate SPDX packages are written and refToID is silently
	// overwritten (with a possibly different id, since Hash() may differ).
	emitted := map[string]bool{}

	for i := range bom.Packages {
		pkg := bom.Packages[i]

		ref := BomRefFor(pkg)
		if emitted[ref] {
			continue
		}
		emitted[ref] = true

		refs := []*spdx.PackageExternalReference{}

		if len(pkg.Cpes) > 0 {
			for _, cpe := range pkg.Cpes {
				refs = append(refs, &spdx.PackageExternalReference{
					RefType:  spdx.SecurityCPE23Type,
					Category: spdx.CategorySecurity,
					Locator:  cpe,
				})
			}
		}

		if pkg.Purl != "" {
			refs = append(refs, &spdx.PackageExternalReference{
				RefType:  spdx.PackageManagerPURL,
				Category: spdx.CategoryPackageManager,
				Locator:  pkg.Purl,
			})
		}

		id := NewSPDXPackageID(pkg)
		refToID[ref] = id

		// Integrity digests → SPDX checksums. Alg is CycloneDX spelling
		// ("SHA-512"); SPDX uses the dash-free form ("SHA512").
		var checksums []common.Checksum
		for _, h := range pkg.Hashes {
			checksums = append(checksums, common.Checksum{
				Algorithm: common.ChecksumAlgorithm(strings.ReplaceAll(h.Alg, "-", "")),
				Value:     h.Value,
			})
		}

		// The SPDX specification requires NOASSERTION rather than an empty value
		// for the license and copyright fields. An empty string is not valid
		// SPDX, and a strict consumer may reject the whole document over it.
		//
		// SPDX draws exactly the distinction the license model does: *declared*
		// is what the package says about itself, *concluded* is what this
		// document asserts after looking. They differ precisely when it matters
		// — a package declaring MIT while shipping AGPL-3.0-only — so where a
		// concluded license was determined it is emitted as itself rather than
		// echoing the declared one.
		declared := spdxNoAssertion(spdxLicense(declaredLicenses(pkg), pkg.License, extractedLicenses))
		concluded := spdxNoAssertion(spdxLicense(concludedLicenses(pkg), "", extractedLicenses))
		if concluded == spdxNoAssertionValue {
			// Nothing was concluded, so this repeats the declared value.
			//
			// The comment that stood here called that "the honest reading",
			// which had the argument backwards: echoing IS asserting more than
			// was determined, and NOASSERTION is the thing that avoids it. The
			// echo is a deliberate overstatement, not a modest one.
			//
			// It stays because the strictly accurate value is the more
			// misleading one in practice. A consumer reading licenseConcluded
			// as the package's license -- and many read it first -- sees
			// NOASSERTION and takes a package that plainly declares MIT for one
			// whose license is unknown. Repeating the declaration is wrong in a
			// direction a reader can recover from; NOASSERTION is wrong in a
			// direction they cannot.
			//
			// What makes the overstatement safe to keep is that it no longer
			// survives a round trip: readSpdxPackageLicensing recognises a
			// concluded value equal to the declared one as this echo and does
			// not import it as a determination.
			concluded = declared
		}
		doc.Packages = append(doc.Packages, &spdx.Package{
			PackageSPDXIdentifier:     id,
			PackageName:               pkg.Name,
			PackageVersion:            pkg.Version,
			PackageLicenseDeclared:    declared,
			PackageLicenseConcluded:   concluded,
			PackageCopyrightText:      spdxNoAssertion(strings.Join(pkg.Copyright, "\n")),
			PackageLicenseComments:    spdxLicenseComments(concludedLicenses(pkg)),
			PackageSupplier:           spdxSupplier(pkg.Supplier),
			PackageDescription:        pkg.Description,
			PackageExternalReferences: refs,
			PackageFileName:           spdxPackageFileName(pkg),
			PackageChecksums:          checksums,
			PackageComment:            spdxPackageComment(pkg),
		})
		// A LicenseRef-* identifier is not on the SPDX license list, so the
		// specification requires the document to define it before it may be
		// referenced.
		extractedLicenses.add(declared)
		extractedLicenses.add(concluded)
	}

	doc.OtherLicenses = extractedLicenses.render()

	// Emit the package→package dependency graph as SPDX DEPENDS_ON relationships,
	// skipping any edge whose endpoints are not in this document.
	for _, dep := range bom.Dependencies {
		fromID, ok := refToID[dep.Ref]
		if !ok {
			continue
		}
		for _, to := range dep.DependencyRefs {
			toID, ok := refToID[to]
			if !ok {
				continue
			}
			doc.Relationships = append(doc.Relationships, &spdx.Relationship{
				RefA:         common.MakeDocElementID("", string(fromID)),
				RefB:         common.MakeDocElementID("", string(toID)),
				Relationship: spdx.RelationshipDependsOn,
			})
		}
	}

	return doc
}

var expr = regexp.MustCompile("[^a-zA-Z0-9.-]")

// NewSPDXPackageID creates a new SPDX ID for a package
// see https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/
func NewSPDXPackageID(pkg *Package) spdx.ElementID {
	hash, _ := pkg.Hash()

	id := fmt.Sprintf("Package-%s-%s-%s", pkg.Type, pkg.Name, hash)
	// Scrub anything outside the SPDX ID charset. This must assign the result
	// back: an unsanitized name (e.g. one containing a newline) would otherwise
	// inject tags into SPDX tag-value output.
	id = expr.ReplaceAllString(id, "-")
	return spdx.ElementID(id)
}

func (s *Spdx) Convert(bom *Sbom) (any, error) {
	spdxLatestBom := s.convertToSpdx(bom)

	var spdxBom any
	var err error
	switch s.Version {
	case "2.1":
		doc := v2_1.Document{}
		err = convert.Document(spdxLatestBom, &doc)
		spdxBom = doc
	case "2.2":
		doc := v2_2.Document{}
		err = convert.Document(spdxLatestBom, &doc)
		spdxBom = doc
	case "2.3":
		fallthrough
	case "":
		doc := v2_3.Document{}
		err = convert.Document(spdxLatestBom, &doc)
		spdxBom = doc
	default:
		return nil, fmt.Errorf("unsupported SPDX version %q", s.Version)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to convertToCycloneDx SBOM to SPDX document: %w", err)
	}
	return spdxBom, nil
}

func (s *Spdx) Render(w io.Writer, bom *Sbom) error {
	spdxBom, err := s.Convert(bom)
	if err != nil {
		return err
	}

	switch s.Format {
	case FormatSpdxTagValue:
		err = tagvalue.Write(spdxBom, w)
		if err != nil {
			return fmt.Errorf("unable to write SPDX tag-value document: %w", err)
		}
		return nil
	case FormatSpdxJSON:
		fallthrough
	default:
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(spdxBom)
	}
}

func (s *Spdx) Parse(r io.ReadSeeker) (*Sbom, error) {
	// try to parse all supported SPDX format
	switch s.Format {
	case FormatSpdxTagValue:
		doc, err := tagvalue.Read(r)
		if err == nil && doc.SPDXVersion != "" {
			return s.convertToSbom(doc), nil
		}
	case FormatSpdxJSON:
		var doc spdx.Document
		err := json.NewDecoder(r).Decode(&doc)
		if err == nil && doc.SPDXVersion != "" {
			return s.convertToSbom(&doc), nil
		}
	}

	return nil, errors.New("unable to parse SPDX document")
}

func (s *Spdx) convertToSbom(doc *spdx.Document) *Sbom {
	bom := &Sbom{
		Generator: spdxGenerator(doc.CreationInfo),
		Asset: &Asset{
			Name: doc.DocumentName,
			Platform: &Platform{
				Name:    "spdx",
				Version: doc.SPDXVersion,
				Title:   "SPDX",
			},
		},
		Packages: []*Package{},
	}

	name := ""
	var pf *Platform

	for i := range doc.Packages {
		pkg := doc.Packages[i]

		bomPkg := &Package{
			Name:        pkg.PackageName,
			Version:     pkg.PackageVersion,
			Description: pkg.PackageDescription,
			Location:    pkg.PackageFileName,
			Type:        "", // extract package type from purl, see below
			Purl:        "", // extract package type from purl, see below
			Cpes:        []string{},
		}

		readSpdxPackageLicensing(bomPkg, pkg)

		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == spdx.PackageManagerPURL {
				bomPkg.Purl = ref.Locator
				pkgUrl, err := packageurl.FromString(ref.Locator)
				if err == nil {
					bomPkg.Type = pkgUrl.Type
					var distro string
					if pf, distro = purlDistroPlatform(pkgUrl, pf); distro != "" {
						name = distro
					}
				}
			}
			if ref.RefType == spdx.SecurityCPE23Type {
				bomPkg.Cpes = append(bomPkg.Cpes, ref.Locator)
			}
		}

		if pkg.PackageFileName != "" && s.opts.IncludeEvidence {
			bomPkg.EvidenceList = append(bomPkg.EvidenceList, &Evidence{
				Type:  EvidenceType_EVIDENCE_TYPE_FILE,
				Value: pkg.PackageFileName,
			})
		}

		bom.Packages = append(bom.Packages, bomPkg)
	}

	if name != "" {
		bom.Asset.Name = name
	}
	if pf != nil {
		bom.Asset.Platform = pf
	}

	return bom
}

// purlDistroPlatform reads the platform a package was installed on out of its
// package URL's `distro` and `arch` qualifiers, updating pf, which may be nil.
// It returns the platform and the raw distro qualifier, or "" when the package
// URL names no distro.
func purlDistroPlatform(purl packageurl.PackageURL, pf *Platform) (*Platform, string) {
	m := purl.Qualifiers.Map()
	distroVal, ok := m["distro"]
	if ok {
		if pf == nil {
			pf = &Platform{}
		}
		pf.Title = distroVal
		// The qualifier is the platform name and version joined with a dash
		// (purl.NewPlatformPurl), and it is the *name* that commonly carries
		// dashes of its own: opensuse-leap, opensuse-tumbleweed,
		// opensuse-microos. Splitting on the first dash reports
		// "opensuse-leap-15.6" as name "opensuse" version "leap", so split on
		// the last one. A qualifier with no dash carries no version, e.g.
		// "arch" rather than "arch-rolling".
		pf.Name = distroVal
		if before, after, ok := strings.CutLast(distroVal, "-"); ok && before != "" {
			pf.Name = before
			pf.Version = after
		}
		pf.Family = familyMap[pf.Name]
	}
	if arch, ok := m["arch"]; ok && pf != nil {
		pf.Arch = arch
	}
	return pf, distroVal
}

// spdxNoAssertion returns the SPDX-mandated NOASSERTION for an empty value.
func spdxNoAssertion(v string) string {
	if strings.TrimSpace(v) == "" {
		return spdxNoAssertionValue
	}
	return v
}

const spdxNoAssertionValue = "NOASSERTION"

// spdxDataLicense is fixed by the specification: the license covering a
// document's own metadata is always CC0-1.0, whatever the document describes.
const spdxDataLicense = "CC0-1.0"

// spdxNamespacePrefix roots the document namespace. The spec wants a URI under
// a domain the producer controls, which is what makes two documents about the
// same asset distinguishable rather than colliding.
const spdxNamespacePrefix = "https://mondoo.com/spdx/"

// spdxDocumentName is what the document calls itself: the asset it describes.
//
// The fallback is shared with the CycloneDX renderer, because it answers the
// same question from the same empty field -- what to call a subject that does
// not name itself -- and the two documents describing one BOM should not
// disagree about it. NOASSERTION is not used here: it is an assertion about a
// license or a supplier, not a stand-in for a title.
func spdxDocumentName(bom *Sbom) string {
	if name := strings.TrimSpace(bom.GetAsset().GetName()); name != "" {
		return name
	}
	return unnamedSubject
}

// spdxDocumentNamespace builds the unique URI every SPDX document must carry.
//
// The spec's requirement is uniqueness per document rather than per asset:
// scanning the same host twice produces two documents that must not claim the
// same identity, or a consumer holding both cannot tell which package list it
// is looking at. A UUID is the spec's own suggestion for the uniquifying part.
//
// The namespace says who produced this document, so it stays under this domain
// even when the content was imported from somebody else's SBOM -- that document
// had its own namespace, and this is a different document.
func spdxDocumentNamespace(name string) string {
	return spdxNamespacePrefix + url.PathEscape(name) + "-" + spdxNamespaceSuffix()
}

// spdxNamespaceSuffix is what makes one document's namespace differ from the
// next: a UUID, or the clock when one cannot be had.
//
// uuid.New panics when the entropy source fails, which is rare and not
// impossible -- a constrained container without /dev/urandom is the usual way
// to see it. Taking a whole scan down over the uniquifying half of a metadata
// URI is the exact failure this file exists to remove, so the error is handled
// rather than raised. Nanosecond time is a weaker uniquifier than a UUID and a
// far better one than a panic; it only ever runs on a machine whose randomness
// has already failed.
func spdxNamespaceSuffix() string {
	if id, err := uuid.NewRandom(); err == nil {
		return id.String()
	}
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

// spdxCreators renders who produced the document, dropping what is not known.
//
// Every entry has to carry a value. The library marshals a Creator with an
// empty one to zero bytes, which is not JSON, so a single blank creator fails
// the whole document with `unexpected end of JSON input` -- a generator with no
// vendor took every SBOM down that way, imported ones included, since an
// imported document rarely names one.
//
// Omitting is the honest form: a creator naming nobody asserts an origin the
// producer does not have. But the field's cardinality is 1..*, so a document
// that can name nobody still has to say something, and the spec supplies the
// word for it: "Person name or organization name may be designated as
// 'anonymous' if appropriate." That is an Organization rather than a Tool --
// the spec offers the escape hatch for the two human types only, and a Tool
// entry is required to be "toolidentifier-version", which "anonymous" is not.
// NOASSERTION is deliberately not used here: the spec never gives it a meaning
// for this field, and it belongs to license and supplier claims.
func spdxCreators(g *Generator) []spdx.Creator {
	creators := make([]spdx.Creator, 0, 2)
	if vendor := strings.TrimSpace(g.GetVendor()); vendor != "" {
		creators = append(creators, spdx.Creator{CreatorType: "Organization", Creator: vendor})
	}
	if tool := spdxToolIdentifier(g); tool != "" {
		creators = append(creators, spdx.Creator{CreatorType: "Tool", Creator: tool})
	}
	if len(creators) == 0 {
		creators = append(creators, spdx.Creator{CreatorType: "Organization", Creator: spdxAnonymousCreator})
	}
	return creators
}

// spdxAnonymousCreator is the spec's own word for a creator that cannot be
// named, and the only value that satisfies a mandatory field with nothing to
// put in it.
const spdxAnonymousCreator = "anonymous"

// spdxToolIdentifier renders the tool creator the spec asks for,
// "toolidentifier-version", or "" when the generator does not name a tool.
//
// The version is appended only when there is one. A bare trailing "-" reads as
// a tool whose version is the empty string rather than one that did not say.
func spdxToolIdentifier(g *Generator) string {
	name := strings.TrimSpace(g.GetName())
	if name == "" {
		return ""
	}
	if version := strings.TrimSpace(g.GetVersion()); version != "" {
		return name + "-" + version
	}
	return name
}

// spdxGenerator reads who made a document back out of its creators.
//
// Creators are a list whose entries are told apart by their type, not their
// position, so this reads the type rather than taking the first entry: an
// Organization is the vendor and a Tool is the tool, and a document that lists
// them in the other order (or lists only one) is just as valid. Taking
// creators[0] read this renderer's own Organization as the tool's *name*, which
// dropped the vendor and version and made mql unable to re-render a document it
// had written itself.
//
// A document that lists no creators at all is valid enough to parse, so this
// returns an empty generator rather than indexing into nothing.
func spdxGenerator(info *spdx.CreationInfo) *Generator {
	g := &Generator{}
	if info == nil {
		return g
	}
	for _, c := range info.Creators {
		// "anonymous" is the spec's placeholder for a creator that could not
		// be named, so it is dropped rather than carried: a Generator whose
		// vendor is the literal string "anonymous" would travel into every
		// other format as though somebody were called that. Leaving it empty
		// keeps "not known" and "known to be anonymous" the same thing, which
		// is what the document said.
		value := strings.TrimSpace(c.Creator)
		if value == "" || value == spdxNoAssertionValue || value == spdxAnonymousCreator {
			continue
		}
		switch c.CreatorType {
		case "Tool":
			if g.Name == "" {
				g.Name, g.Version = spdxSplitTool(value)
			}
		case "Organization", "Person":
			if g.Vendor == "" {
				g.Vendor = value
			}
		}
	}
	return g
}

// spdxLooksLikeVersion reports whether a trailing segment is a version rather
// than the last word of a hyphenated name: digits, optionally behind a "v".
func spdxLooksLikeVersion(s string) bool {
	s = strings.TrimPrefix(s, "v")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// spdxSplitTool splits "toolidentifier-version" back into its two halves.
//
// The spec's own format is ambiguous, because a tool identifier may contain a
// hyphen: "cyclonedx-gomod-v1.4.0" and "my-tool" are the same shape. So the
// split happens only when what follows the last hyphen looks like a version,
// which leaves a hyphenated name that carries no version intact rather than
// slicing its last word off and calling it a release.
//
// The ambiguity cannot be resolved from the string alone -- a tool genuinely
// called "log4j-2" is indistinguishable from version 2 of "log4j" -- so what
// this guarantees is not that the halves are right but that the *document* does
// not drift: rejoining whatever came out reproduces the identifier exactly, for
// every shape above. That is the property the round trip needs, and the one the
// old reader broke.
//
// So the halves are safe to re-render and unsafe to believe. Nothing in this
// repository reads a parsed Generator's name or version for anything except
// writing it back out, which is why the guess costs nothing here -- but this is
// a library, and a consumer that displays one, compares it, or branches on it
// is reading a guess for the shapes above. Report the identifier whole if that
// matters more than the split.
func spdxSplitTool(tool string) (string, string) {
	before, version, ok := strings.CutLast(tool, "-")
	if !ok || before == "" {
		return tool, ""
	}
	if spdxLooksLikeVersion(version) {
		return before, version
	}
	return tool, ""
}

// licenseRefPrefix marks a custom identifier that is not on the SPDX license
// list.
const licenseRefPrefix = "LicenseRef-"

// extractedLicenseSet collects the LicenseRef-* identifiers a document
// references, so each can be declared in hasExtractedLicensingInfos as the
// specification requires.
//
// The value is the human-readable name the identifier stands for, which matters
// for a reference synthesized from a free-form license string: "see LICENSE" is
// not a legal identifier, so it becomes LicenseRef-see-LICENSE, and the original
// text is the only place the reader learns what that means. Empty means the
// identifier is all that is known and names itself.
type extractedLicenseSet map[string]string

// add registers every LicenseRef-* identifier appearing in a rendered license
// expression. It never overwrites a name already recorded for an identifier, so
// a reference synthesized by addNamed keeps its original text when the rendered
// expression it landed in is scanned again.
func (s extractedLicenseSet) add(license string) {
	for _, tok := range strings.FieldsFunc(license, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '(' || r == ')'
	}) {
		if !strings.HasPrefix(tok, licenseRefPrefix) {
			continue
		}
		if _, ok := s[tok]; !ok {
			s[tok] = ""
		}
	}
}

// addNamed registers an identifier together with the text it was synthesized
// from.
func (s extractedLicenseSet) addNamed(id, name string) {
	if existing, ok := s[id]; ok && existing != "" {
		return
	}
	s[id] = name
}

// render returns the collected identifiers as SPDX other-license entries, sorted
// so a document is byte-stable across runs.
func (s extractedLicenseSet) render() []*spdx.OtherLicense {
	if len(s) == 0 {
		return nil
	}
	ids := make([]string, 0, len(s))
	for id := range s {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]*spdx.OtherLicense, 0, len(ids))
	for _, id := range ids {
		name := s[id]
		if name == "" {
			name = id
		}
		out = append(out, &spdx.OtherLicense{
			LicenseIdentifier: id,
			// The text is not available here — the extractors carry an
			// identifier, not a license body — so the field states that rather
			// than inventing one.
			ExtractedText: spdxNoAssertionValue,
			LicenseName:   name,
		})
	}
	return out
}

// spdxLicense renders license entries as the single value an SPDX field holds,
// falling back to a legacy scalar when the structured list is empty.
//
// SPDX carries one expression per field, so several entries are joined with
// AND: a package under two licenses is under both, and OR would grant a choice
// the producer never reported.
//
// The field must hold a license *expression*, which constrains what each operand
// may be, so the three License shapes do not all reach it the same way. Refs
// synthesized for a free-form name are registered in extracted so the document
// declares them before referencing them.
//
// The fallback scalar is passed through unchanged. It has rendered verbatim for
// as long as the field has existed and producers set it to whatever their
// package manager reported; re-encoding it here would rewrite what every
// existing document says about a large share of OS packages, which is a
// migration to make deliberately rather than as a side effect of adding a list.
func spdxLicense(licenses []*License, fallback string, extracted extractedLicenseSet) string {
	parts := make([]string, 0, len(licenses))
	for _, l := range licenses {
		if v := strings.TrimSpace(l.GetExpression()); v != "" {
			parts = append(parts, v)
			continue
		}
		if v := strings.TrimSpace(l.GetSpdxId()); v != "" {
			parts = append(parts, v)
			continue
		}
		// A free-form name is not a legal operand: "see LICENSE" has a space in
		// it, so emitting it raw makes the field unparseable and joining it with
		// AND produces "MIT AND see LICENSE", which reads as an expression and
		// is not one. SPDX's encoding for a license that is not on its list is a
		// LicenseRef-* identifier defined in hasExtractedLicensingInfos, so that
		// is what the text becomes — the name survives, in the field that can
		// hold it.
		if v := strings.TrimSpace(l.GetName()); v != "" {
			ref := spdxLicenseRef(v)
			if ref == "" {
				// Nothing in the name survives sanitization, so there is no
				// identifier to reference and no way to say this in SPDX.
				continue
			}
			extracted.addNamed(ref, v)
			parts = append(parts, ref)
		}
	}
	if len(parts) == 0 {
		return strings.TrimSpace(fallback)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	for i, p := range parts {
		if isSPDXExpression(p) {
			// Parenthesize so joining cannot reassociate an operand: "A OR B"
			// AND "C" is not "A OR (B AND C)". Decided on the rendered operands
			// rather than the input count, so an entry that carried no value
			// cannot add parentheses around the one that did.
			parts[i] = "(" + p + ")"
		}
	}
	return strings.Join(parts, " AND ")
}

// spdxLicenseRef builds the LicenseRef-* identifier that stands for a free-form
// license name.
//
// SPDX restricts the part after the prefix to letters, digits, "." and "-", so
// every other run of characters collapses to a single dash. Returns "" when the
// name has nothing an identifier can be built from, which is the caller's signal
// that there is no way to reference it.
func spdxLicenseRef(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		default:
			dash = true
		}
	}
	id := strings.Trim(b.String(), "-.")
	if id == "" {
		return ""
	}
	return licenseRefPrefix + id
}

// spdxLicenseComments records what a conclusion was based on: the file it was
// read from and how sure whoever read it was.
//
// SPDX has no field for either, and PackageLicenseComments is the one place the
// spec puts prose about how the license fields were arrived at. It is free text,
// so this is for a human reading the document rather than a consumer parsing it
// -- but the alternative is dropping the difference between a certainty and an
// inference entirely, which is what the renderer did before.
//
// Empty when nothing was concluded, or when a conclusion carries neither
// detail: a comment saying nothing is worse than none, since a reader takes its
// presence as a sign there was something to say.
func spdxLicenseComments(licenses []*License) string {
	notes := make([]string, 0, len(licenses))
	for _, l := range licenses {
		value := strings.TrimSpace(spdxLicense([]*License{l}, "", extractedLicenseSet{}))
		if value == "" {
			continue
		}

		var detail []string
		if loc := strings.TrimSpace(l.GetLocation()); loc != "" {
			detail = append(detail, "read from "+loc)
		}
		// A conclusion at full confidence is not worth a note: it says the same
		// thing as a conclusion with no score attached.
		if c := l.GetConfidence(); c > 0 && c < 1 {
			detail = append(detail, "confidence "+strconv.FormatFloat(c, 'g', -1, 64))
		}
		if len(detail) == 0 {
			continue
		}
		notes = append(notes, value+": "+strings.Join(detail, ", "))
	}
	if len(notes) == 0 {
		return ""
	}
	return "Concluded " + strings.Join(notes, "; ") + "."
}

// spdxSupplier renders a supplier as the spec's Originator/Supplier shape, or
// NOASSERTION when none is known.
//
// SPDX requires the value to be typed — "Organization: name" or "Person: name".
// An unqualified name is not valid, and this package has no way to tell which a
// supplier is, so it reports the type SPDX itself uses for a supplier of
// software: an organization.
func spdxSupplier(supplier string) *common.Supplier {
	supplier = strings.TrimSpace(supplier)
	if supplier == "" {
		return &common.Supplier{Supplier: spdxNoAssertionValue}
	}
	return &common.Supplier{Supplier: supplier, SupplierType: "Organization"}
}

// readSpdxPackageLicensing carries what an imported SPDX document states about a
// package's licensing into the model.
//
// This decoder read a package's name, version, identifiers and file evidence and
// dropped everything else the document said, which is information that exists
// nowhere else in the file: a document stating a declared license, a concluded
// one, a copyright and a supplier came out carrying none of them. #10597 fixed
// the same gap in the Protobom decoder, but DefaultMultiDecoder routes SPDX
// here, so no consumer of that entry point saw the difference.
//
// SPDX separates the two acquisitions by field, which is exactly the distinction
// the model draws: PackageLicenseDeclared is what the package says about itself,
// PackageLicenseConcluded is what the document's producer determined. Both are
// single expressions rather than lists, so there is at most one entry of each.
func readSpdxPackageLicensing(bomPkg *Package, pkg *v2_3.Package) {
	declared := importedLicenseValue(pkg.PackageLicenseDeclared)
	concluded := importedLicenseValue(pkg.PackageLicenseConcluded)

	// A concluded value equal to the declared one is an echo, not a conclusion.
	//
	// This renderer writes one: where nothing was concluded it repeats the
	// declared value rather than NOASSERTION, on the grounds that it is what the
	// document has to go on, and other SPDX producers do the same. Reading it
	// back as a determination turns a package that declared MIT and concluded
	// nothing into one asserting somebody concluded MIT -- a claim that the
	// license was verified, invented by a round trip.
	//
	// The two are indistinguishable in the document, so this is a choice about
	// which way to be wrong, and it is not free either way. A third-party tool
	// that genuinely concluded MIT for a package declaring MIT wrote the same
	// two fields as our echo, and its real conclusion is dropped here with the
	// echoes. What is lost is the acquisition signal, not the license: the
	// package is still reported as licensed MIT, on its own declaration.
	//
	// It goes this way on frequency and on direction. This renderer echoes for
	// every unconcluded package, so keeping the entry over-asserts across most
	// of every document it produces, against a minority of genuine agreements;
	// and inventing a verification nobody performed is worse than omitting one
	// that happened. A conclusion that DISAGREES is the case the split exists
	// for and is never touched.
	if concluded == declared {
		concluded = ""
	}

	if entry := DeclaredLicense(declared); entry != nil {
		bomPkg.Licenses = append(bomPkg.Licenses, entry)
	}

	// No location and no confidence, for the reasons the Protobom decoder
	// records: SPDX carries neither for a concluded license, and the model
	// spells "nobody measured this" as 0. Reporting 1.0 would rank an imported
	// conclusion that was never scored alongside one that scored perfectly.
	if entry := ConcludedLicense(concluded, "", 0); entry != nil {
		bomPkg.Licenses = append(bomPkg.Licenses, entry)
	}

	// The legacy scalar keeps being written, as every other producer in this
	// package does, so a consumer that has not migrated to the list still sees a
	// license. It takes the DECLARED entry, falling back to the concluded value
	// when the document declared none: a scalar left empty while the document
	// did state a license is the failure the fallback exists to prevent.
	for _, l := range bomPkg.Licenses {
		if l.GetAcquisition() == LicenseAcquisition_LICENSE_ACQUISITION_DECLARED {
			bomPkg.License = licenseValueOf(l)
			break
		}
	}
	if bomPkg.License == "" {
		bomPkg.License = concluded
	}

	if c := importedLicenseValue(pkg.PackageCopyrightText); c != "" {
		bomPkg.Copyright = []string{c}
	}

	if pkg.PackageSupplier != nil {
		if name := importedLicenseValue(pkg.PackageSupplier.Supplier); name != "" {
			bomPkg.Supplier = name
		}
	}
}

// spdxPackageFileName is the package's packageFileName: the deprecated
// location, or for a binary the path of the executable, which is the file
// the package is. Other packages' file evidence points at the package
// database rather than at the package, so it is not a file name.
func spdxPackageFileName(pkg *Package) string {
	if pkg.Location != "" || pkg.Type != "binary" {
		return pkg.Location
	}
	for _, e := range pkg.EvidenceList {
		if e.GetType() == EvidenceType_EVIDENCE_TYPE_FILE && e.GetValue() != "" {
			return e.GetValue()
		}
	}
	return ""
}

// spdxPackageComment states what SPDX has no field for: how a binary's
// identity was concluded and its code signature, one statement per line, in
// the property names the CycloneDX rendering uses. Empty when there is none.
func spdxPackageComment(pkg *Package) string {
	var lines []string
	for _, e := range pkg.GetIdentityEvidence() {
		if e.GetField() == "" || e.GetTechnique() == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("mondoo:identity:%s: %s by %s from %s (confidence %g)",
			e.GetField(), e.GetConcludedValue(), e.GetTechnique(), e.GetValue(), e.GetConfidence()))
	}
	if sig := pkg.GetSignature(); sig != nil {
		for _, p := range [][2]string{
			{propSignatureStatus, sig.GetStatus()},
			{propSignatureSignerOrg, sig.GetSignerOrganization()},
			{propSignatureSignerName, sig.GetSignerCommonName()},
		} {
			if p[1] != "" {
				lines = append(lines, p[0]+": "+p[1])
			}
		}
	}
	return strings.Join(lines, "\n")
}
