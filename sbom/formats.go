// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"errors"
	"io"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

const (
	FormatJson          string = "json"
	FormatCycloneDxJSON string = "cyclonedx-json"
	FormatCycloneDxXML  string = "cyclonedx-xml"
	FormatSpdxJSON      string = "spdx-json"
	FormatSpdxTagValue  string = "spdx-tag-value"
	FormatList          string = "table"
)

// unnamedSubject is what a BOM's subject is called when the asset does not name
// itself. Both document formats have to put a name somewhere -- SPDX's document
// name is mandatory, and a CycloneDX component's name is required by the schema
// -- so the choice is between this and a nameless entry a consumer has to
// recognise as junk. Shared so that the SPDX and CycloneDX renderings of one
// BOM do not disagree about what its subject is called.
const unnamedSubject = "sbom"

var (
	errConversionNotSupported = errors.New("conversion is not supported")
	errParsingNotSupported    = errors.New("parsing is not supported")
)

type FormatSpecificationHandler interface {
	// Convert converts cnquery sbom to the desired format
	Convert(bom *Sbom) (any, error)
	// Render writes the converted sbom to the writer in the desired format
	Render(w io.Writer, bom *Sbom) error
	// ApplyOptions applies render options to the handler
	ApplyOptions(opts ...renderOption)
	Decoder
}

// format is one value --output accepts: what builds it, and whether it is
// advertised. The undocumented ones are accepted but not listed -- "list" is a
// common spelling of the table renderer, and the json aliases predate this and
// stay for callers already using them.
//
// AllFormats, IsSupportedFormat and New all read this, so a format cannot be
// constructible but rejected by the guard, or accepted and then silently fall
// through to a default. Those were two hand-kept lists and a switch before, and
// they disagreed: New's default returned the table renderer for anything it did
// not recognise, so a misspelled --output produced a table instead of an error.
type format struct {
	name       string
	documented bool
	new        func() FormatSpecificationHandler
}

var formats = []format{
	{FormatJson, true, func() FormatSpecificationHandler { return &CnqueryBOM{} }},
	{"cnquery-json", false, func() FormatSpecificationHandler { return &CnqueryBOM{} }},
	{"cnspec-json", false, func() FormatSpecificationHandler { return &CnqueryBOM{} }},
	{FormatCycloneDxJSON, true, func() FormatSpecificationHandler {
		return &CycloneDX{Format: cyclonedx.BOMFileFormatJSON}
	}},
	{FormatCycloneDxXML, true, func() FormatSpecificationHandler {
		return &CycloneDX{Format: cyclonedx.BOMFileFormatXML}
	}},
	{FormatSpdxJSON, true, func() FormatSpecificationHandler {
		return &Spdx{Version: "2.3", Format: FormatSpdxJSON}
	}},
	{FormatSpdxTagValue, true, func() FormatSpecificationHandler {
		return &Spdx{Version: "2.3", Format: FormatSpdxTagValue}
	}},
	{FormatList, true, func() FormatSpecificationHandler { return &TextList{} }},
	{"list", false, func() FormatSpecificationHandler { return &TextList{} }},
}

func lookup(name string) (format, bool) {
	for _, f := range formats {
		if f.name == name {
			return f, true
		}
	}
	return format{}, false
}

// AllFormats lists the formats worth telling a user about, for help text and
// for the error a rejected --output produces.
func AllFormats() string {
	names := make([]string, 0, len(formats))
	for _, f := range formats {
		if f.documented {
			names = append(names, f.name)
		}
	}
	return strings.Join(names, ", ")
}

// IsSupportedFormat reports whether New can build this format. A caller that
// validates up front gets to refuse a bad --output before doing the work of a
// scan, rather than after.
func IsSupportedFormat(format string) bool {
	_, ok := lookup(format)
	return ok
}

// New returns the handler for a format. It keeps the historical fallback to the
// table renderer for callers that did not check IsSupportedFormat first.
func New(name string) FormatSpecificationHandler {
	if f, ok := lookup(name); ok {
		return f.new()
	}
	return &TextList{}
}
