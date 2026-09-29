// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell

import (
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/text/encoding/charmap"
)

// clixmlHeader is the line Windows PowerShell writes to stderr before it
// serializes error, warning, verbose, debug and progress records as CLIXML.
// powershell.exe does this when it runs an -EncodedCommand script with stderr
// redirected, which is how every script built with Encode runs.
const clixmlHeader = "#< CLIXML"

// clixmlEscape matches one encoded UTF-16 code unit. [MS-PSRP] "Encoding
// Strings" encodes control and surrogate characters as _xHHHH_, an underscore
// that would otherwise start such a sequence as _x005F_, and a character
// outside the BMP as two sequences, one per surrogate.
var clixmlEscape = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)

// streamPrefix is what the PowerShell console host prints in front of a
// record of each non-error stream. Error records carry their own text.
var streamPrefix = map[string]string{
	"warning": "WARNING: ",
	"verbose": "VERBOSE: ",
	"debug":   "DEBUG: ",
}

// IsCLIXML reports whether b is PowerShell's CLIXML stderr serialization.
func IsCLIXML(b []byte) bool {
	return bytes.HasPrefix(b, []byte(clixmlHeader))
}

// DecodeCLIXML turns PowerShell's CLIXML stderr serialization into the text
// PowerShell would have printed. Every string record (<S>) is kept in order,
// error records as they are and warning, verbose and debug records with the
// prefix the console host gives them. Progress records (<Obj S="progress">)
// are dropped. Text written to stderr outside the XML, such as the output of
// [Console]::Error or of a native command, is kept verbatim.
//
// Each record ends in a line break, and trailing whitespace is trimmed from
// the result: PowerShell's error view ends in a blank line.
//
// powershell.exe writes stderr in the console's OEM code page, not UTF-8, and
// an XML parser rejects bytes that are not UTF-8. Input that is not valid
// UTF-8 is therefore read as code page 850 first, so an accented character in
// an error message (every localized message on a German or French host) does
// not leave the whole serialization undecoded. 850 and 437, the Western
// European and US defaults, agree on every accented letter.
//
// Input that does not start with the CLIXML header, or that fails to parse,
// is returned unchanged.
func DecodeCLIXML(b []byte) []byte {
	if !IsCLIXML(b) {
		return b
	}

	src := b
	if !utf8.Valid(src) {
		if dec, err := charmap.CodePage850.NewDecoder().Bytes(src); err == nil {
			src = dec
		}
	}

	var out strings.Builder
	rest := string(src)
	for rest != "" {
		start := strings.Index(rest, "<Objs")
		if start < 0 {
			out.WriteString(stripHeaders(rest))
			break
		}
		out.WriteString(stripHeaders(rest[:start]))

		end := strings.Index(rest[start:], "</Objs>")
		if end < 0 {
			return b
		}
		end += start + len("</Objs>")

		text, err := decodeObjs(rest[start:end])
		if err != nil {
			return b
		}
		out.WriteString(text)
		rest = rest[end:]
	}

	return []byte(strings.TrimRight(out.String(), " \t\r\n"))
}

// DecodeStderr replaces a command's stderr with its decoded text when it holds
// CLIXML. Any other stderr is left untouched, byte for byte.
func DecodeStderr(cmd *shared.Command) {
	if cmd == nil {
		return
	}
	buf, ok := cmd.Stderr.(*bytes.Buffer)
	if !ok || !IsCLIXML(buf.Bytes()) {
		return
	}
	decoded := DecodeCLIXML(buf.Bytes())
	buf.Reset()
	buf.Write(decoded)
}

// stripHeaders removes CLIXML header lines from text that sits between
// serialized blocks. A nested PowerShell that inherits the same stderr
// writes a header of its own.
func stripHeaders(s string) string {
	if !strings.Contains(s, clixmlHeader) {
		return s
	}
	s = strings.ReplaceAll(s, clixmlHeader+"\r\n", "")
	s = strings.ReplaceAll(s, clixmlHeader+"\n", "")
	return s
}

// decodeObjs reads one <Objs> element and returns the text of its top-level
// string records.
func decodeObjs(doc string) (string, error) {
	dec := xml.NewDecoder(strings.NewReader(doc))
	var out strings.Builder
	depth := 0
	inString := false
	prefix := ""
	var text strings.Builder

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out.String(), nil
		}
		if err != nil {
			return "", err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			// depth 1 is <Objs>, depth 2 its records
			if depth == 2 && t.Name.Local == "S" {
				inString = true
				prefix = ""
				for _, a := range t.Attr {
					if a.Name.Local == "S" {
						prefix = streamPrefix[strings.ToLower(a.Value)]
					}
				}
				text.Reset()
			}
		case xml.EndElement:
			if depth == 2 && inString {
				// Each record comes from one Write*Line host call. Error
				// records carry their own line break, the other streams do
				// not, so without one they would run into the next record.
				line := prefix + unescapeCLIXML(text.String())
				if !strings.HasSuffix(line, "\n") {
					line += "\r\n"
				}
				out.WriteString(line)
				inString = false
			}
			depth--
		case xml.CharData:
			if inString {
				text.Write(t)
			}
		}
	}
}

// unescapeCLIXML decodes the _xHHHH_ sequences of a serialized string.
// Consecutive sequences are joined as UTF-16 so a surrogate pair becomes one
// character.
func unescapeCLIXML(s string) string {
	matches := clixmlEscape.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s
	}

	var out strings.Builder
	var units []uint16
	flush := func() {
		if len(units) > 0 {
			out.WriteString(string(utf16.Decode(units)))
			units = units[:0]
		}
	}

	last := 0
	for _, m := range matches {
		if m[0] > last {
			flush()
			out.WriteString(s[last:m[0]])
		}
		v, _ := strconv.ParseUint(s[m[2]:m[3]], 16, 16)
		units = append(units, uint16(v))
		last = m[1]
	}
	flush()
	out.WriteString(s[last:])
	return out.String()
}
