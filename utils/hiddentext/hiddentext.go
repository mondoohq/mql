// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package hiddentext finds text a person reading a file does not see and a
// program reading the same bytes does: characters that render as nothing or
// reorder what renders, and Markdown HTML comments.
//
// It exists for files an AI agent reads as instructions (skills, rules files,
// tool descriptions). An instruction written in invisible characters is a
// prompt injection no review catches. The package reports what is hidden and
// whether the hidden text reads like an instruction. It assigns no severity:
// the caller knows what the file is and what it grants.
//
// Visible text is never judged. Instructions are what such a file is for.
package hiddentext

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Class is the kind of hidden content.
type Class string

const (
	// TagCharacters (H1): the Unicode Tags block, U+E0001 and U+E0020 to
	// U+E007F. Each mirrors one ASCII character and renders as nothing.
	TagCharacters Class = "tag-characters"
	// ZeroWidth (H2): zero-width and invisible format characters, and the
	// Hangul fillers that render blank.
	ZeroWidth Class = "zero-width"
	// BidiControl (H3): an override, or an embedding or isolate left open at
	// the end of its line, which shows text in another order than it is stored.
	BidiControl Class = "bidi-control"
	// VariationSelectors (H4): variation selectors used as a data carrier:
	// two or more in a row, or one after an ASCII character.
	VariationSelectors Class = "variation-selectors"
	// PrivateUse (H5): private-use code points and noncharacters, which
	// render inconsistently or not at all.
	PrivateUse Class = "private-use"
	// HTMLComment: a Markdown HTML comment whose text is instruction-like.
	// Most previews do not render a comment; an agent reads it as written.
	HTMLComment Class = "html-comment"
)

// MaxPreview is the most characters of decoded hidden text a Finding carries.
const MaxPreview = 80

// Finding is one piece of hidden content.
type Finding struct {
	Class Class
	// Offset is the byte offset of the first hidden character, Line and
	// Column its 1-based position (Column counts characters, not bytes).
	Offset, Line, Column int
	// Count is the number of hidden characters in the run (0 for a comment).
	Count int
	// CodePoints are the first hidden characters of the run, at most 16.
	CodePoints []rune
	// Decoded is what the hidden run carries, when it carries text: the ASCII
	// a tag run mirrors, the bytes a variation-selector run encodes, or a
	// comment's text. It holds printable ASCII only (anything else is
	// replaced by '?') and at most MaxPreview characters, so a finding never
	// itself carries an invisible character or a long secret.
	Decoded string
	// InstructionLike says the hidden text reads like an instruction to an
	// agent, a download-and-run command, a credential path or an encoded blob.
	InstructionLike bool
}

// Scan returns the hidden content of text, in the order it appears. It
// reports only what is not explained by an ordinary use of the same
// characters: emoji sequences, right-to-left prose, joining scripts,
// ideographic variation sequences, a byte-order mark at the start, a single
// stray zero-width space, and comments that carry no instruction.
func Scan(text string) []Finding {
	s := newScanner(text)
	var out []Finding
	for i := 0; i < len(s.runes); {
		r := s.runes[i]
		switch {
		case isTag(r):
			i = s.tagRun(i, &out)
		case isVariationSelector(r):
			i = s.selectorRun(i, &out)
		case isZeroWidth(r):
			i = s.zeroWidthRun(i, &out)
		case isBidiOpenOrOverride(r):
			s.bidi(i, &out)
			i++
		case isPrivateUse(r):
			j := i
			for j < len(s.runes) && isPrivateUse(s.runes[j]) {
				j++
			}
			out = append(out, s.finding(PrivateUse, i, j))
			i = j
		default:
			i++
		}
	}
	out = append(out, s.comments()...)
	sortFindings(out)
	return out
}

type scanner struct {
	text    string
	runes   []rune
	offsets []int // byte offset of each rune
}

func newScanner(text string) *scanner {
	s := &scanner{text: text}
	for off, r := range text {
		s.runes = append(s.runes, r)
		s.offsets = append(s.offsets, off)
	}
	return s
}

func (s *scanner) at(i int) rune {
	if i < 0 || i >= len(s.runes) {
		return 0
	}
	return s.runes[i]
}

// finding builds a Finding for the run [from, to) of rune indexes.
func (s *scanner) finding(c Class, from, to int) Finding {
	f := Finding{Class: c, Offset: s.offsets[from], Count: to - from}
	f.Line, f.Column = s.position(from)
	for i := from; i < to && len(f.CodePoints) < 16; i++ {
		f.CodePoints = append(f.CodePoints, s.runes[i])
	}
	return f
}

func (s *scanner) position(idx int) (line, col int) {
	line, col = 1, 1
	for i := 0; i < idx; i++ {
		if s.runes[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// ---- H1: tag characters ----

func isTag(r rune) bool { return r == 0xE0001 || (r >= 0xE0020 && r <= 0xE007F) }

func (s *scanner) tagRun(i int, out *[]Finding) int {
	j := i
	for j < len(s.runes) && isTag(s.runes[j]) {
		j++
	}
	// An emoji tag sequence spells a subdivision flag: U+1F3F4 WAVING BLACK
	// FLAG, tag letters and digits, then U+E007F CANCEL TAG.
	if s.at(i-1) == 0x1F3F4 && s.runes[j-1] == 0xE007F && j-i >= 2 && j-i <= 8 {
		flag := true
		for k := i; k < j-1; k++ {
			c := s.runes[k] - 0xE0000
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
				flag = false
				break
			}
		}
		if flag {
			return j
		}
	}
	f := s.finding(TagCharacters, i, j)
	var b strings.Builder
	for k := i; k < j; k++ {
		if c := s.runes[k] - 0xE0000; c >= 0x20 && c < 0x7F {
			b.WriteRune(c)
		}
	}
	f.Decoded, f.InstructionLike = preview(b.String()), InstructionLike(b.String())
	*out = append(*out, f)
	return j
}

// ---- H4: variation selectors ----

func isVariationSelector(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

func (s *scanner) selectorRun(i int, out *[]Finding) int {
	j := i
	for j < len(s.runes) && isVariationSelector(s.runes[j]) {
		j++
	}
	base := s.at(i - 1)
	// One selector is ordinary after a base that takes one: text or emoji
	// presentation, or an ideographic variation. After an ASCII character it
	// selects nothing, and two or more in a row are not a variation sequence.
	if j-i == 1 && (base == 0 || base > 0x7F) {
		return j
	}
	// A keycap (digit, #, * + U+FE0F + U+20E3) is the one ASCII base that
	// takes a selector.
	if j-i == 1 && s.runes[i] == 0xFE0F && s.at(j) == 0x20E3 {
		return j
	}
	f := s.finding(VariationSelectors, i, j)
	// The carrier encoding seen in the wild maps VS1-16 to bytes 0-15 and
	// VS17-256 to bytes 16-255.
	var b []byte
	for k := i; k < j; k++ {
		if r := s.runes[k]; r <= 0xFE0F {
			b = append(b, byte(r-0xFE00))
		} else {
			b = append(b, byte(r-0xE0100+16))
		}
	}
	f.Decoded, f.InstructionLike = preview(string(b)), InstructionLike(string(b))
	*out = append(*out, f)
	return j
}

// ---- H2: zero-width and invisible format characters ----

func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
		0x180E, 0x00AD, 0xFEFF, 0x115F, 0x1160, 0x3164, 0xFFA0:
		return true
	}
	return false
}

// minZeroWidthRun is the shortest run of unexplained zero-width characters
// that is reported. One or two are what copy and paste leaves behind; a run
// encodes bits. A starting value, not a measured one.
const minZeroWidthRun = 4

// keywords are ASCII words a text filter looks for. A zero-width character
// inside one splits it for the filter and not for the model.
var keywords = []string{
	"ignore", "system", "prompt", "instruction", "curl", "wget", "token",
	"secret", "password", "credential", "execute", "sudo", "bash", "eval",
}

func (s *scanner) zeroWidthRun(i int, out *[]Finding) int {
	j := i
	for j < len(s.runes) && isZeroWidth(s.runes[j]) {
		j++
	}
	if s.splitsKeyword(i, j) {
		*out = append(*out, s.finding(ZeroWidth, i, j))
		return j
	}
	unexplained := 0
	for k := i; k < j; k++ {
		if !s.zeroWidthExplained(k) {
			unexplained++
		}
	}
	if unexplained >= minZeroWidthRun {
		*out = append(*out, s.finding(ZeroWidth, i, j))
	}
	return j
}

// zeroWidthExplained reports whether the character at k has an ordinary use
// where it stands.
func (s *scanner) zeroWidthExplained(k int) bool {
	r, prev, next := s.runes[k], s.at(k-1), s.at(k+1)
	switch r {
	case 0xFEFF:
		return k == 0 // a byte-order mark
	case 0x00AD:
		return unicode.IsLetter(prev) && unicode.IsLetter(next) // a soft hyphen in a word
	case 0x200D:
		if isEmojiPart(prev) && isEmojiPart(next) {
			return true // an emoji ZWJ sequence
		}
		return isJoiningScript(prev) && isJoiningScript(next)
	case 0x200C:
		return isJoiningScript(prev) && isJoiningScript(next)
	}
	return false
}

// splitsKeyword reports whether the zero-width run [i, j) sits inside an ASCII
// word that is a keyword once the invisible characters are removed.
func (s *scanner) splitsKeyword(i, j int) bool {
	isWord := func(r rune) bool { return r < 0x80 && (unicode.IsLetter(r) || isZeroWidth(r)) }
	inWord := func(r rune) bool { return isWord(r) || isZeroWidth(r) }
	a := i
	for a > 0 && inWord(s.runes[a-1]) {
		a--
	}
	b := j
	for b < len(s.runes) && inWord(s.runes[b]) {
		b++
	}
	var w strings.Builder
	left, right := false, false
	for k := a; k < b; k++ {
		if isZeroWidth(s.runes[k]) {
			continue
		}
		if k < i {
			left = true
		}
		if k >= j {
			right = true
		}
		w.WriteRune(unicode.ToLower(s.runes[k]))
	}
	if !left || !right { // the run is at an edge of the word, not inside it
		return false
	}
	word := w.String()
	for _, kw := range keywords {
		if strings.Contains(word, kw) {
			return true
		}
	}
	return false
}

// isEmojiPart reports whether r can stand next to a ZWJ in an emoji sequence:
// a pictograph, a skin-tone modifier, or the emoji variation selector.
func isEmojiPart(r rune) bool {
	switch {
	case r == 0xFE0F,
		r >= 0x1F000 && r <= 0x1FAFF, // pictographs, emoticons, transport, supplemental symbols
		r >= 0x2600 && r <= 0x27BF,   // miscellaneous symbols and dingbats
		r >= 0x2190 && r <= 0x21FF,   // arrows used in emoji sequences
		r >= 0x2B00 && r <= 0x2BFF,
		r == 0x2640, r == 0x2642, r == 0x2695, r == 0x2696, r == 0x2708:
		return true
	}
	return false
}

// isJoiningScript reports whether r belongs to a script in which ZWJ and ZWNJ
// shape ordinary words: Arabic (and Persian, Urdu), Syriac, and the Indic
// scripts.
func isJoiningScript(r rune) bool {
	return unicode.In(r, unicode.Arabic, unicode.Syriac, unicode.Devanagari, unicode.Bengali,
		unicode.Gurmukhi, unicode.Gujarati, unicode.Oriya, unicode.Tamil, unicode.Telugu,
		unicode.Kannada, unicode.Malayalam, unicode.Sinhala, unicode.Mongolian)
}

// ---- H3: bidirectional controls ----

func isBidiOpenOrOverride(r rune) bool {
	return (r >= 0x202A && r <= 0x202E && r != 0x202C) || (r >= 0x2066 && r <= 0x2068)
}

// bidi reports an override always, and an embedding or isolate only when no
// terminator closes it before the end of its line. Balanced embeddings and
// isolates, and the marks U+200E, U+200F and U+061C, are how right-to-left
// prose mixed with Latin is written.
func (s *scanner) bidi(i int, out *[]Finding) {
	r := s.runes[i]
	if r == 0x202D || r == 0x202E {
		*out = append(*out, s.finding(BidiControl, i, i+1))
		return
	}
	closer := rune(0x202C) // POP DIRECTIONAL FORMATTING closes an embedding
	if r >= 0x2066 {
		closer = 0x2069 // POP DIRECTIONAL ISOLATE closes an isolate
	}
	depth := 1
	for k := i + 1; k < len(s.runes) && s.runes[k] != '\n'; k++ {
		c := s.runes[k]
		switch {
		case closer == 0x202C && c >= 0x202A && c <= 0x202E && c != 0x202C,
			closer == 0x2069 && c >= 0x2066 && c <= 0x2068:
			depth++
		case c == closer:
			depth--
			if depth == 0 {
				return
			}
		}
	}
	*out = append(*out, s.finding(BidiControl, i, i+1))
}

// ---- H5: private use and noncharacters ----

// isPrivateUse covers the private-use areas and the noncharacters. Unassigned
// code points are left out on purpose: which ones are unassigned depends on
// the Unicode version compiled into this binary, and a newer emoji would be
// reported as hidden content by an older table.
func isPrivateUse(r rune) bool {
	return (r >= 0xE000 && r <= 0xF8FF) || (r >= 0xF0000 && r <= 0xFFFFD) || (r >= 0x100000 && r <= 0x10FFFD) ||
		(r >= 0xFDD0 && r <= 0xFDEF) || (r&0xFFFE == 0xFFFE && r <= 0x10FFFF && r >= 0xFFFE)
}

// ---- HTML comments ----

var htmlComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)

func (s *scanner) comments() []Finding {
	var out []Finding
	for _, m := range htmlComment.FindAllStringSubmatchIndex(s.text, -1) {
		body := s.text[m[2]:m[3]]
		if !InstructionLike(body) {
			continue
		}
		f := Finding{Class: HTMLComment, Offset: m[0], Decoded: preview(strings.TrimSpace(body)), InstructionLike: true}
		f.Line, f.Column = s.position(utf8.RuneCountInString(s.text[:m[0]]))
		out = append(out, f)
	}
	return out
}

// ---- instruction-like text ----

// phrases are imperatives addressed to an agent that a file's author would
// have no reason to hide. The list is data: short, reviewed, and grown only
// from text found hidden in real files.
var phrases = []string{
	"ignore previous", "ignore all previous", "ignore the previous", "ignore prior",
	"ignore the user", "ignore your instructions", "ignore the above",
	"disregard previous", "disregard the above", "disregard your",
	"do not tell the user", "don't tell the user", "do not mention this", "don't mention this",
	"do not reveal", "without telling the user", "without asking the user",
	"you must", "you are now", "new instructions", "system prompt", "override your",
}

var (
	// A fetched script piped into an interpreter.
	downloadAndRun = regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex|invoke-expression)\b`)
	// Where credentials live on a developer machine.
	credentialPath = regexp.MustCompile(`(?i)(~|\$home|%userprofile%)[/\\]\.(ssh|aws|kube|gnupg|docker|npmrc|netrc)\b|\bid_(rsa|ed25519|ecdsa)\b|(^|[\s"'/\\])\.env\b`)
	// An encoded blob long enough to carry a command.
	base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{64,}={0,2}`)
)

// InstructionLike reports whether text reads like something an agent would
// act on: an imperative addressed to it, a download-and-run command, a
// credential path, or a base64 blob of 64 or more characters.
func InstructionLike(text string) bool {
	lower := strings.ToLower(strings.Join(strings.Fields(text), " "))
	for _, p := range phrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return downloadAndRun.MatchString(text) || credentialPath.MatchString(text) || base64Blob.MatchString(text)
}

// preview makes hidden text safe to show: printable ASCII only, at most
// MaxPreview characters.
func preview(text string) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(text) && n < MaxPreview; i++ {
		c := text[i]
		if c < 0x20 || c > 0x7E {
			c = '?'
		}
		b.WriteByte(c)
		n++
	}
	return b.String()
}

func sortFindings(fs []Finding) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && fs[j].Offset < fs[j-1].Offset; j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}
