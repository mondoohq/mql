// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"
	"strings"
)

type luksDump struct {
	Version       int
	UUID          string
	Label         string
	Subsystem     string
	MasterKeyBits int
	PayloadOffset int
	Cipher        luksCipherInfo
	Keyslots      []luksKeyslotInfo
	Tokens        []map[string]any
}

type luksCipherInfo struct {
	Name    string
	Mode    string
	Spec    string
	KeySize int
	Hash    string
}

type luksKeyslotInfo struct {
	Index             int
	State             string
	KDF               string
	Iterations        int
	Time              int
	Memory            int
	Parallel          int
	Hash              string
	Stripes           int
	KeyMaterialOffset int
}

// parseLuksDump parses the text output of `cryptsetup luksDump <device>`
// for both LUKS1 and LUKS2 headers.
func parseLuksDump(out string) (luksDump, error) {
	d := luksDump{}
	lines := strings.Split(out, "\n")

	// Pass 1: global header fields, up to the first section header. LUKS2
	// uses named sections ("Keyslots:", "Tokens:", "Digests:", "Data
	// segments:"); LUKS1 has no Keyslots: header — slots appear as
	// "Key Slot N: ENABLED|DISABLED" lines after the header fields.
	i := 0
	for ; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		if isSectionHeader(trimmed) || strings.HasPrefix(trimmed, "Key Slot ") {
			break
		}

		key, value, ok := splitColon(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "Version":
			d.Version, _ = strconv.Atoi(value)
		case "UUID":
			d.UUID = value
		case "Label":
			d.Label = decodeNoneSentinel(value)
		case "Subsystem":
			d.Subsystem = decodeNoneSentinel(value)
		case "Cipher name":
			d.Cipher.Name = value
		case "Cipher mode":
			d.Cipher.Mode = value
		case "Hash spec":
			d.Cipher.Hash = value
		case "MK bits":
			d.MasterKeyBits, _ = strconv.Atoi(value)
			d.Cipher.KeySize = d.MasterKeyBits
		case "Payload offset":
			d.PayloadOffset, _ = strconv.Atoi(value)
		}
	}

	if d.Version == 0 {
		return d, errors.New("luksDump output: missing Version field")
	}

	if d.Cipher.Name != "" && d.Cipher.Mode != "" {
		d.Cipher.Spec = d.Cipher.Name + "-" + d.Cipher.Mode
	}

	rest := lines[i:]
	if d.Version == 1 {
		parseLuks1Keyslots(rest, &d)
	} else {
		parseLuks2Sections(rest, &d)
	}

	return d, nil
}

func isSectionHeader(trimmed string) bool {
	switch trimmed {
	case "Keyslots:", "Tokens:", "Digests:", "Data segments:":
		return true
	}
	return false
}

// splitColon splits on the *first* colon only — important because LUKS
// cipher-mode values can themselves contain colons (e.g.
// `cbc-essiv:sha256`). Splitting on the last colon would corrupt those.
func splitColon(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

// decodeNoneSentinel translates cryptsetup's "(no ...)" sentinels into
// empty strings so unset fields don't carry that text into MQL.
func decodeNoneSentinel(value string) string {
	if strings.HasPrefix(value, "(no ") && strings.HasSuffix(value, ")") {
		return ""
	}
	return value
}

func parseLuks1Keyslots(lines []string, d *luksDump) {
	var current *luksKeyslotInfo
	flush := func() {
		if current != nil {
			d.Keyslots = append(d.Keyslots, *current)
			current = nil
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "Key Slot ") {
			flush()
			rest := strings.TrimPrefix(trimmed, "Key Slot ")
			idxStr, state, ok := splitColon(rest)
			if !ok {
				continue
			}
			n, err := strconv.Atoi(idxStr)
			if err != nil {
				continue
			}
			current = &luksKeyslotInfo{Index: n, State: state}
			// Only ENABLED slots carry KDF parameters; populate kdf/hash
			// from the volume header so audits that filter by these
			// fields don't false-positive on DISABLED slots.
			if state == "ENABLED" {
				current.KDF = "pbkdf2"
				current.Hash = d.Cipher.Hash
			}
			continue
		}

		if current == nil {
			continue
		}

		key, value, ok := splitColon(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "Iterations":
			current.Iterations, _ = strconv.Atoi(value)
		case "Key material offset":
			current.KeyMaterialOffset, _ = strconv.Atoi(value)
		case "AF stripes":
			current.Stripes, _ = strconv.Atoi(value)
		}
	}
	flush()
}

func parseLuks2Sections(lines []string, d *luksDump) {
	type section int
	const (
		sectionNone section = iota
		sectionKeyslots
		sectionSegments
		sectionTokens
		sectionDigests
	)

	var (
		sec       = sectionNone
		keyslot   *luksKeyslotInfo
		token     map[string]any
		segIndex  = -1 // current `Data segments:` subsection index (-1 outside)
		cipherSet bool
	)
	flushKeyslot := func() {
		if keyslot != nil {
			d.Keyslots = append(d.Keyslots, *keyslot)
			keyslot = nil
		}
	}
	flushToken := func() {
		if token != nil {
			d.Tokens = append(d.Tokens, token)
			token = nil
		}
	}

	for _, line := range lines {
		if line == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)

		if isSectionHeader(trimmed) {
			flushKeyslot()
			flushToken()
			segIndex = -1
			switch trimmed {
			case "Keyslots:":
				sec = sectionKeyslots
			case "Data segments:":
				sec = sectionSegments
			case "Tokens:":
				sec = sectionTokens
			case "Digests:":
				sec = sectionDigests
			}
			continue
		}

		// Subsection start ("  N: <type>") — not tab-indented, numeric id.
		if !strings.HasPrefix(line, "\t") && isSubsectionStart(trimmed) {
			flushKeyslot()
			flushToken()
			idxStr, typ, _ := splitColon(trimmed)
			n, _ := strconv.Atoi(idxStr)
			switch sec {
			case sectionKeyslots:
				// Slots that appear in a LUKS2 textual dump are by
				// definition allocated and usable — the on-disk format
				// has no separate "inactive" state (LUKS1's
				// ENABLED/DISABLED distinction doesn't carry over).
				// `Priority: ignore` further down can still mark a slot
				// as not-prompted-for, but the slot remains valid.
				keyslot = &luksKeyslotInfo{Index: n, State: "active"}
			case sectionTokens:
				token = map[string]any{"id": int64(n), "type": typ}
			case sectionSegments:
				segIndex = n
			}
			continue
		}

		key, value, ok := splitColon(trimmed)
		if !ok {
			continue
		}
		switch sec {
		case sectionKeyslots:
			if keyslot != nil {
				applyLuks2KeyslotField(keyslot, d, key, value)
			}
		case sectionTokens:
			if token != nil {
				applyLuks2TokenField(token, key, value)
			}
		case sectionSegments:
			// LUKS2 keeps the cipher under the data segment, not the
			// global header. Take the first segment's cipher as the
			// volume's cipher — multi-segment LUKS2 volumes are rare
			// and a segment-aware audit would need a deeper schema.
			if segIndex == 0 && key == "cipher" && !cipherSet {
				setLuks2CipherSpec(&d.Cipher, value)
				cipherSet = true
			}
		}
	}
	flushKeyslot()
	flushToken()
}

// setLuks2CipherSpec splits a cryptsetup cipher string like
// "aes-xts-plain64" or "twofish-cbc-essiv:sha256" into Name/Mode/Spec.
// Cipher family names from the kernel crypto API don't contain
// hyphens, so splitting on the first hyphen reliably separates the
// family from the chaining mode.
func setLuks2CipherSpec(c *luksCipherInfo, spec string) {
	c.Spec = spec
	if idx := strings.IndexByte(spec, '-'); idx > 0 {
		c.Name = spec[:idx]
		c.Mode = spec[idx+1:]
	} else {
		c.Name = spec
	}
}

// isSubsectionStart reports whether the trimmed line is of the form
// "N: <type>" — a numeric id followed by a colon. Used to detect the
// start of a keyslot/token/segment/digest entry.
func isSubsectionStart(trimmed string) bool {
	idx := strings.IndexByte(trimmed, ':')
	if idx <= 0 {
		return false
	}
	for _, r := range trimmed[:idx] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func applyLuks2KeyslotField(k *luksKeyslotInfo, d *luksDump, key, value string) {
	switch key {
	case "PBKDF":
		k.KDF = value
	case "Hash":
		k.Hash = value
	case "Iterations":
		k.Iterations, _ = strconv.Atoi(value)
	case "Time cost":
		k.Time, _ = strconv.Atoi(value)
	case "Memory":
		k.Memory, _ = strconv.Atoi(value)
	case "Threads":
		k.Parallel, _ = strconv.Atoi(value)
	case "AF stripes":
		k.Stripes, _ = strconv.Atoi(value)
	case "Area offset":
		// "32768 [bytes]" — convert to 512-byte sectors to match LUKS1.
		k.KeyMaterialOffset = firstInt(value) / 512
	case "Key", "Cipher key":
		// "Key: 512 bits" is the size of the volume key the slot wraps.
		// cryptsetup 2.0.x (RHEL 7) prints only that line; later releases
		// follow it with "Cipher key: 512 bits", the keyslot area cipher's
		// key, which matches it. LUKS2 has no global "MK bits" header; take
		// the first keyslot we see as authoritative since all slots in
		// a single-segment volume wrap the same master key.
		if d.MasterKeyBits == 0 {
			bits := firstInt(value)
			d.MasterKeyBits = bits
			d.Cipher.KeySize = bits
		}
	}
}

func applyLuks2TokenField(t map[string]any, key, value string) {
	switch key {
	case "Keyslot":
		n, err := strconv.Atoi(value)
		if err == nil {
			existing, _ := t["keyslots"].([]int64)
			t["keyslots"] = append(existing, int64(n))
		}
	default:
		t[lowerFirst(key)] = value
	}
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// isLuksFstype reports whether an lsblk fstype string indicates a
// LUKS-formatted block device. Both LUKS1 and LUKS2 are reported as
// "crypto_LUKS" by lsblk.
func isLuksFstype(fstype string) bool {
	return fstype == "crypto_LUKS"
}

// firstInt returns the first run of digits in s as an int.
func firstInt(s string) int {
	start := -1
	for i, r := range s {
		if r >= '0' && r <= '9' {
			if start < 0 {
				start = i
			}
		} else if start >= 0 {
			n, _ := strconv.Atoi(s[start:i])
			return n
		}
	}
	if start >= 0 {
		n, _ := strconv.Atoi(s[start:])
		return n
	}
	return 0
}
