// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/xml"
	"path"
	"regexp"
	"sort"
	"strings"
)

// polkitActionEntry is one action parsed from a polkit .policy file.
type polkitActionEntry struct {
	ID            string
	Description   string
	Message       string
	Vendor        string
	VendorURL     string
	IconName      string
	AllowAny      string
	AllowInactive string
	AllowActive   string
	Annotations   map[string]string
}

// polkitLocalAuthorityEntry is one section parsed from a legacy .pkla file.
type polkitLocalAuthorityEntry struct {
	Name           string
	Identities     []string
	Actions        []string
	ResultAny      string
	ResultInactive string
	ResultActive   string
}

// polkitRuleFacts holds everything a lexical pass over a JavaScript rule body
// can state without evaluating it.
type polkitRuleFacts struct {
	AdminRule bool
	ActionIDs []string
	Results   []string
}

// polkitRuleFile is a rule file that survived shadowing, together with the
// position it occupies in polkit's evaluation order.
type polkitRuleFile struct {
	Path  string
	Order int
}

type polkitPolicyDoc struct {
	XMLName   xml.Name             `xml:"policyconfig"`
	Vendor    string               `xml:"vendor"`
	VendorURL string               `xml:"vendor_url"`
	IconName  string               `xml:"icon_name"`
	Actions   []polkitPolicyAction `xml:"action"`
}

// polkitLocalizedText is a description or message element. Policy files repeat
// these once per translation, distinguished by the xml:lang attribute.
type polkitLocalizedText struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

type polkitPolicyAction struct {
	ID           string                `xml:"id,attr"`
	Descriptions []polkitLocalizedText `xml:"description"`
	Messages     []polkitLocalizedText `xml:"message"`
	Vendor       string                `xml:"vendor"`
	VendorURL    string                `xml:"vendor_url"`
	IconName     string                `xml:"icon_name"`
	Defaults     struct {
		AllowAny      string `xml:"allow_any"`
		AllowInactive string `xml:"allow_inactive"`
		AllowActive   string `xml:"allow_active"`
	} `xml:"defaults"`
	Annotations []struct {
		Key   string `xml:"key,attr"`
		Value string `xml:",chardata"`
	} `xml:"annotate"`
}

var polkitPklaSectionRegex = regexp.MustCompile(`^\[(.*)\]$`)

var (
	polkitAdminRuleRegex = regexp.MustCompile(`\baddAdminRule\s*\(`)
	polkitResultRegex    = regexp.MustCompile(`\bResult\.([A-Z][A-Z_]*)\b`)

	// polkitResultStrings are the values of polkit.Result's constants, which a
	// rule may return directly. NOT_HANDLED is null, not a string, and polkit
	// matches these case-sensitively.
	polkitResultStrings = map[string]struct{}{
		"no": {}, "yes": {}, "auth_self": {}, "auth_self_keep": {}, "auth_admin": {}, "auth_admin_keep": {},
	}

	// polkitActionIDRegex matches a reverse-DNS action identifier, optionally
	// ending in a trailing dot or star so the prefixes used with startsWith and
	// with a regular expression are recognized too.
	polkitActionIDRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*(\.[a-zA-Z0-9_-]+)+\.?\*?$`)

	polkitVersionRegex = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)*)\s*$`)
)

// parsePolkitPolicy parses the XML of a polkit .policy file into its actions.
// Localized description and message variants are skipped in favor of the
// untranslated text, which is what polkit falls back to and what an audit
// should compare against.
func parsePolkitPolicy(content string) ([]polkitActionEntry, error) {
	doc := polkitPolicyDoc{}
	if err := xml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, err
	}

	res := make([]polkitActionEntry, 0, len(doc.Actions))
	for i := range doc.Actions {
		raw := doc.Actions[i]
		id := strings.TrimSpace(raw.ID)
		if id == "" {
			continue
		}

		entry := polkitActionEntry{
			ID:            id,
			Description:   untranslatedPolkitText(raw.Descriptions),
			Message:       untranslatedPolkitText(raw.Messages),
			Vendor:        polkitFallback(raw.Vendor, doc.Vendor),
			VendorURL:     polkitFallback(raw.VendorURL, doc.VendorURL),
			IconName:      polkitFallback(raw.IconName, doc.IconName),
			AllowAny:      strings.TrimSpace(raw.Defaults.AllowAny),
			AllowInactive: strings.TrimSpace(raw.Defaults.AllowInactive),
			AllowActive:   strings.TrimSpace(raw.Defaults.AllowActive),
			Annotations:   map[string]string{},
		}

		for _, annotation := range raw.Annotations {
			key := strings.TrimSpace(annotation.Key)
			if key == "" {
				continue
			}
			entry.Annotations[key] = strings.TrimSpace(annotation.Value)
		}

		res = append(res, entry)
	}

	return res, nil
}

// untranslatedPolkitText returns the variant carrying no xml:lang attribute.
func untranslatedPolkitText(texts []polkitLocalizedText) string {
	for _, text := range texts {
		if text.Lang == "" {
			return strings.TrimSpace(text.Value)
		}
	}
	return ""
}

func polkitFallback(primary string, fallback string) string {
	if trimmed := strings.TrimSpace(primary); trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(fallback)
}

// parsePolkitPkla parses a legacy .pkla file into its sections. The key names
// are matched exactly as the local authority documents them, with whitespace
// around the separator tolerated.
func parsePolkitPkla(content string) []polkitLocalAuthorityEntry {
	res := []polkitLocalAuthorityEntry{}
	current := -1

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if match := polkitPklaSectionRegex.FindStringSubmatch(line); match != nil {
			res = append(res, polkitLocalAuthorityEntry{Name: strings.TrimSpace(match[1])})
			current = len(res) - 1
			continue
		}

		// a key outside of any section is not a grant, so it carries no meaning
		if current < 0 {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "Identity":
			res[current].Identities = splitPolkitList(value)
		case "Action":
			res[current].Actions = splitPolkitList(value)
		case "ResultAny":
			res[current].ResultAny = value
		case "ResultInactive":
			res[current].ResultInactive = value
		case "ResultActive":
			res[current].ResultActive = value
		}
	}

	return res
}

// parsePolkitLocalAuthorityConf pulls AdminIdentities out of a
// localauthority.conf.d file. A later assignment overrides an earlier one, so
// the final occurrence wins. Returns nil when the file sets no identities,
// which lets the caller tell "unset" apart from "set to nothing".
func parsePolkitLocalAuthorityConf(content string) []string {
	var res []string

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "AdminIdentities" {
			continue
		}
		res = splitPolkitList(strings.TrimSpace(value))
	}

	return res
}

// splitPolkitList splits a semicolon-separated polkit value list, dropping
// empty elements left behind by a trailing separator.
func splitPolkitList(value string) []string {
	parts := strings.Split(value, ";")
	res := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

// polkitRuleFactsFrom collects what can be stated about a JavaScript rule body
// without evaluating it: whether it registers an administrator rule, which
// action identifiers it names, and which result values it can return.
func polkitRuleFactsFrom(body string) polkitRuleFacts {
	literals, code := scanPolkitRuleBody(body)

	actionIDs := map[string]struct{}{}
	for _, literal := range literals {
		candidate := strings.TrimSpace(literal)
		if candidate == "" || !strings.Contains(candidate, ".") {
			continue
		}
		if !polkitActionIDRegex.MatchString(candidate) {
			continue
		}
		actionIDs[candidate] = struct{}{}
	}

	results := map[string]struct{}{}
	for _, match := range polkitResultRegex.FindAllStringSubmatch(code, -1) {
		results[match[1]] = struct{}{}
	}
	// A rule may return the string a Result constant stands for. SUSE's
	// generated 90-default-privs.rules returns entries of a lookup table such
	// as [ 'auth_admin', 'auth_admin', 'yes' ] and never names Result.
	for _, literal := range literals {
		if _, ok := polkitResultStrings[literal]; ok {
			results[strings.ToUpper(literal)] = struct{}{}
		}
	}

	return polkitRuleFacts{
		AdminRule: polkitAdminRuleRegex.MatchString(code),
		ActionIDs: sortedPolkitSet(actionIDs),
		Results:   sortedPolkitSet(results),
	}
}

// scanPolkitRuleBody walks a rule body once, returning the string literals it
// holds and a copy of the body with comments removed and literals blanked out.
// Separating the two keeps a commented-out rule from being reported as live
// configuration, and keeps the "//" in a URL inside a string from being
// mistaken for the start of a comment.
//
// A backtick literal is read to its closing backtick, so a `${...}`
// interpolation is captured as part of the literal rather than as code. Two
// consequences, both accepted because polkit rules are plain ECMAScript 5 and do
// not use template literals: a result value referenced only inside an
// interpolation is not reported, and a backtick nested inside an interpolation
// ends the literal early.
func scanPolkitRuleBody(body string) (literals []string, code string) {
	literals = []string{}

	var out strings.Builder
	out.Grow(len(body))

	runes := []rune(body)
	for i := 0; i < len(runes); i++ {
		char := runes[i]

		if char == '/' && i+1 < len(runes) {
			if runes[i+1] == '/' {
				for i < len(runes) && runes[i] != '\n' {
					i++
				}
				out.WriteRune('\n')
				continue
			}

			if runes[i+1] == '*' {
				i += 2
				for i+1 < len(runes) && (runes[i] != '*' || runes[i+1] != '/') {
					i++
				}
				// land on the closing slash so the loop steps past it. On a
				// truncated file with no closing "*/" the scan already sits at the
				// end, and advancing once more only ends the loop.
				i++
				out.WriteRune(' ')
				continue
			}
		}

		if char == '\'' || char == '"' || char == '`' {
			quote := char
			var literal strings.Builder

			i++
			for i < len(runes) {
				if runes[i] == '\\' && i+1 < len(runes) {
					literal.WriteRune(runes[i+1])
					i += 2
					continue
				}
				if runes[i] == quote {
					break
				}
				literal.WriteRune(runes[i])
				i++
			}

			literals = append(literals, literal.String())
			out.WriteRune(' ')
			continue
		}

		out.WriteRune(char)
	}

	return literals, out.String()
}

// orderPolkitRuleFiles resolves the effective rule set from per-directory file
// lists given in precedence order. Polkit merges every rule directory and
// evaluates the result in lexicographic order by file name; when a name appears
// in more than one directory the earliest directory wins, which is how a file
// dropped into /etc overrides a distribution default of the same name.
func orderPolkitRuleFiles(dirFiles [][]string) []polkitRuleFile {
	winners := map[string]string{}
	names := []string{}

	for _, files := range dirFiles {
		for _, file := range files {
			name := path.Base(file)
			if _, taken := winners[name]; taken {
				continue
			}
			winners[name] = file
			names = append(names, name)
		}
	}

	sort.Strings(names)

	res := make([]polkitRuleFile, 0, len(names))
	for i, name := range names {
		res = append(res, polkitRuleFile{Path: winners[name], Order: i})
	}
	return res
}

// parsePolkitVersion pulls the release out of pkaction --version output, which
// reads like "pkaction version 0.105".
func parsePolkitVersion(out string) string {
	line := strings.TrimSpace(out)
	if line == "" {
		return ""
	}
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}

	match := polkitVersionRegex.FindStringSubmatch(line)
	if match == nil {
		return ""
	}
	return match[1]
}

func sortedPolkitSet(set map[string]struct{}) []string {
	res := make([]string, 0, len(set))
	for key := range set {
		res = append(res, key)
	}
	sort.Strings(res)
	return res
}
