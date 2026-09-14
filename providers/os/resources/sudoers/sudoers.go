// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudoers

import (
	"regexp"
	"strings"
)

var (
	// AliasRegex matches alias definitions (User_Alias, Host_Alias, Cmnd_Alias, Runas_Alias)
	AliasRegex = regexp.MustCompile(`^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+(\w+)\s*=\s*(.+)$`)
	// DefaultsRegex matches Defaults lines
	DefaultsRegex = regexp.MustCompile(`^Defaults\b`)
	// IncludeRegex matches @include and #include directives (sudo 1.9.1+)
	IncludeRegex = regexp.MustCompile(`^[@#]include\s+(.+)$`)
	// IncludedirRegex matches @includedir and #includedir directives (sudo 1.9.1+)
	IncludedirRegex = regexp.MustCompile(`^[@#]includedir\s+(.+)$`)
	// TagRegex matches sudo tags (NOPASSWD, SETENV, etc.)
	TagRegex = regexp.MustCompile(`\b(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT)\s*:\s*`)
)

// UserSpec represents a user specification entry in sudoers
type UserSpec struct {
	File        string
	LineNumber  int
	Users       []string
	Hosts       []string
	RunasUsers  []string
	RunasGroups []string
	Tags        []string
	Commands    []string
}

// Default represents a Defaults entry in sudoers
type Default struct {
	File       string
	LineNumber int
	Raw        string
	Scope      string
	Target     string
	Parameter  string
	Value      string
	Operation  string
	Negated    bool
}

// Alias represents an alias definition in sudoers
type Alias struct {
	File       string
	LineNumber int
	Type       string
	Name       string
	Members    []string
}

// ParseUserSpecs parses user specification entries from sudoers content
func ParseUserSpecs(filePath string, content string) []UserSpec {
	var entries []UserSpec
	lines := strings.Split(content, "\n")

	// Track line continuations
	var continuedLine string
	var continuedLineNum int

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Handle line continuations
		if strings.HasSuffix(strings.TrimSpace(line), "\\") {
			if continuedLine == "" {
				continuedLineNum = actualLineNum
			}
			continuedLine += strings.TrimSuffix(strings.TrimSpace(line), "\\") + " "
			continue
		}

		// If we were continuing a line, append this final part
		if continuedLine != "" {
			line = continuedLine + line
			actualLineNum = continuedLineNum
			continuedLine = ""
		}

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip include directives
		if IncludeRegex.MatchString(line) || IncludedirRegex.MatchString(line) {
			continue
		}

		// Parse the line
		parsed := parseLine(line)
		if parsed == nil || parsed.entryType != "user_spec" {
			continue
		}

		entries = append(entries, UserSpec{
			File:        filePath,
			LineNumber:  actualLineNum,
			Users:       parsed.users,
			Hosts:       parsed.hosts,
			RunasUsers:  parsed.runasUsers,
			RunasGroups: parsed.runasGroups,
			Tags:        parsed.tags,
			Commands:    parsed.commands,
		})
	}

	return entries
}

// ParseDefaults parses Defaults entries from sudoers content
func ParseDefaults(filePath string, content string) []Default {
	var defaults []Default
	lines := strings.Split(content, "\n")

	// Track line continuations
	var continuedLine string
	var continuedLineNum int

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Handle line continuations
		if strings.HasSuffix(strings.TrimSpace(line), "\\") {
			if continuedLine == "" {
				continuedLineNum = actualLineNum
			}
			continuedLine += strings.TrimSuffix(strings.TrimSpace(line), "\\") + " "
			continue
		}

		// If we were continuing a line, append this final part
		if continuedLine != "" {
			line = continuedLine + line
			actualLineNum = continuedLineNum
			continuedLine = ""
		}

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Only process Defaults lines
		if !DefaultsRegex.MatchString(line) {
			continue
		}

		// Parse the Defaults line
		scope, target, parameter, value, operation, negated := ParseDefaultsLine(line)

		defaults = append(defaults, Default{
			File:       filePath,
			LineNumber: actualLineNum,
			Raw:        line,
			Scope:      scope,
			Target:     target,
			Parameter:  parameter,
			Value:      value,
			Operation:  operation,
			Negated:    negated,
		})
	}

	return defaults
}

// ParseAliases parses alias definitions from sudoers content
func ParseAliases(filePath string, content string) []Alias {
	var aliases []Alias
	lines := strings.Split(content, "\n")

	// Track line continuations
	var continuedLine string
	var continuedLineNum int

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Handle line continuations
		if strings.HasSuffix(strings.TrimSpace(line), "\\") {
			if continuedLine == "" {
				continuedLineNum = actualLineNum
			}
			continuedLine += strings.TrimSuffix(strings.TrimSpace(line), "\\") + " "
			continue
		}

		// If we were continuing a line, append this final part
		if continuedLine != "" {
			line = continuedLine + line
			actualLineNum = continuedLineNum
			continuedLine = ""
		}

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for alias definitions
		matches := AliasRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		aliasType := matches[1] // User_Alias, Host_Alias, etc.
		aliasName := matches[2]
		aliasValue := matches[3]

		// Convert alias type to lowercase without "_Alias" suffix
		typeStr := strings.ToLower(strings.TrimSuffix(aliasType, "_Alias"))

		// Parse members
		memberList := splitAndTrim(aliasValue, ",")

		aliases = append(aliases, Alias{
			File:       filePath,
			LineNumber: actualLineNum,
			Type:       typeStr,
			Name:       aliasName,
			Members:    memberList,
		})
	}

	return aliases
}

// ParseDefaultsLine parses a Defaults line and extracts its components
// Returns: scope, target, parameter, value, operation, negated
func ParseDefaultsLine(line string) (string, string, string, string, string, bool) {
	// Strip "Defaults" prefix
	line = strings.TrimSpace(strings.TrimPrefix(line, "Defaults"))

	scope := "global"
	target := ""

	// Check for scope specifiers
	if len(line) > 0 {
		switch line[0] {
		case ':': // User-specific
			scope = "user"
		case '@': // Host-specific
			scope = "host"
		case '>': // Runas-specific
			scope = "runas"
		case '!': // Command-specific
			scope = "command"
		}
		if scope != "global" {
			target, line = splitOnWhitespace(line[1:])
		}
	}

	line = strings.TrimSpace(line)

	// Check for negation
	negated := false
	if strings.HasPrefix(line, "!") {
		negated = true
		line = strings.TrimPrefix(line, "!")
	}

	// Parse parameter[operator]value
	parameter := ""
	value := ""
	operation := ""

	// Check for operators: =, +=, -=
	if idx := strings.Index(line, "+="); idx != -1 {
		parameter = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+2:])
		operation = "+="
	} else if idx := strings.Index(line, "-="); idx != -1 {
		parameter = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+2:])
		operation = "-="
	} else if idx := strings.Index(line, "="); idx != -1 {
		parameter = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+1:])
		operation = "="
	} else {
		// No operator, just a parameter (boolean flag)
		parameter = strings.TrimSpace(line)
		operation = ""
	}

	// Remove quotes from value if present
	value = strings.Trim(value, "\"")

	return scope, target, parameter, value, operation, negated
}

// splitOnWhitespace splits s at the first space or tab and returns the leading
// token plus the remainder with its leading whitespace removed. Sudoers accepts
// either separator between a scoped Defaults target and its parameter.
func splitOnWhitespace(s string) (string, string) {
	idx := strings.IndexAny(s, " \t")
	if idx == -1 {
		return s, ""
	}
	return s[:idx], strings.TrimLeft(s[idx:], " \t")
}

// parsedLine represents a parsed line from a sudoers file (internal use)
type parsedLine struct {
	entryType   string
	users       []string
	hosts       []string
	runasUsers  []string
	runasGroups []string
	tags        []string
	commands    []string
}

// parseLine parses a single line from a sudoers file
func parseLine(line string) *parsedLine {
	// Filter out comments
	if strings.HasPrefix(line, "#") {
		return nil
	}

	// Filter out empty lines
	if strings.TrimSpace(line) == "" {
		return nil
	}

	// Check for Defaults entries
	if DefaultsRegex.MatchString(line) {
		return &parsedLine{
			entryType: "defaults",
		}
	}

	// Check for alias definitions
	if AliasRegex.MatchString(line) {
		return &parsedLine{
			entryType: "alias",
		}
	}

	// Check for include directives
	if IncludeRegex.MatchString(line) || IncludedirRegex.MatchString(line) {
		return &parsedLine{
			entryType: "include",
		}
	}

	// Parse user specification
	// Format: user host=(runasuser:runasgroup) tag: command
	result := &parsedLine{
		entryType: "user_spec",
	}

	// First, extract runas specification from the line before splitting
	// This is important because the host can be followed directly by =(...)
	runasStart := strings.Index(line, "=(")
	var remaining string
	var beforeRunas string

	if runasStart != -1 {
		runasEnd := strings.Index(line[runasStart:], ")")
		if runasEnd != -1 {
			runasEnd += runasStart
			runasSpec := line[runasStart+2 : runasEnd]

			// Parse runas users and groups
			if strings.Contains(runasSpec, ":") {
				runasParts := strings.SplitN(runasSpec, ":", 2)
				result.runasUsers = splitAndTrim(runasParts[0], ",")
				result.runasGroups = splitAndTrim(runasParts[1], ",")
			} else {
				result.runasUsers = splitAndTrim(runasSpec, ",")
			}

			// Split line into parts: before runas, and after runas
			beforeRunas = strings.TrimSpace(line[:runasStart])
			remaining = strings.TrimSpace(line[runasEnd+1:])
		}
	} else {
		// No runas specification. The first `=` separates the "user host"
		// portion from the command spec, and whitespace around it is optional
		// (e.g. `root ALL=ALL` or `bob ALL=/bin/ls`). Splitting on whitespace
		// alone misreads (or drops) these specs, so split on `=` here and
		// reuse the shared user/host logic below — analogous to how the runas
		// branch splits around `=(...)`.
		eq := strings.Index(line, "=")
		if eq == -1 {
			return nil
		}
		beforeRunas = strings.TrimSpace(line[:eq])
		remaining = strings.TrimSpace(line[eq+1:])
	}

	// For lines with runas, split beforeRunas to get user and host
	tokens := smartSplit(beforeRunas)
	if len(tokens) < 2 {
		return nil
	}

	// Find the boundary between user list and host list
	var userEndIndex int
	for i := len(tokens) - 1; i >= 0; i-- {
		token := strings.TrimSpace(tokens[i])
		if strings.HasSuffix(token, ",") {
			continue
		}
		if i > 0 && strings.HasSuffix(strings.TrimSpace(tokens[i-1]), ",") {
			continue
		}
		if i < len(tokens)-1 {
			userEndIndex = i
			break
		}
		userEndIndex = i - 1
		break
	}

	if userEndIndex < 0 {
		return nil
	}

	// Split into user and host parts
	userTokens := tokens[:userEndIndex+1]
	hostTokens := tokens[userEndIndex+1:]

	// Join and parse
	userPart := strings.Join(userTokens, " ")
	result.users = splitAndTrim(userPart, ",")

	hostPart := strings.Join(hostTokens, " ")
	result.hosts = splitAndTrim(hostPart, ",")

	// Extract tags and commands from remaining
	extractTagsAndCommands(result, remaining)
	return result
}

// extractTagsAndCommands extracts tags and commands from a sudoers line
func extractTagsAndCommands(result *parsedLine, remaining string) {
	for {
		match := TagRegex.FindStringIndex(remaining)
		if match == nil {
			break
		}
		tag := strings.TrimSpace(remaining[match[0]:match[1]])
		tag = strings.TrimSuffix(tag, ":")
		result.tags = append(result.tags, strings.TrimSpace(tag))
		remaining = remaining[match[1]:]
	}

	// Remaining part is the command specification
	if remaining != "" {
		result.commands = SplitCommands(remaining)
	}
}

// smartSplit splits a string on runs of spaces or tabs but respects quoted
// strings. Distribution-shipped sudoers files separate the user, host and
// command fields with tabs, so splitting on spaces alone drops every rule.
func smartSplit(s string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	escaped := false

	for _, ch := range s {
		if escaped {
			current.WriteRune(ch)
			escaped = false
			continue
		}

		if ch == '\\' {
			escaped = true
			current.WriteRune(ch)
			continue
		}

		if ch == '"' {
			inQuote = !inQuote
			current.WriteRune(ch)
			continue
		}

		if (ch == ' ' || ch == '\t') && !inQuote {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteRune(ch)
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// SplitCommands splits command specifications by comma (exported for testing)
func SplitCommands(s string) []string {
	var commands []string
	var current strings.Builder
	inQuote := false
	escaped := false

	for _, ch := range s {
		if escaped {
			current.WriteRune(ch)
			escaped = false
			continue
		}

		if ch == '\\' {
			escaped = true
			current.WriteRune(ch)
			continue
		}

		if ch == '"' {
			inQuote = !inQuote
			current.WriteRune(ch)
			continue
		}

		if ch == ',' && !inQuote {
			if current.Len() > 0 {
				commands = append(commands, strings.TrimSpace(current.String()))
				current.Reset()
			}
			continue
		}

		current.WriteRune(ch)
	}

	if current.Len() > 0 {
		commands = append(commands, strings.TrimSpace(current.String()))
	}

	return commands
}

// splitAndTrim splits a string by the given separator and trims each part
func splitAndTrim(s string, sep string) []string {
	if s == "" {
		return []string{}
	}

	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// SmartSplit is exported for testing
func SmartSplit(s string) []string {
	return smartSplit(s)
}

// SplitAndTrim is exported for testing
func SplitAndTrim(s string, sep string) []string {
	return splitAndTrim(s, sep)
}

// ParseLine is exported for testing
func ParseLine(line string) *parsedLine {
	return parseLine(line)
}

// ParsedLine provides access to internal parsedLine fields for testing
type ParsedLine struct {
	EntryType   string
	Users       []string
	Hosts       []string
	RunasUsers  []string
	RunasGroups []string
	Tags        []string
	Commands    []string
}

// ToParsedLine converts internal parsedLine to exported ParsedLine for testing
func ToParsedLine(p *parsedLine) *ParsedLine {
	if p == nil {
		return nil
	}
	return &ParsedLine{
		EntryType:   p.entryType,
		Users:       p.users,
		Hosts:       p.hosts,
		RunasUsers:  p.runasUsers,
		RunasGroups: p.runasGroups,
		Tags:        p.tags,
		Commands:    p.commands,
	}
}
