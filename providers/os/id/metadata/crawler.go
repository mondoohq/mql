// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package metadata

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

// Compiled once: applied to every value the crawler classifies.
var sshKeyPattern = regexp.MustCompile(`(?:^|[:\s])(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|ssh-ecdsa)\s+[A-Za-z0-9+/=]`)

const maxDepth = 50

// recursive is the interface passed to `Crawl` to fetch all metadata from an instance
type recursive interface {
	GetMetadataValue(path string) (string, error)
}

// Crawl fetches all metadata from an instance recursively
func Crawl(r recursive, path string) (any, error) {
	return getMetadataRecursively(r, path, 0)
}

func getMetadataRecursively(r recursive, path string, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("crawler reached maximum depth limit")
	}

	log.Trace().Str("path", path).Msg("os.id.metadata> crawling")
	data, err := r.GetMetadataValue(path)
	if err != nil {
		return nil, err
	}

	// If the response is JSON, parse it
	if isJSON(data) {
		log.Trace().Str("path", path).Msg("os.id.metadata> json format")
		var jsonData any
		if err := json.Unmarshal([]byte(data), &jsonData); err != nil {
			return nil, err
		}
		return jsonData, nil
	}

	// Handle specific paths that return multiline strings (e.g., "meta-data/managed-ssh-keys/signer-cert")
	if isMultilineString(path) {
		log.Trace().Str("path", path).Msg("os.id.metadata> multiline string")
		return data, nil // Preserve as a raw string
	}

	// If the data is a multiline string, return it as a raw string
	if detectMultilineString(data) {
		log.Trace().Str("path", path).Msg("os.id.metadata> multiline string (detected)")
		return data, nil
	}

	lines := strings.Split(data, "\n")

	// If the data contains sub-paths, fetch them recursively
	if len(lines) > 1 || strings.HasSuffix(data, "/") {
		result := make(map[string]any)
		values := make([]string, 0, len(lines))
		resolvedChild := false

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			key := strings.TrimSuffix(line, "/")
			values = append(values, key)

			subPath := path + line

			subData, err := getMetadataRecursively(r, subPath, depth+1)
			if err != nil {
				log.Trace().Err(err).
					Str("path", path).
					Str("line", line).
					Msg("os.id.awsec2> failed to get sub-path metadata")
				continue
			}

			resolvedChild = true
			result[key] = subData
		}

		// Some IMDS keys return a newline-separated *list of values* rather than
		// a directory of navigable sub-paths (e.g. "security-group-ids",
		// "vpc-ipv4-cidr-blocks", or a multi-valued "local-ipv4s"). For those,
		// the sub-path lookups above all fail, which previously produced an
		// empty map and silently dropped the data. Treat that case as a value
		// list and preserve the values instead.
		if !resolvedChild {
			return values, nil
		}

		return result, nil
	}

	// If it's a single value, return it as a string
	return data, nil
}

// isJSON checks if a string is valid JSON.
func isJSON(data string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(data), &js) == nil
}

// Add any additional paths that should be treated as multiline strings.
//
// Regex are allowed with `*` for single segment and `**` for multiple, if the
// path is not a regex, it will be considered an exact match.
var multilineStringFields = []string{
	// AWS
	"**/signer-cert",
	// GCP
	"instance/service-accounts/*/scopes",
	"instance/attributes/ssh-keys",
	"instance/attributes/sshKeys",
	"instance/attributes/startup-script",
	"instance/attributes/shutdown-script",
	"instance/attributes/user-data",
	"instance/attributes/windows-startup-script-ps1",
	"instance/attributes/windows-startup-script-cmd",
	"instance/attributes/windows-startup-script-bat",
	"instance/attributes/windows-startup-script-url",
	"instance/attributes/sysprep-specialize-script-ps1",
	"instance/attributes/sysprep-specialize-script-cmd",
	"instance/attributes/sysprep-specialize-script-bat",
	"instance/attributes/sysprep-specialize-script-url",
}

// isMultilineString checks if a path should be treated as a raw multiline string.
func isMultilineString(path string) bool {
	for _, pattern := range multilineStringFields {
		if matchRegex(pattern, path) {
			return true
		}
	}

	return false
}

// matchRegex accepts a pattern considered a regex and the path to match.
func matchRegex(pattern, path string) bool {
	re, err := regexp.Compile(patternToRegex(pattern))
	if err != nil {
		log.Trace().Err(err).
			Str("path", path).
			Str("pattern", pattern).
			Msg("os.id.metadata> failed to compile pattern")
		return false
	}
	return re.MatchString(path)
}

// Convert wildcard pattern to regex, or return exact match regex.
func patternToRegex(pattern string) string {
	if !strings.ContainsAny(pattern, "*?") {
		// No wildcards → Match exact string
		return "^" + regexp.QuoteMeta(pattern) + "$"
	}

	// Replace ** with .* (matches multiple path segments)
	pattern = strings.ReplaceAll(pattern, "**", ".*")

	// Replace * with [^/]+ (matches a single path segment)
	pattern = strings.ReplaceAll(pattern, "*", "[^/]+")

	// Ensure full match
	return pattern + "$"
}

// detectMultilineString checks if the data is a multiline string value rather than metadata we subpaths
func detectMultilineString(data string) bool {
	if !strings.Contains(data, "\n") {
		return false
	}

	prefix := data
	if len(data) > 50 {
		prefix = data[:50]
	}

	switch {
	case strings.Contains(prefix, "#!/bin/bash"):
		return true
	case strings.ContainsAny(prefix, "#!&+>"):
		return true
	case strings.Contains(prefix, "<!DOCTYPE") || strings.Contains(prefix, "<html"):
		return true
	case sshKeyPattern.MatchString(prefix):
		return true
	default:
		return false
	}
}
