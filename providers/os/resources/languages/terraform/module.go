// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package terraform

import (
	"net/url"
	"strings"

	"github.com/package-url/packageurl-go"
)

// PurlTypeModule identifies a Terraform module.
//
// Modules are their own type rather than a flavour of "terraform": a provider
// and a module may share a namespace and name while being different artifacts
// served by different registry endpoints (/v1/providers and /v1/modules). The
// obvious alternative, folding the target system in as a fourth path segment
// ("pkg:terraform/hashicorp/consul/aws"), does not survive a round trip —
// packageurl reads it back as namespace "hashicorp/consul", name "aws".
const PurlTypeModule = "terraform-module"

// ModuleSourceKind classifies a module `source` argument.
type ModuleSourceKind int

const (
	// ModuleSourceUnknown is a source shape this package does not inventory.
	ModuleSourceUnknown ModuleSourceKind = iota
	// ModuleSourceLocal is a path inside the calling configuration ("./x",
	// "../x"). Not a third-party dependency and deliberately not inventoried.
	ModuleSourceLocal
	// ModuleSourceRegistry is a module registry address,
	// <NAMESPACE>/<NAME>/<TARGET_SYSTEM> with an optional leading <HOST>.
	ModuleSourceRegistry
	// ModuleSourceVCS is a repository address: the git:: and hg:: forms and
	// the github.com / bitbucket.org shorthands.
	ModuleSourceVCS
	// ModuleSourceHTTP is an archive fetched over HTTP(S).
	ModuleSourceHTTP
)

// ModuleSource is a parsed module `source` argument.
type ModuleSource struct {
	// Kind is how the source is fetched.
	Kind ModuleSourceKind
	// Raw is the source exactly as written.
	Raw string
	// Host is the registry or repository host, empty when the source omits one.
	Host string
	// Namespace is the registry namespace, or the repository owner path.
	Namespace string
	// Name is the module name, or the repository name.
	Name string
	// TargetSystem is the registry address's third segment (e.g. "aws"). It is
	// part of a registry module's identity, not a qualifier of its content.
	TargetSystem string
	// Ref is the pinned revision from a VCS source's ?ref= argument.
	Ref string
	// Subdir is the "//path" component selecting a directory inside the source.
	Subdir string
	// VCS names the version control system for a ModuleSourceVCS, "git" or "hg".
	VCS string
}

// ClassifyModuleSource parses a module `source` argument.
//
// Terraform resolves a source by trying a fixed list of detectors in order;
// this mirrors the ones that can name a third-party artifact. Anything it does
// not recognise — s3::, gcs::, a bare archive path — comes back as
// ModuleSourceUnknown rather than being guessed at, because a wrong coordinate
// is worse than no coordinate.
func ClassifyModuleSource(source string) ModuleSource {
	m := ModuleSource{Raw: source}

	if source == "" {
		return m
	}

	// Local paths. Terraform requires the leading ./ or ../ precisely so that
	// a local path is never confused with a registry address.
	if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") ||
		source == "." || source == ".." {
		m.Kind = ModuleSourceLocal
		return m
	}

	body := source
	scheme := ""
	if idx := strings.Index(body, "::"); idx >= 0 {
		scheme = body[:idx]
		body = body[idx+2:]
	}

	// Strip the query first: ref and subdir both live outside the address.
	query := ""
	if idx := strings.Index(body, "?"); idx >= 0 {
		query = body[idx+1:]
		body = body[:idx]
	}
	if values, err := url.ParseQuery(query); err == nil {
		m.Ref = values.Get("ref")
	}

	// "//" after the host selects a subdirectory of the fetched source. The
	// scan starts past any URL scheme, otherwise the "//" of "https://" is
	// read as the separator and the whole address is taken as a subdirectory.
	searchFrom := 0
	if idx := strings.Index(body, "://"); idx >= 0 {
		searchFrom = idx + 3
	}
	if idx := strings.Index(body[searchFrom:], "//"); idx >= 0 {
		at := searchFrom + idx
		m.Subdir = body[at+2:]
		body = body[:at]
	}

	switch {
	case scheme == "git" || scheme == "hg":
		m.Kind = ModuleSourceVCS
		m.VCS = scheme
		m.Host, m.Namespace, m.Name = splitRepoAddress(body)
		return m
	case scheme != "":
		// s3::, gcs:: and anything else: no stable public coordinate.
		m.Kind = ModuleSourceUnknown
		return m
	}

	if strings.HasPrefix(body, "http://") || strings.HasPrefix(body, "https://") {
		m.Kind = ModuleSourceHTTP
		m.Host, m.Namespace, m.Name = splitRepoAddress(body)
		return m
	}

	// The two shorthands Terraform detects without a git:: prefix.
	if strings.HasPrefix(body, "github.com/") || strings.HasPrefix(body, "bitbucket.org/") {
		m.Kind = ModuleSourceVCS
		m.VCS = "git"
		m.Host, m.Namespace, m.Name = splitRepoAddress(body)
		return m
	}

	// Registry address: <NAMESPACE>/<NAME>/<TARGET_SYSTEM>, optionally with a
	// leading host. A host is recognised by a dot, the same rule providers use.
	parts := strings.Split(body, "/")
	if len(parts) > 0 && strings.Contains(parts[0], ".") {
		m.Host = parts[0]
		parts = parts[1:]
	}
	if len(parts) == 3 {
		m.Kind = ModuleSourceRegistry
		m.Namespace, m.Name, m.TargetSystem = parts[0], parts[1], parts[2]
		return m
	}

	return m
}

// splitRepoAddress splits a repository address into host, owner path and name.
// It accepts the URL forms and the SCP-like "git@host:owner/repo" form.
func splitRepoAddress(address string) (host, namespace, name string) {
	address = strings.TrimSuffix(address, "/")

	// Strip a URL scheme and any userinfo.
	if idx := strings.Index(address, "://"); idx >= 0 {
		address = address[idx+3:]
	}
	if idx := strings.Index(address, "@"); idx >= 0 {
		// SCP-like "git@host:owner/repo" uses ":" where a URL uses "/".
		rest := address[idx+1:]
		if colon := strings.Index(rest, ":"); colon >= 0 && !strings.Contains(rest[:colon], "/") {
			rest = rest[:colon] + "/" + rest[colon+1:]
		}
		address = rest
	}

	parts := strings.Split(address, "/")
	if len(parts) == 0 {
		return "", "", ""
	}
	host = parts[0]
	parts = parts[1:]
	if len(parts) == 0 {
		return host, "", ""
	}

	name = strings.TrimSuffix(parts[len(parts)-1], ".git")
	namespace = strings.Join(parts[:len(parts)-1], "/")
	return host, namespace, name
}

// NewModulePackageUrl builds the purl for a parsed module source. It returns an
// empty string for a source with no third-party identity — a local path, or a
// fetcher whose address names no stable artifact.
func NewModulePackageUrl(m ModuleSource, version string) string {
	switch m.Kind {
	case ModuleSourceRegistry:
		qualifiers := packageurl.Qualifiers{
			{Key: "target_system", Value: m.TargetSystem},
		}
		if m.Host != "" && m.Host != ModuleRegistryHost {
			qualifiers = append(qualifiers, packageurl.Qualifier{
				Key: "repository_url", Value: m.Host,
			})
		}
		return packageurl.NewPackageURL(
			PurlTypeModule, m.Namespace, m.Name, version, qualifiers, m.Subdir,
		).String()

	case ModuleSourceVCS:
		if m.Host == "" || m.Name == "" {
			return ""
		}
		// Not pkg:github, even for a github.com source: the SBOM pipeline
		// already reads that type as a GitHub Action, so a module filed under
		// it would be reported as one.
		return packageurl.NewPackageURL(
			packageurl.TypeGeneric,
			strings.Join([]string{m.Host, m.Namespace}, "/"),
			m.Name,
			m.Ref,
			packageurl.Qualifiers{{Key: "vcs_url", Value: VCSURL(m)}},
			m.Subdir,
		).String()

	case ModuleSourceHTTP:
		if m.Host == "" || m.Name == "" {
			return ""
		}
		return packageurl.NewPackageURL(
			packageurl.TypeGeneric,
			strings.Join([]string{m.Host, m.Namespace}, "/"),
			m.Name,
			"",
			packageurl.Qualifiers{{Key: "download_url", Value: m.Raw}},
			m.Subdir,
		).String()
	}

	return ""
}

// VCSURL is the repository URL for a VCS module source, in the purl-spec
// "vcs_url" form. The raw Terraform source is not used: it carries the "git::"
// fetcher prefix and the ?ref= argument, neither of which belongs in a
// repository URL, and both of which encode badly as a qualifier value.
func VCSURL(m ModuleSource) string {
	if m.Kind != ModuleSourceVCS || m.Host == "" || m.Name == "" {
		return ""
	}
	vcs := m.VCS
	if vcs == "" {
		vcs = "git"
	}
	path := m.Name
	if m.Namespace != "" {
		path = m.Namespace + "/" + m.Name
	}
	suffix := ""
	if vcs == "git" {
		suffix = ".git"
	}
	return vcs + "+https://" + m.Host + "/" + path + suffix
}

// ModuleRegistryHost is the public Terraform module registry.
const ModuleRegistryHost = "registry.terraform.io"

// ModuleName is the human-readable name reported for a module source.
func ModuleName(m ModuleSource) string {
	switch m.Kind {
	case ModuleSourceRegistry:
		return strings.Join([]string{m.Namespace, m.Name, m.TargetSystem}, "/")
	case ModuleSourceVCS, ModuleSourceHTTP:
		if m.Namespace == "" {
			return strings.Join([]string{m.Host, m.Name}, "/")
		}
		return strings.Join([]string{m.Host, m.Namespace, m.Name}, "/")
	}
	return ""
}
