// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// This file models what a project publishes and depends on: who may overwrite
// its container image tags, how its Pages site is served and with which
// certificates, the authorities that sign its build attestations, and the
// packages it depends on. Rule ids, domains, and dependencies repeat across
// projects, so every resource here keys on projectScopedID.
//
// Private keys are never read: the Pages domain listing returns the
// certificate, not its key, and only the certificate's subject and expiry are
// modeled.

//
// Container registry tag protection rules
//

// containerRegistryTagProtectionRules lists the rules restricting who may push
// and delete image tags. The endpoint takes no options but still paginates, so
// the walk follows the next-page link the way the repository protection rules
// do.
func (p *mqlGitlabProject) containerRegistryTagProtectionRules() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	var all []*gitlab.ContainerRegistryTagProtectionRule
	var nextOpts []gitlab.RequestOptionFunc
	for {
		rules, resp, err := conn.Client().ContainerRegistryTagProtectionRules.ListContainerRegistryTagProtectionRules(projectID, nextOpts...)
		if err != nil {
			if err = gatedError(err); err != nil {
				return nil, err
			}
			return []any{}, nil
		}
		all = append(all, rules...)
		next, hasNext := gitlab.WithNext(resp)
		if !hasNext {
			break
		}
		nextOpts = []gitlab.RequestOptionFunc{next}
	}

	res := make([]any, 0, len(all))
	for _, r := range all {
		if r == nil {
			continue
		}
		rule, err := CreateResource(p.MqlRuntime, "gitlab.project.containerRegistryTagProtectionRule", map[string]*llx.RawData{
			"__id":                        llx.StringData(projectScopedID("gitlab.project.containerRegistryTagProtectionRule", projectID, strconv.FormatInt(r.ID, 10))),
			"id":                          llx.IntData(r.ID),
			"tagNamePattern":              llx.StringData(r.TagNamePattern),
			"minimumAccessLevelForPush":   llx.StringData(string(r.MinimumAccessLevelForPush)),
			"minimumAccessLevelForDelete": llx.StringData(string(r.MinimumAccessLevelForDelete)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, rule)
	}
	return res, nil
}

//
// GitLab Pages
//

// pagesSettings reads how the Pages site is served. GitLab answers 404 for a
// project without a Pages site, which reads as null.
func (p *mqlGitlabProject) pagesSettings() (*mqlGitlabProjectPagesSetting, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)

	pages, _, err := conn.Client().Pages.GetPages(p.Id.Data)
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		pages = nil
	}
	if pages == nil {
		p.PagesSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(p.MqlRuntime, "gitlab.project.pagesSetting", map[string]*llx.RawData{
		"__id":                  llx.StringData(projectScopedID("gitlab.project.pagesSetting", p.Id.Data)),
		"url":                   llx.StringData(pages.URL),
		"forceHttps":            llx.BoolData(pages.ForceHTTPS),
		"isUniqueDomainEnabled": llx.BoolData(pages.IsUniqueDomainEnabled),
		"primaryDomain":         llx.StringData(pages.PrimaryDomain),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabProjectPagesSetting), nil
}

// pagesDomainCertificate returns the certificate fields of a Pages domain, all
// null when the domain serves no certificate. The SDK decodes an absent
// certificate into a zero struct, which would otherwise read as a certificate
// that has not expired.
func pagesDomainCertificate(cert gitlab.PagesDomainCertificate) (subject, expiresAt, expired *llx.RawData) {
	if cert.Subject == "" && cert.Expiration == nil && cert.Certificate == "" {
		return llx.NilData, llx.NilData, llx.NilData
	}
	return llx.StringData(cert.Subject), llx.TimeDataPtr(cert.Expiration), llx.BoolData(cert.Expired)
}

// pagesDomains lists the custom domains serving the project's Pages site.
func (p *mqlGitlabProject) pagesDomains() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.PagesDomain, *gitlab.Response, error) {
		return conn.Client().PagesDomains.ListPagesDomains(projectID, &gitlab.ListPagesDomainsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, d := range all {
		if d == nil {
			continue
		}
		subject, expiresAt, expired := pagesDomainCertificate(d.Certificate)
		domain, err := CreateResource(p.MqlRuntime, "gitlab.project.pagesDomain", map[string]*llx.RawData{
			"__id":                 llx.StringData(projectScopedID("gitlab.project.pagesDomain", projectID, d.Domain)),
			"domain":               llx.StringData(d.Domain),
			"url":                  llx.StringData(d.URL),
			"verified":             llx.BoolData(d.Verified),
			"autoSslEnabled":       llx.BoolData(d.AutoSslEnabled),
			"enabledUntil":         llx.TimeDataPtr(d.EnabledUntil),
			"certificateSubject":   subject,
			"certificateExpiresAt": expiresAt,
			"certificateExpired":   expired,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, domain)
	}
	return res, nil
}

//
// Attestation signing certificates
//

// attestationSigningCertificates lists the certificate authorities that sign
// the project's build attestations.
func (p *mqlGitlabProject) attestationSigningCertificates() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.SigningCertificate, *gitlab.Response, error) {
		return conn.Client().Attestations.ListSigningCertificates(projectID, &gitlab.ListSigningCertificatesOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, c := range all {
		if c == nil {
			continue
		}
		cert, err := CreateResource(p.MqlRuntime, "gitlab.project.attestationSigningCertificate", map[string]*llx.RawData{
			"__id":      llx.StringData(projectScopedID("gitlab.project.attestationSigningCertificate", projectID, strconv.FormatInt(c.ID, 10))),
			"id":        llx.IntData(c.ID),
			"active":    llx.BoolData(c.Active),
			"expiresAt": llx.TimeDataPtr(c.ExpiresAt),
			"createdAt": llx.TimeDataPtr(c.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, cert)
	}
	return res, nil
}

//
// Dependencies
//

// dependencies lists the packages dependency scanning found on the default
// branch. Ultimate only; other tiers answer 404 or 403. A large project can
// list thousands, so this is only read when queried.
func (p *mqlGitlabProject) dependencies() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.Dependency, *gitlab.Response, error) {
		return conn.Client().Dependencies.ListProjectDependencies(projectID, &gitlab.ListProjectDependenciesOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabLargePage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, d := range all {
		if d == nil {
			continue
		}
		depID := dependencyID(projectID, d)

		vulns := make([]any, 0, len(d.Vulnerabilities))
		for _, v := range d.Vulnerabilities {
			if v == nil {
				continue
			}
			vuln, err := CreateResource(p.MqlRuntime, "gitlab.project.dependency.vulnerability", map[string]*llx.RawData{
				"__id":     llx.StringData(depID + "/vulnerability/" + strconv.FormatInt(v.ID, 10)),
				"id":       llx.IntData(v.ID),
				"name":     llx.StringData(v.Name),
				"severity": llx.StringData(v.Severity),
				"url":      llx.StringData(v.URL),
			})
			if err != nil {
				return nil, err
			}
			vuln.(*mqlGitlabProjectDependencyVulnerability).project = p
			vulns = append(vulns, vuln)
		}

		dep, err := CreateResource(p.MqlRuntime, "gitlab.project.dependency", map[string]*llx.RawData{
			"__id":               llx.StringData(depID),
			"name":               llx.StringData(d.Name),
			"version":            llx.StringData(d.Version),
			"packageManager":     llx.StringData(string(d.PackageManager)),
			"dependencyFilePath": llx.StringData(d.DependencyFilePath),
			"licenses":           llx.ArrayData(dependencyLicenseNames(d.Licenses), types.String),
			"vulnerabilities":    llx.ArrayData(vulns, types.Resource("gitlab.project.dependency.vulnerability")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, dep)
	}
	return res, nil
}

// dependencyID keys a dependency on everything that identifies it in the
// listing. The API assigns dependencies no id, and the same package can be
// declared at different versions or in several files of one project.
func dependencyID(projectID int64, d *gitlab.Dependency) string {
	return projectScopedID("gitlab.project.dependency", projectID,
		string(d.PackageManager), d.DependencyFilePath, d.Name, d.Version)
}

// dependencyLicenseNames returns the license names of a dependency, skipping
// empty entries.
func dependencyLicenseNames(licenses []*gitlab.DependencyLicense) []any {
	out := make([]any, 0, len(licenses))
	for _, l := range licenses {
		if l == nil || l.Name == "" {
			continue
		}
		out = append(out, l.Name)
	}
	return out
}

type mqlGitlabProjectDependencyVulnerabilityInternal struct {
	project *mqlGitlabProject
}

// vulnerabilityGID returns the GraphQL global id GitLab gives the vulnerability
// with the given REST id.
func vulnerabilityGID(id int64) string {
	return "gid://gitlab/Vulnerability/" + strconv.FormatInt(id, 10)
}

// finding resolves the vulnerability through the project's vulnerability list,
// which is read once per project however many dependencies refer to it.
func (v *mqlGitlabProjectDependencyVulnerability) finding() (*mqlGitlabProjectVulnerability, error) {
	if v.project == nil || v.Id.Data <= 0 {
		v.Finding.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	list := v.project.GetVulnerabilities()
	if list.Error != nil {
		return nil, list.Error
	}
	want := vulnerabilityGID(v.Id.Data)
	for _, r := range list.Data {
		found, ok := r.(*mqlGitlabProjectVulnerability)
		if ok && found.Id.Data == want {
			return found, nil
		}
	}
	v.Finding.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
