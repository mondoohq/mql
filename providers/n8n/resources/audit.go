// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sort"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/n8n/connection"
	"go.mondoo.com/mql/types"
)

type mqlN8nAuditInternal struct {
	// raw is the decoded audit, kept for instanceSettings so the instance
	// computes the audit once per scan.
	raw []connection.AuditReport
}

type mqlN8nAuditSectionInternal struct {
	workflowIDs   []string
	credentialIDs []string
}

func (r *mqlN8nAudit) id() (string, error) {
	return "n8n.audit", nil
}

func (r *mqlN8nAudit) reports() ([]any, error) {
	reports, err := n8nConnection(r.MqlRuntime).Client().Audit(context.Background())
	if err != nil {
		return nil, err
	}
	r.raw = reports
	out := make([]any, 0, len(reports))
	for _, rep := range reports {
		sections := make([]any, 0, len(rep.Sections))
		for i, s := range rep.Sections {
			section, err := newAuditSection(r, rep.Risk, i, s)
			if err != nil {
				return nil, err
			}
			sections = append(sections, section)
		}
		res, err := CreateResource(r.MqlRuntime, ResourceN8nAuditReport, map[string]*llx.RawData{
			"__id":     llx.StringData("n8n.audit/" + rep.Risk),
			"risk":     llx.StringData(rep.Risk),
			"sections": llx.ArrayData(sections, types.Resource(ResourceN8nAuditSection)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newAuditSection(r *mqlN8nAudit, risk string, idx int, s connection.AuditSection) (*mqlN8nAuditSection, error) {
	locations := make([]any, 0, len(s.Locations))
	for _, l := range s.Locations {
		locations = append(locations, l)
	}
	var settings any
	if s.Settings != nil {
		settings = s.Settings
	}
	res, err := CreateResource(r.MqlRuntime, ResourceN8nAuditSection, map[string]*llx.RawData{
		// Titles are unique within a report today, but nothing guarantees it,
		// so the position keeps two same-titled findings apart.
		"__id":           llx.StringData("n8n.audit/" + risk + "/" + strconv.Itoa(idx) + "/" + s.Title),
		"risk":           llx.StringData(risk),
		"title":          llx.StringData(s.Title),
		"description":    llx.StringData(s.Description),
		"recommendation": llx.StringData(s.Recommendation),
		"locations":      llx.ArrayData(locations, types.Dict),
		"settings":       llx.DictData(settings),
	})
	if err != nil {
		return nil, err
	}
	section := res.(*mqlN8nAuditSection)
	section.workflowIDs, section.credentialIDs = auditLocationIDs(s.Locations)
	return section, nil
}

// auditLocationIDs reads the workflows and credentials a finding's locations
// name: `node` locations carry a workflowId, `credential` locations an id.
// Both lists are sorted and free of duplicates, since a finding lists one
// location per node and a workflow often has several.
func auditLocationIDs(locations []map[string]any) (workflowIDs []string, credentialIDs []string) {
	wf := map[string]struct{}{}
	cr := map[string]struct{}{}
	for _, l := range locations {
		kind, _ := l["kind"].(string)
		switch kind {
		case "node":
			if id, ok := l["workflowId"].(string); ok && id != "" {
				wf[id] = struct{}{}
			}
		case "credential":
			if id, ok := l["id"].(string); ok && id != "" {
				cr[id] = struct{}{}
			}
		}
	}
	return sortedKeys(wf), sortedKeys(cr)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (r *mqlN8n) instanceSettings() (*mqlN8nSecuritySettings, error) {
	audit, err := r.securityAudit()
	if err != nil {
		return nil, err
	}
	// Reading reports runs the audit once; the decoded result stays on the
	// audit resource.
	if reports := audit.GetReports(); reports.Error != nil {
		return nil, reports.Error
	}
	s, ok := connection.InstanceSettingsFrom(audit.raw)
	if !ok {
		r.InstanceSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, ResourceN8nSecuritySettings, map[string]*llx.RawData{
		"communityPackagesEnabled":    llx.BoolDataPtr(s.CommunityPackagesEnabled),
		"publicApiEnabled":            llx.BoolDataPtr(s.PublicAPIEnabled),
		"templatesEnabled":            llx.BoolDataPtr(s.TemplatesEnabled),
		"versionNotificationsEnabled": llx.BoolDataPtr(s.VersionNotificationsEnabled),
		"diagnosticsEnabled":          llx.BoolDataPtr(s.DiagnosticsEnabled),
		"excludedNodes":               stringArray(s.ExcludedNodes),
		"includedNodes":               stringArray(s.IncludedNodes),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlN8nSecuritySettings), nil
}

func (r *mqlN8nSecuritySettings) id() (string, error) {
	return "n8n.securitySettings", nil
}

func (r *mqlN8nAuditSection) workflows() ([]any, error) {
	index, err := workflowsByID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return pick(index, r.workflowIDs), nil
}

func (r *mqlN8nAuditSection) credentials() ([]any, error) {
	index, err := credentialsByID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return pick(index, r.credentialIDs), nil
}
