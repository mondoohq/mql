// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jamf/connection"
	"go.mondoo.com/mql/types"
)

// jamfScopeEntities renders a list of scope entities into id/name dicts.
func jamfScopeEntities[T any](items []T, idName func(T) (any, string)) []any {
	out := make([]any, 0, len(items))
	for _, it := range items {
		id, name := idName(it)
		out = append(out, map[string]any{"id": id, "name": name})
	}
	return out
}

// jamfScopeEntitiesPtr is the pointer-slice variant; the Jamf policy scope
// uses pointer slices that are nil when empty.
func jamfScopeEntitiesPtr[T any](items *[]T, idName func(T) (any, string)) []any {
	if items == nil {
		return []any{}
	}
	return jamfScopeEntities(*items, idName)
}

// mqlJamfPolicyInternal caches the detail record. The list API returns only id
// and name, so the remaining fields are fetched once, on first access, via
// GetPolicyByID. detail is an atomic pointer so the lock-free fast path in
// fetchDetail can read it without racing the write under lock.
type mqlJamfPolicyInternal struct {
	detail atomic.Pointer[jamfpro.ResourcePolicy]
	lock   sync.Mutex
}

type mqlJamfPolicyPackageInternal struct {
	packageID string
}

type mqlJamfPolicyScriptInternal struct {
	scriptID string
}

func (r *mqlJamf) policies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	client := conn.Client

	list, err := client.GetPolicies()
	if err != nil {
		return nil, err
	}

	var res []any
	for _, item := range list.Policy {
		mqlItem, err := CreateResource(r.MqlRuntime, "jamf.policy", map[string]*llx.RawData{
			"id":   llx.StringData(strconv.Itoa(item.ID)),
			"name": llx.StringData(item.Name),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlItem)
	}

	return res, nil
}

func (p *mqlJamfPolicy) id() (string, error) {
	return "jamf.policy/" + p.Id.Data, nil
}

func (p *mqlJamfPolicy) fetchDetail() (*jamfpro.ResourcePolicy, error) {
	if d := p.detail.Load(); d != nil {
		return d, nil
	}

	p.lock.Lock()
	defer p.lock.Unlock()
	if d := p.detail.Load(); d != nil {
		return d, nil
	}

	conn := p.MqlRuntime.Connection.(*connection.JamfConnection)
	detail, err := conn.Client.GetPolicyByID(p.Id.Data)
	if err != nil {
		return nil, err
	}
	p.detail.Store(detail)
	return detail, nil
}

func (p *mqlJamfPolicy) enabled() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.General.Enabled, nil
}

func (p *mqlJamfPolicy) frequency() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	return d.General.Frequency, nil
}

func (p *mqlJamfPolicy) trigger() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	return d.General.Trigger, nil
}

func (p *mqlJamfPolicy) triggerCheckin() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.General.TriggerCheckin, nil
}

func (p *mqlJamfPolicy) triggerEnrollmentComplete() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.General.TriggerEnrollmentComplete, nil
}

func (p *mqlJamfPolicy) triggerLogin() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.General.TriggerLogin, nil
}

func (p *mqlJamfPolicy) triggerLogout() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.General.TriggerLogout, nil
}

func (p *mqlJamfPolicy) triggerNetworkStateChanged() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.General.TriggerNetworkStateChanged, nil
}

func (p *mqlJamfPolicy) triggerStartup() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.General.TriggerStartup, nil
}

func (p *mqlJamfPolicy) triggerOther() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	return d.General.TriggerOther, nil
}

func (p *mqlJamfPolicy) retryEvent() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	return d.General.RetryEvent, nil
}

func (p *mqlJamfPolicy) retryAttempts() (int64, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return 0, err
	}
	return int64(d.General.RetryAttempts), nil
}

func (p *mqlJamfPolicy) offline() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.General.Offline, nil
}

func (p *mqlJamfPolicy) targetDrive() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	return d.General.TargetDrive, nil
}

func (p *mqlJamfPolicy) networkRequirements() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	return d.General.NetworkRequirements, nil
}

func (p *mqlJamfPolicy) categoryId() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	if d.General.Category == nil {
		return "", nil
	}
	return strconv.Itoa(d.General.Category.ID), nil
}

func (p *mqlJamfPolicy) categoryName() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	if d.General.Category == nil {
		return "", nil
	}
	return d.General.Category.Name, nil
}

func (p *mqlJamfPolicy) siteName() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	if d.General.Site == nil {
		return "", nil
	}
	return d.General.Site.Name, nil
}

func (p *mqlJamfPolicy) selfServiceEnabled() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.SelfService.UseForSelfService, nil
}

func (p *mqlJamfPolicy) selfServiceDisplayName() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	return d.SelfService.SelfServiceDisplayName, nil
}

func (p *mqlJamfPolicy) selfServiceDescription() (string, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return "", err
	}
	return d.SelfService.SelfServiceDescription, nil
}

func (p *mqlJamfPolicy) scopeAllComputers() (bool, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.Scope.AllComputers, nil
}

func (p *mqlJamfPolicy) scope() (any, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return nil, err
	}
	scope := d.Scope

	computer := func(c jamfpro.PolicySubsetComputer) (any, string) { return int64(c.ID), c.Name }
	group := func(g jamfpro.PolicySubsetComputerGroup) (any, string) { return int64(g.ID), g.Name }
	building := func(b jamfpro.PolicySubsetBuilding) (any, string) { return int64(b.ID), b.Name }
	department := func(dp jamfpro.PolicySubsetDepartment) (any, string) { return int64(dp.ID), dp.Name }
	user := func(u jamfpro.PolicySubsetUser) (any, string) { return int64(u.ID), u.Name }
	userGroup := func(g jamfpro.PolicySubsetUserGroup) (any, string) { return g.ID, g.Name }
	networkSegment := func(n jamfpro.PolicySubsetNetworkSegment) (any, string) { return int64(n.ID), n.Name }

	result := map[string]any{
		"allComputers":   scope.AllComputers,
		"allJssUsers":    scope.AllJSSUsers,
		"computers":      jamfScopeEntitiesPtr(scope.Computers, computer),
		"computerGroups": jamfScopeEntitiesPtr(scope.ComputerGroups, group),
		"buildings":      jamfScopeEntitiesPtr(scope.Buildings, building),
		"departments":    jamfScopeEntitiesPtr(scope.Departments, department),
	}

	if scope.Limitations != nil {
		result["limitations"] = map[string]any{
			"users":           jamfScopeEntitiesPtr(scope.Limitations.Users, user),
			"userGroups":      jamfScopeEntitiesPtr(scope.Limitations.UserGroups, userGroup),
			"networkSegments": jamfScopeEntitiesPtr(scope.Limitations.NetworkSegments, networkSegment),
		}
	}

	if scope.Exclusions != nil {
		result["exclusions"] = map[string]any{
			"computers":       jamfScopeEntitiesPtr(scope.Exclusions.Computers, computer),
			"computerGroups":  jamfScopeEntitiesPtr(scope.Exclusions.ComputerGroups, group),
			"buildings":       jamfScopeEntitiesPtr(scope.Exclusions.Buildings, building),
			"departments":     jamfScopeEntitiesPtr(scope.Exclusions.Departments, department),
			"users":           jamfScopeEntitiesPtr(scope.Exclusions.Users, user),
			"userGroups":      jamfScopeEntitiesPtr(scope.Exclusions.UserGroups, userGroup),
			"networkSegments": jamfScopeEntitiesPtr(scope.Exclusions.NetworkSegments, networkSegment),
		}
	}

	return result, nil
}

func (p *mqlJamfPolicy) filesProcesses() (any, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return nil, err
	}
	fp := d.FilesProcesses
	return map[string]any{
		"searchByPath":         fp.SearchByPath,
		"deleteFile":           fp.DeleteFile,
		"locateFile":           fp.LocateFile,
		"updateLocateDatabase": fp.UpdateLocateDatabase,
		"spotlightSearch":      fp.SpotlightSearch,
		"searchForProcess":     fp.SearchForProcess,
		"killProcess":          fp.KillProcess,
		"runCommand":           fp.RunCommand,
	}, nil
}

func (p *mqlJamfPolicy) packages() ([]any, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return nil, err
	}

	var res []any
	for _, pkg := range d.PackageConfiguration.Packages {
		mqlPkg, err := CreateResource(p.MqlRuntime, "jamf.policy.package", map[string]*llx.RawData{
			"__id":              llx.StringData(fmt.Sprintf("%s/package/%d", p.Id.Data, pkg.ID)),
			"action":            llx.StringData(pkg.Action),
			"fillUserTemplate":  llx.BoolData(pkg.FillUserTemplate),
			"fillExistingUsers": llx.BoolData(pkg.FillExistingUsers),
			"updateAutorun":     llx.BoolData(pkg.UpdateAutorun),
		})
		if err != nil {
			return nil, err
		}
		mqlPkg.(*mqlJamfPolicyPackage).packageID = strconv.Itoa(pkg.ID)
		res = append(res, mqlPkg)
	}

	return res, nil
}

func (p *mqlJamfPolicy) scripts() ([]any, error) {
	d, err := p.fetchDetail()
	if err != nil {
		return nil, err
	}

	var res []any
	for _, sc := range d.Scripts {
		mqlScript, err := CreateResource(p.MqlRuntime, "jamf.policy.script", map[string]*llx.RawData{
			"__id":       llx.StringData(fmt.Sprintf("%s/script/%s", p.Id.Data, sc.ID)),
			"priority":   llx.StringData(sc.Priority),
			"parameters": llx.MapData(policyScriptParameters(sc), types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlScript.(*mqlJamfPolicyScript).scriptID = sc.ID
		res = append(res, mqlScript)
	}

	return res, nil
}

// policyScriptParameters collects the non-empty labeled parameters (parameter4
// through parameter11) a policy passes to a script.
func policyScriptParameters(s jamfpro.PolicySubsetScript) map[string]any {
	slots := map[string]string{
		"parameter4":  s.Parameter4,
		"parameter5":  s.Parameter5,
		"parameter6":  s.Parameter6,
		"parameter7":  s.Parameter7,
		"parameter8":  s.Parameter8,
		"parameter9":  s.Parameter9,
		"parameter10": s.Parameter10,
		"parameter11": s.Parameter11,
	}
	out := map[string]any{}
	for k, v := range slots {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

func (p *mqlJamfPolicyPackage) compute_package() (*mqlJamfPackage, error) {
	if p.packageID == "" || p.packageID == "0" {
		p.Package.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(p.MqlRuntime, "jamf.package", map[string]*llx.RawData{
		"id": llx.StringData(p.packageID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJamfPackage), nil
}

func (s *mqlJamfPolicyScript) script() (*mqlJamfScript, error) {
	if s.scriptID == "" || s.scriptID == "0" {
		s.Script.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(s.MqlRuntime, "jamf.script", map[string]*llx.RawData{
		"id": llx.StringData(s.scriptID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJamfScript), nil
}
