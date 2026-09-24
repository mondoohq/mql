// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"slices"
	"sort"

	albwaf "github.com/stackitcloud/stackit-sdk-go/services/albwaf/v1betaapi"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlStackitAlbCustomRuleInternal struct {
	// cacheConditions holds the rule's match conditions, captured when the
	// rule is built from its group so conditions() can expose them as typed
	// sub-resources without another API call. cacheIdBase is the rule's own
	// cache key, used to key the condition sub-resources.
	cacheConditions []albwaf.Condition
	cacheIdBase     string
}

type mqlStackitAlbManagedRuleSetInternal struct {
	// cacheGroups holds the rule set's groups, captured during init so rules()
	// need not re-fetch the set. A nil pointer means "not yet fetched".
	cacheGroups *map[string]albwaf.MRSRuleGroup
	// cacheUsage holds the names of the WAF configurations binding this rule
	// set, from the same response. A nil pointer means "not yet fetched".
	cacheUsage *[]string
}

type mqlStackitAlbCustomRuleGroupInternal struct {
	// cacheRules holds the group's rules, captured during init so rules() need
	// not re-fetch the group. A nil pointer means "not yet fetched".
	cacheRules *[]albwaf.GetCustomRule
	// cacheUsage holds the names of the WAF configurations binding this
	// group, from the same response. A nil pointer means "not yet fetched".
	cacheUsage *[]string
}

type mqlStackitAlbWafInternal struct {
	// cacheUsageLoadBalancers holds the names of the application load
	// balancers whose listeners enforce this WAF, from the list or get
	// response the WAF was built from.
	cacheUsageLoadBalancers []string
}

// wafUsageLoadBalancers collects the load balancer names out of a WAF's
// usage block, deduplicated and sorted. Empty when nothing enforces the WAF.
func wafUsageLoadBalancers(u *albwaf.WAFUsage) []string {
	if u == nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, item := range u.GetItems() {
		if name := item.GetLoadBalancerName(); name != "" {
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// wafRefs resolves WAF configuration names into resources, skipping names
// that no longer resolve so one deleted WAF does not fail the list.
func wafRefs(runtime *plugin.Runtime, names []string) ([]any, error) {
	return refsByKey(runtime, "stackit.alb.waf", "name", names)
}

// ------------------------- WAF configurations -------------------------

func (r *mqlStackit) albWafs() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.AlbWaf()
	if err != nil {
		return nil, err
	}
	out := []any{}
	pageId := ""
	for {
		req := client.DefaultAPI.ListWAF(bgctx(), c.ProjectID(), c.Region())
		if pageId != "" {
			req = req.PageId(pageId)
		}
		resp, err := req.Execute()
		if err != nil {
			if isAccessDenied(err) || isNotFound(err) {
				return []any{}, nil
			}
			return nil, err
		}
		items, _ := resp.GetItemsOk()
		for i := range items {
			res, err := buildAlbWaf(r.MqlRuntime, &items[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		next, ok := resp.GetNextPageIdOk()
		if !ok || next == nil || *next == "" {
			break
		}
		pageId = *next
	}
	return out, nil
}

func buildAlbWaf(runtime *plugin.Runtime, w *albwaf.GetWAFResponse) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"name":                llx.StringData(w.GetName()),
		"managedRuleSetName":  llx.StringData(w.GetManagedRuleSetName()),
		"customRuleGroupName": llx.StringData(w.GetCustomRuleGroupName()),
		"labels":              labelData(w.GetLabels()),
	}
	res, err := CreateResource(runtime, "stackit.alb.waf", args)
	if err != nil {
		return nil, err
	}
	if usage, ok := w.GetUsageOk(); ok {
		res.(*mqlStackitAlbWaf).cacheUsageLoadBalancers = wafUsageLoadBalancers(usage)
	}
	return res, nil
}

func (r *mqlStackitAlbWaf) id() (string, error) {
	return "stackit.alb.waf/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Name.Data, nil
}

// loadBalancers resolves the application load balancers whose listeners
// enforce this WAF, from the usage block on the WAF response. Empty for a WAF
// that is configured but attached to nothing. A balancer that no longer
// resolves is skipped rather than failing the list.
func (r *mqlStackitAlbWaf) loadBalancers() ([]any, error) {
	return refsByKey(r.MqlRuntime, "stackit.alb.loadBalancer", "name", r.cacheUsageLoadBalancers)
}

func initStackitAlbWaf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, ok := idArg(args, "name")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.AlbWaf()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetWAF(bgctx(), c.ProjectID(), c.Region(), name).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildAlbWaf(runtime, resp)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlStackitAlbWaf) managedRuleSet() (*mqlStackitAlbManagedRuleSet, error) {
	if r.ManagedRuleSetName.Data == "" {
		return markNull[mqlStackitAlbManagedRuleSet](&r.ManagedRuleSet)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.alb.managedRuleSet", map[string]*llx.RawData{
		"name": llx.StringData(r.ManagedRuleSetName.Data),
	})
	if err != nil {
		// Degrade the auto-traversal from the parent WAF: a token that can list
		// WAFs but lacks GetManagedRuleSet, or a set that was deleted (404),
		// should read as null rather than fail the whole query.
		if isAccessDenied(err) || isNotFound(err) {
			return markNull[mqlStackitAlbManagedRuleSet](&r.ManagedRuleSet)
		}
		return nil, err
	}
	return res.(*mqlStackitAlbManagedRuleSet), nil
}

func (r *mqlStackitAlbWaf) customRuleGroup() (*mqlStackitAlbCustomRuleGroup, error) {
	if r.CustomRuleGroupName.Data == "" {
		return markNull[mqlStackitAlbCustomRuleGroup](&r.CustomRuleGroup)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.alb.customRuleGroup", map[string]*llx.RawData{
		"name": llx.StringData(r.CustomRuleGroupName.Data),
	})
	if err != nil {
		// Degrade the auto-traversal from the parent WAF: a token that can list
		// WAFs but lacks GetCustomRuleGroup, or a group that was deleted (404),
		// should read as null rather than fail the whole query.
		if isAccessDenied(err) || isNotFound(err) {
			return markNull[mqlStackitAlbCustomRuleGroup](&r.CustomRuleGroup)
		}
		return nil, err
	}
	return res.(*mqlStackitAlbCustomRuleGroup), nil
}

// wafs resolves the WAF configurations referenced by the load balancer's
// listeners (via each listener's wafConfigName), deduplicated.
func (r *mqlStackitAlbLoadBalancer) wafs() ([]any, error) {
	seen := map[string]struct{}{}
	names := []string{}
	for _, raw := range r.Listeners.Data {
		listener, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// "wafConfigName" is the SDK's json key for the WAF a listener
		// references (alb.Listener.WafConfigName); listeners without a WAF omit
		// it, so a missing key just means "no WAF on this listener".
		name, ok := listener["wafConfigName"].(string)
		if !ok || name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return wafRefs(r.MqlRuntime, names)
}

// ------------------------- managed rule sets -------------------------

func (r *mqlStackitAlbManagedRuleSet) id() (string, error) {
	return "stackit.alb.managedRuleSet/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Name.Data, nil
}

func initStackitAlbManagedRuleSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, ok := idArg(args, "name")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.AlbWaf()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetManagedRuleSet(bgctx(), c.ProjectID(), c.Region(), name).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := CreateResource(runtime, "stackit.alb.managedRuleSet", map[string]*llx.RawData{
		"name":    llx.StringData(resp.GetName()),
		"type":    llx.StringData(string(resp.GetType())),
		"version": llx.StringData(resp.GetVersion()),
	})
	if err != nil {
		return nil, nil, err
	}
	// Keep the groups and usage from this call so rules() and wafs() don't
	// re-fetch the set.
	groups := resp.GetGroups()
	set := res.(*mqlStackitAlbManagedRuleSet)
	set.cacheGroups = &groups
	usage := usageNames(usageItems(resp.GetUsageOk()))
	set.cacheUsage = &usage
	return nil, res, nil
}

// usageItems unwraps a rule set's or rule group's usage block into its item
// list, nil when the response omitted the block. The SDK's usage getters have
// pointer receivers and tolerate a nil receiver, so the ok flag is what
// distinguishes "no usage reported" from an empty list.
func usageItems[T interface{ GetItems() []string }](u T, ok bool) []string {
	if !ok {
		return nil
	}
	return u.GetItems()
}

// usageNames copies a usage item list into a sorted, deduplicated name list.
func usageNames(items []string) []string {
	seen := map[string]struct{}{}
	for _, n := range items {
		if n != "" {
			seen[n] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// wafs resolves the WAF configurations that bind this managed rule set, from
// the usage block on the rule-set response. Empty for a rule set nothing
// references.
func (r *mqlStackitAlbManagedRuleSet) wafs() ([]any, error) {
	if r.cacheUsage == nil {
		c := conn(r.MqlRuntime)
		client, err := c.AlbWaf()
		if err != nil {
			return nil, err
		}
		resp, err := client.DefaultAPI.GetManagedRuleSet(bgctx(), c.ProjectID(), c.Region(), r.Name.Data).Execute()
		if err != nil {
			if isAccessDenied(err) || isNotFound(err) {
				return []any{}, nil
			}
			return nil, err
		}
		usage := usageNames(usageItems(resp.GetUsageOk()))
		r.cacheUsage = &usage
	}
	return wafRefs(r.MqlRuntime, *r.cacheUsage)
}

// groups returns the rule set's groups, using the copy captured during init
// when available and fetching the set otherwise.
func (r *mqlStackitAlbManagedRuleSet) groups() (map[string]albwaf.MRSRuleGroup, error) {
	if r.cacheGroups != nil {
		return *r.cacheGroups, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.AlbWaf()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetManagedRuleSet(bgctx(), c.ProjectID(), c.Region(), r.Name.Data).Execute()
	if err != nil {
		if isAccessDenied(err) || isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	groups := resp.GetGroups()
	r.cacheGroups = &groups
	return groups, nil
}

// rules flattens the managed rule set's groups into individual rules,
// each carrying its group name and mode.
func (r *mqlStackitAlbManagedRuleSet) rules() ([]any, error) {
	c := conn(r.MqlRuntime)
	groups, err := r.groups()
	if err != nil {
		return nil, err
	}
	out := []any{}
	// Iterate groups and rules in sorted order for deterministic output.
	for _, groupName := range sortedKeys(groups) {
		group := groups[groupName]
		rules := group.GetRules()
		for _, ruleName := range sortedKeys(rules) {
			rule := rules[ruleName]
			res, err := CreateResource(r.MqlRuntime, "stackit.alb.managedRule", map[string]*llx.RawData{
				"__id":        llx.StringData("stackit.alb.managedRule/" + c.ProjectID() + "/" + r.Name.Data + "/" + groupName + "/" + ruleName),
				"name":        llx.StringData(ruleName),
				"groupName":   llx.StringData(groupName),
				"mode":        llx.StringData(string(rule.GetMode())),
				"severity":    llx.StringData(rule.GetSeverity()),
				"description": llx.StringData(rule.GetDescription()),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil
}

// ------------------------- custom rule groups -------------------------

func (r *mqlStackitAlbCustomRuleGroup) id() (string, error) {
	return "stackit.alb.customRuleGroup/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Name.Data, nil
}

func initStackitAlbCustomRuleGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, ok := idArg(args, "name")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.AlbWaf()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetCustomRuleGroup(bgctx(), c.ProjectID(), c.Region(), name).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := CreateResource(runtime, "stackit.alb.customRuleGroup", map[string]*llx.RawData{
		"name": llx.StringData(resp.GetName()),
	})
	if err != nil {
		return nil, nil, err
	}
	// Keep the rules and usage from this call so rules() and wafs() don't
	// re-fetch the group.
	rules := resp.GetRules()
	group := res.(*mqlStackitAlbCustomRuleGroup)
	group.cacheRules = &rules
	usage := usageNames(usageItems(resp.GetUsageOk()))
	group.cacheUsage = &usage
	return nil, res, nil
}

// wafs resolves the WAF configurations that bind this custom rule group, from
// the usage block on the group response. Empty for a group nothing
// references.
func (r *mqlStackitAlbCustomRuleGroup) wafs() ([]any, error) {
	if r.cacheUsage == nil {
		c := conn(r.MqlRuntime)
		client, err := c.AlbWaf()
		if err != nil {
			return nil, err
		}
		resp, err := client.DefaultAPI.GetCustomRuleGroup(bgctx(), c.ProjectID(), c.Region(), r.Name.Data).Execute()
		if err != nil {
			if isAccessDenied(err) || isNotFound(err) {
				return []any{}, nil
			}
			return nil, err
		}
		usage := usageNames(usageItems(resp.GetUsageOk()))
		r.cacheUsage = &usage
	}
	return wafRefs(r.MqlRuntime, *r.cacheUsage)
}

// customRules returns the group's rules, using the copy captured during init
// when available and fetching the group otherwise.
func (r *mqlStackitAlbCustomRuleGroup) customRules() ([]albwaf.GetCustomRule, error) {
	if r.cacheRules != nil {
		return *r.cacheRules, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.AlbWaf()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetCustomRuleGroup(bgctx(), c.ProjectID(), c.Region(), r.Name.Data).Execute()
	if err != nil {
		if isAccessDenied(err) || isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	rules := resp.GetRules()
	r.cacheRules = &rules
	return rules, nil
}

func (r *mqlStackitAlbCustomRuleGroup) rules() ([]any, error) {
	c := conn(r.MqlRuntime)
	rules, err := r.customRules()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rules))
	for i := range rules {
		rule := rules[i]
		var (
			action   string
			logMatch bool
			logMsg   string
			severity string
		)
		if b, ok := rule.GetBehaviourOk(); ok && b != nil {
			action = string(b.GetAction())
			logMatch = b.GetLog()
			logMsg = b.GetLogMsg()
			severity = string(b.GetSeverity())
		}
		idBase := fmt.Sprintf("stackit.alb.customRule/%s/%s/%d", c.ProjectID(), r.Name.Data, rule.GetId())
		res, err := CreateResource(r.MqlRuntime, "stackit.alb.customRule", map[string]*llx.RawData{
			"__id":        llx.StringData(idBase),
			"id":          llx.IntData(int64(rule.GetId())),
			"description": llx.StringData(rule.GetDescription()),
			"action":      llx.StringData(action),
			"log":         llx.BoolData(logMatch),
			"logMsg":      llx.StringData(logMsg),
			"severity":    llx.StringData(severity),
		})
		if err != nil {
			return nil, err
		}
		cr := res.(*mqlStackitAlbCustomRule)
		cr.cacheConditions = rule.GetConditions()
		cr.cacheIdBase = idBase
		out = append(out, res)
	}
	return out, nil
}

// conditions exposes the rule's match conditions as typed sub-resources,
// captured when the rule was built from its group.
func (r *mqlStackitAlbCustomRule) conditions() ([]any, error) {
	out := make([]any, 0, len(r.cacheConditions))
	for i := range r.cacheConditions {
		cond := r.cacheConditions[i]
		var variableType, variableValue, operatorType, operatorValue string
		if v, ok := cond.GetVariableOk(); ok && v != nil {
			variableType = string(v.GetType())
			variableValue = v.GetValue()
		}
		if o, ok := cond.GetOperatorOk(); ok && o != nil {
			operatorType = string(o.GetType())
			operatorValue = o.GetValue()
		}
		transforms := make([]string, 0, len(cond.GetTransformations()))
		for _, t := range cond.GetTransformations() {
			transforms = append(transforms, string(t))
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.alb.customRuleCondition", map[string]*llx.RawData{
			"__id":            llx.StringData(fmt.Sprintf("%s/condition/%d", r.cacheIdBase, i)),
			"variableType":    llx.StringData(variableType),
			"variableValue":   llx.StringData(variableValue),
			"operatorType":    llx.StringData(operatorType),
			"operatorValue":   llx.StringData(operatorValue),
			"transformations": strSliceData(transforms),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// sortedKeys returns the keys of a map in sorted order for deterministic
// iteration.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
