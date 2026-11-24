// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"slices"
	"strings"

	observability "github.com/stackitcloud/stackit-sdk-go/services/observability/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Grafana hardening flags, alerting, and technical credentials of an
// Observability instance.

// grafanaAdminEnabled reads the admin-account flag from the instance detail.
// Only the flag is read; the detail's admin password stays behind.
func (r *mqlStackitObservabilityInstance) grafanaAdminEnabled() (bool, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return false, err
	}
	if d == nil {
		return nullBool(&r.GrafanaAdminEnabled)
	}
	inst, ok := d.GetInstanceOk()
	if !ok || inst == nil {
		return nullBool(&r.GrafanaAdminEnabled)
	}
	return inst.GetGrafanaAdminEnabled(), nil
}

// genericOauthFlag reads one optional flag of the Grafana configuration's
// generic OAuth provider. Nil when the configuration carries no provider or
// the provider does not report the flag.
func genericOauthFlag(g *observability.GrafanaConfigs, read func(*observability.GrafanaOauth) (*bool, bool)) *bool {
	if g == nil {
		return nil
	}
	oauth, ok := g.GetGenericOauthOk()
	if !ok || oauth == nil {
		return nil
	}
	return optBool(read(oauth))
}

func (r *mqlStackitObservabilityInstance) grafanaOauthField(
	read func(*observability.GrafanaOauth) (*bool, bool), field *plugin.TValue[bool],
) (bool, error) {
	g, err := r.fetchGrafana()
	if err != nil {
		return false, err
	}
	v := genericOauthFlag(g, read)
	if v == nil {
		return nullBool(field)
	}
	return *v, nil
}

func (r *mqlStackitObservabilityInstance) grafanaGenericOauthRoleAttributeStrict() (bool, error) {
	return r.grafanaOauthField((*observability.GrafanaOauth).GetRoleAttributeStrictOk, &r.GrafanaGenericOauthRoleAttributeStrict)
}

func (r *mqlStackitObservabilityInstance) grafanaGenericOauthUsePkce() (bool, error) {
	return r.grafanaOauthField((*observability.GrafanaOauth).GetUsePkceOk, &r.GrafanaGenericOauthUsePkce)
}

func (r *mqlStackitObservabilityInstance) alertReceivers() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListAlertConfigReceivers(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	receivers := resp.GetData()
	out := make([]any, 0, len(receivers))
	for i := range receivers {
		res, err := CreateResource(r.MqlRuntime, "stackit.observability.alertReceiver", alertReceiverArgs(r.Id.Data, &receivers[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// alertReceiverArgs maps an Alertmanager receiver. Webhook URLs, Opsgenie API
// keys, and SMTP credentials are deliberately not mapped: a webhook URL
// usually carries its own access token, so only its scheme is kept.
func alertReceiverArgs(instanceID string, rcv *observability.Receivers) map[string]*llx.RawData {
	kinds := []string{}
	addKind := func(k string) {
		if !slices.Contains(kinds, k) {
			kinds = append(kinds, k)
		}
	}
	emailTo := []string{}
	schemes := []string{}
	// sendResolved is true when any notifier reports true, false when every
	// notifier that reports the setting reports false, nil when none does.
	var sendResolved *bool
	noteResolved := func(v *bool, ok bool) {
		if !ok || v == nil {
			return
		}
		if sendResolved == nil || *v {
			b := *v
			sendResolved = &b
		}
	}

	emails := rcv.GetEmailConfigs()
	for i := range emails {
		addKind("email")
		if to := emails[i].GetTo(); to != "" {
			emailTo = append(emailTo, to)
		}
		noteResolved(emails[i].GetSendResolvedOk())
	}
	opsgenie := rcv.GetOpsgenieConfigs()
	for i := range opsgenie {
		addKind("opsgenie")
		noteResolved(opsgenie[i].GetSendResolvedOk())
	}
	hooks := rcv.GetWebHookConfigs()
	for i := range hooks {
		switch {
		case hooks[i].GetMsTeams():
			addKind("msTeams")
		case hooks[i].GetGoogleChat():
			addKind("googleChat")
		default:
			addKind("webhook")
		}
		if s := urlScheme(hooks[i].GetUrl()); s != "" {
			schemes = append(schemes, s)
		}
		noteResolved(hooks[i].GetSendResolvedOk())
	}

	return map[string]*llx.RawData{
		"__id":           llx.StringData(qualifiedId("stackit.observability.alertReceiver", instanceID, rcv.GetName())),
		"name":           llx.StringData(rcv.GetName()),
		"types":          strSliceData(kinds),
		"emailTo":        strSliceData(emailTo),
		"webhookSchemes": strSliceData(schemes),
		"sendResolved":   llx.BoolDataPtr(sendResolved),
	}
}

// urlScheme returns the lower-cased scheme of a URL, or "" when the URL does
// not parse or names none. Nothing else of the URL is kept.
func urlScheme(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}

// fetchAlertGroups reads the instance's alert groups once for the two count
// fields. The second result is false when the groups could not be read.
func (r *mqlStackitObservabilityInstance) fetchAlertGroups() ([]observability.AlertGroup, bool, error) {
	if r.alertGroupsFetched.Load() {
		return r.alertGroups, r.alertGroupsRead, nil
	}
	r.alertGroupsLock.Lock()
	defer r.alertGroupsLock.Unlock()
	if r.alertGroupsFetched.Load() {
		return r.alertGroups, r.alertGroupsRead, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, false, err
	}
	resp, err := client.DefaultAPI.ListAlertgroups(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.alertGroupsFetched.Store(true)
				return nil, false, nil
			}
			return nil, false, refusal(err)
		}
		return nil, false, err
	}
	r.alertGroups = resp.GetData()
	r.alertGroupsRead = true
	r.alertGroupsFetched.Store(true)
	return r.alertGroups, true, nil
}

// alertRuleTotal counts the rules across alert groups.
func alertRuleTotal(groups []observability.AlertGroup) int64 {
	var n int64
	for i := range groups {
		n += int64(len(groups[i].GetRules()))
	}
	return n
}

func (r *mqlStackitObservabilityInstance) alertGroupCount() (int64, error) {
	groups, ok, err := r.fetchAlertGroups()
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.AlertGroupCount)
	}
	return int64(len(groups)), nil
}

func (r *mqlStackitObservabilityInstance) alertRuleCount() (int64, error) {
	groups, ok, err := r.fetchAlertGroups()
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.AlertRuleCount)
	}
	return alertRuleTotal(groups), nil
}

// credentials lists the instance's technical credentials by id, name, and
// description only. The response's credentialsInfo map is not read.
func (r *mqlStackitObservabilityInstance) credentials() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListCredentials(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	creds := resp.GetCredentials()
	out := make([]any, 0, len(creds))
	for i := range creds {
		cr := &creds[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.observability.credential", map[string]*llx.RawData{
			"__id":        llx.StringData(qualifiedId("stackit.observability.credential", r.Id.Data, cr.GetId())),
			"id":          llx.StringData(cr.GetId()),
			"name":        llx.StringData(cr.GetName()),
			"description": llx.StringData(cr.GetDescription()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// observabilityInstanceFromList resolves an observability instance by id
// against the project's instance list, which is read once and shared by every
// caller. The field is null for an empty id and for an instance the list does
// not hold.
func observabilityInstanceFromList(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlStackitObservabilityInstance]) (*mqlStackitObservabilityInstance, error) {
	if id == "" {
		return markNull(field)
	}
	ns, err := makeNamespace(runtime, "stackit.observability")
	if err != nil {
		return nil, err
	}
	instances := ns.(*mqlStackitObservability).GetInstances()
	if instances.Error != nil {
		return nil, instances.Error
	}
	for _, i := range instances.Data {
		inst, ok := i.(*mqlStackitObservabilityInstance)
		if ok && inst.Id.Data == id {
			return inst, nil
		}
	}
	return markNull(field)
}
