// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"sync"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/workers"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

type mqlCloudflareZoneWorkerRouteInternal struct {
	cacheAccountID  string
	cacheScriptName string
}

func (c *mqlCloudflareZoneWorkerRoute) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// workerRoutes lists the URL patterns that put a Workers script in front of
// requests to the zone.
func (c *mqlCloudflareZone) workerRoutes() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	// The route names a script, but scripts live on the account, so carry the
	// owning account through to the worker() accessor.
	accountID := ""
	if acc := c.GetAccount(); acc.Error == nil && acc.Data != nil {
		accountID = acc.Data.Id.Data
	}

	result := []any{}
	iter := conn.Cf.Workers.Routes.ListAutoPaging(context.TODO(), workers.RouteListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.workerRoute", map[string]*llx.RawData{
			"__id":       llx.StringData("cloudflare.zone.workerRoute@" + c.Id.Data + "/" + rec.ID),
			"id":         llx.StringData(rec.ID),
			"pattern":    llx.StringData(rec.Pattern),
			"scriptName": llx.StringData(rec.Script),
		})
		if err != nil {
			return nil, err
		}

		route := res.(*mqlCloudflareZoneWorkerRoute)
		route.cacheAccountID = accountID
		route.cacheScriptName = rec.Script

		result = append(result, route)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

// worker resolves the script the route runs, against the account's already
// fetched script list rather than a per-route lookup.
//
// A route that names no script, or names one absent from the list, reports null:
// the pattern still matches but there is nothing behind it.
func (c *mqlCloudflareZoneWorkerRoute) worker() (*mqlCloudflareWorkersWorker, error) {
	if c.cacheScriptName == "" || c.cacheAccountID == "" {
		c.Worker.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	acctWorkers, err := newWorkers(c.MqlRuntime, c.cacheAccountID)
	if err != nil {
		return nil, err
	}

	list := acctWorkers.GetWorkers()
	if list.Error != nil {
		// A failure to read the script list is not evidence that the route
		// points at nothing, so it surfaces rather than reporting null.
		return nil, list.Error
	}

	for _, w := range list.Data {
		worker, ok := w.(*mqlCloudflareWorkersWorker)
		if ok && worker.Id.Data == c.cacheScriptName {
			return worker, nil
		}
	}

	c.Worker.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

type mqlCloudflareWorkersWorkerInternal struct {
	accountID string

	settingsLock    sync.Mutex
	settingsFetched bool
	settingsOK      bool
	cacheSettings   *workers.ScriptScriptAndVersionSettingGetResponse
	settingsErr     error
}

// fetchSettings reads the Worker's settings once and shares the result across
// bindings(), tailConsumers() and observabilityEnabled(), so querying all three
// costs one API call rather than three.
//
// The `ok` return is false when the settings could not be read at all; callers
// must not read that as "this Worker has no bindings".
func (c *mqlCloudflareWorkersWorker) fetchSettings() (ok bool, settings *workers.ScriptScriptAndVersionSettingGetResponse, err error) {
	if c.settingsFetched {
		return c.settingsOK, c.cacheSettings, c.settingsErr
	}
	c.settingsLock.Lock()
	defer c.settingsLock.Unlock()
	if c.settingsFetched {
		return c.settingsOK, c.cacheSettings, c.settingsErr
	}
	c.settingsFetched = true

	if c.accountID == "" {
		c.settingsErr = errNoAccountBound
		return false, nil, c.settingsErr
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	resp, rerr := conn.Cf.Workers.Scripts.ScriptAndVersionSettings.Get(context.TODO(), c.Id.Data,
		workers.ScriptScriptAndVersionSettingGetParams{
			AccountID: cloudflare.F(c.accountID),
		})
	if rerr != nil {
		if isUnavailable(rerr) {
			return false, nil, nil
		}
		c.settingsErr = rerr
		return false, nil, rerr
	}

	c.settingsOK = true
	c.cacheSettings = resp
	return true, resp, nil
}

// literalBindingTypes are the binding kinds whose configured value is the
// binding itself: a secret, an inline constant, or key material. They have no
// resource to name, and their value must never be reported, so they report an
// empty target.
var literalBindingTypes = map[string]struct{}{
	"secret_text":  {},
	"plain_text":   {},
	"json":         {},
	"secret_key":   {},
	"data_blob":    {},
	"text_blob":    {},
	"wasm_module":  {},
	"version_meta": {},
}

// workerBindingTarget names the specific resource a binding points at. The
// binding record is a polymorphic union with one identifying field per kind, so
// the kind decides which field carries the answer.
//
// A kind with no single identifying field (ai, browser, images) and every kind
// whose value is a literal report an empty target rather than a guess.
func workerBindingTarget(b workers.ScriptScriptAndVersionSettingGetResponseBinding) string {
	if _, literal := literalBindingTypes[string(b.Type)]; literal {
		return ""
	}

	switch string(b.Type) {
	case "kv_namespace":
		return b.NamespaceID
	case "r2_bucket":
		return b.BucketName
	case "d1":
		if b.DatabaseID != "" {
			return b.DatabaseID
		}
		// `id` is the pre-rename spelling of database_id and is still returned
		// by older deployments.
		return b.ID
	case "queue":
		return b.QueueName
	case "service":
		return b.Service
	case "durable_object_namespace":
		if b.ScriptName != "" {
			return b.ScriptName + "/" + b.ClassName
		}
		return b.ClassName
	case "dispatch_namespace":
		return b.Namespace
	case "mtls_certificate":
		return b.CertificateID
	case "analytics_engine":
		return b.Dataset
	case "vectorize":
		return b.IndexName
	case "hyperdrive":
		return b.ID
	case "pipelines":
		return b.Pipeline
	case "k2":
		return b.Stream
	case "workflow":
		return b.WorkflowName
	case "secrets_store_secret":
		// The secret's name and store, never its value.
		if b.StoreID != "" {
			return b.StoreID + "/" + b.SecretName
		}
		return b.SecretName
	case "send_email":
		return b.DestinationAddress
	case "vpc_service":
		return b.ServiceID
	case "vpc_network":
		return b.NetworkID
	case "ai_search", "ai_search_namespace":
		return b.InstanceName
	case "flagship":
		return b.AppID
	case "assets", "media":
		return b.Name
	default:
		return ""
	}
}

// bindings lists the resources the Worker's code can reach at runtime.
//
// A Worker whose settings cannot be read reports an empty list, matching the
// degradation the rest of the provider applies to collections; the posture
// fields on this resource report null instead.
func (c *mqlCloudflareWorkersWorker) bindings() ([]any, error) {
	ok, settings, err := c.fetchSettings()
	if err != nil {
		return nil, err
	}
	if !ok {
		return []any{}, nil
	}

	result := make([]any, 0, len(settings.Bindings))
	for i := range settings.Bindings {
		b := settings.Bindings[i]

		res, err := CreateResource(c.MqlRuntime, "cloudflare.workers.worker.binding", map[string]*llx.RawData{
			"__id":   llx.StringData("cloudflare.workers.worker.binding@" + c.accountID + "/" + c.Id.Data + "/" + b.Name),
			"name":   llx.StringData(b.Name),
			"type":   llx.StringData(string(b.Type)),
			"target": llx.StringData(workerBindingTarget(b)),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}

	return result, nil
}

// tailConsumers lists the Workers that receive this Worker's tail events.
func (c *mqlCloudflareWorkersWorker) tailConsumers() ([]any, error) {
	ok, settings, err := c.fetchSettings()
	if err != nil {
		return nil, err
	}
	if !ok {
		return []any{}, nil
	}

	result := make([]any, 0, len(settings.TailConsumers))
	for i := range settings.TailConsumers {
		tc := settings.TailConsumers[i]
		result = append(result, map[string]any{
			"service":     tc.Service,
			"environment": tc.Environment,
			"namespace":   tc.Namespace,
		})
	}
	return result, nil
}

// observabilityEnabled reports whether the Worker retains invocations, logs and
// exceptions.
//
// It reports null when the settings cannot be read: a false there would claim
// the Worker keeps no record of what it did, on a Worker nobody managed to ask.
func (c *mqlCloudflareWorkersWorker) observabilityEnabled() (bool, error) {
	ok, settings, err := c.fetchSettings()
	if err != nil {
		return false, err
	}
	if !ok {
		c.ObservabilityEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return settings.Observability.Enabled, nil
}
