// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

func newWorkers(runtime *plugin.Runtime, accountID string) (*mqlCloudflareWorkers, error) {
	res, err := CreateResource(runtime, "cloudflare.workers", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.workers@" + accountID),
	})
	if err != nil {
		return nil, err
	}

	workers := res.(*mqlCloudflareWorkers)
	workers.AccountID = accountID

	return workers, nil
}

// initCloudflareWorkers binds the connection's account when `cloudflare.workers`
// is reached bare, i.e. not through cloudflare.account.workers. Workers are
// account-scoped, so without this the resource is built with an empty AccountID
// and every request goes to /accounts//workers/scripts.
func initCloudflareWorkers(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	accountID, err := connectionAccountID(runtime)
	if err != nil {
		return nil, nil, err
	}

	res, err := newWorkers(runtime, accountID)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (c *mqlCloudflareAccount) workers() (*mqlCloudflareWorkers, error) {
	return newWorkers(c.MqlRuntime, c.Id.Data)
}

// workerScript mirrors the account workers-scripts list entry. We decode it via
// the client's generic Get to preserve fields (size, deployment_id,
// pipeline_hash) that the typed cloudflare-go script struct no longer
// exposes.
type workerScript struct {
	ID               string    `json:"id"`
	ETag             string    `json:"etag"`
	Size             int64     `json:"size"`
	DeploymentID     *string   `json:"deployment_id"`
	PipelineHash     *string   `json:"pipeline_hash"`
	PlacementMode    string    `json:"placement_mode"`
	LastDeployedFrom *string   `json:"last_deployed_from"`
	Logpush          *bool     `json:"logpush"`
	CreatedOn        time.Time `json:"created_on"`
	ModifiedOn       time.Time `json:"modified_on"`
}

type mqlCloudflareWorkersInternal struct {
	AccountID string

	workerListLock sync.Mutex
	workerListDone bool
	workerList     []workerScript
	workerListErr  error
}

// fetchWorkerList caches the per-account workers list so that workers() and
// secrets() share a single list API call.
func (c *mqlCloudflareWorkers) fetchWorkerList() ([]workerScript, error) {
	if c.workerListDone {
		return c.workerList, c.workerListErr
	}
	c.workerListLock.Lock()
	defer c.workerListLock.Unlock()
	if c.workerListDone {
		return c.workerList, c.workerListErr
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	var env struct {
		Result []workerScript `json:"result"`
	}
	uri := fmt.Sprintf("accounts/%s/workers/scripts", c.mqlCloudflareWorkersInternal.AccountID)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		c.workerListErr = err
	} else {
		c.workerList = env.Result
	}
	c.workerListDone = true
	return c.workerList, c.workerListErr
}

func (c *mqlCloudflareWorkers) workers() ([]any, error) {
	if c.mqlCloudflareWorkersInternal.AccountID == "" {
		return nil, errNoAccountBound
	}

	workerList, err := c.fetchWorkerList()
	if err != nil {
		return nil, err
	}

	var result []any
	for i := range workerList {
		w := workerList[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.workers.worker", map[string]*llx.RawData{
			// This resource has no id() method, so without an explicit __id every
			// worker would share the empty cache key and alias to the first
			// script. Scope by account so cross-account scans don't collide.
			"__id":             llx.StringData("cloudflare.workers.worker@" + c.AccountID + "/" + w.ID),
			"id":               llx.StringData(w.ID),
			"etag":             llx.StringData(w.ETag),
			"size":             llx.IntData(w.Size),
			"deploymentId":     llx.StringDataPtr(w.DeploymentID),
			"pipelineHash":     llx.StringDataPtr(w.PipelineHash),
			"placementMode":    llx.StringData(w.PlacementMode),
			"lastDeployedFrom": llx.StringDataPtr(w.LastDeployedFrom),
			"logPush":          llx.BoolDataPtr(w.Logpush),
			"createdOn":        llx.TimeData(w.CreatedOn),
			"modifiedOn":       llx.TimeData(w.ModifiedOn),
		})
		if err != nil {
			return nil, err
		}
		// The per-script settings endpoint is account-scoped, so carry the
		// account through for bindings(), tailConsumers() and
		// observabilityEnabled().
		res.(*mqlCloudflareWorkersWorker).accountID = c.AccountID
		result = append(result, res)
	}

	return result, nil
}

// pages lists Cloudflare Pages projects, surfacing each project's canonical
// (production) deployment. The projects endpoint embeds that deployment, so a
// single paged call covers it; preview/historical deployments are out of scope
// here. Degrades to empty when Pages isn't available to the token.
func (c *mqlCloudflareWorkers) pages() ([]any, error) {
	if c.mqlCloudflareWorkersInternal.AccountID == "" {
		return nil, errNoAccountBound
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	projects, err := cfGetPaged[pagesProject](conn, fmt.Sprintf("accounts/%s/pages/projects", c.AccountID))
	if err != nil {
		if isUnavailable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	var result []any
	for i := range projects {
		p := projects[i]
		d := p.CanonicalDeployment
		if d == nil {
			// No production deployment yet — nothing to describe for this project.
			continue
		}
		res, err := CreateResource(c.MqlRuntime, "cloudflare.workers.page", map[string]*llx.RawData{
			"__id":             llx.StringData("cloudflare.workers.page@" + c.AccountID + "/" + p.Name + "/" + d.ID),
			"id":               llx.StringData(d.ID),
			"shortId":          llx.StringData(d.ShortID),
			"projectId":        llx.StringData(d.ProjectID),
			"projectName":      llx.StringData(p.Name),
			"environment":      llx.StringData(d.Environment),
			"url":              llx.StringData(d.URL),
			"aliases":          llx.ArrayData(convert.SliceAnyToInterface(d.Aliases), types.String),
			"productionBranch": llx.StringData(p.ProductionBranch),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (c *mqlCloudflareWorkersSecret) id() (string, error) {
	return c.GetScriptName().Data + "/" + c.GetName().Data, nil
}

func (c *mqlCloudflarePagesEnvVar) id() (string, error) {
	return c.GetProjectName().Data + "/" + c.GetEnvironment().Data + "/" + c.GetName().Data, nil
}

// secrets enumerates secret bindings across every worker script in the
// account. We only surface name + type — Cloudflare's API never returns the
// secret value, and we explicitly avoid fields that could expose plaintext.
func (c *mqlCloudflareWorkers) secrets() ([]any, error) {
	if c.mqlCloudflareWorkersInternal.AccountID == "" {
		return nil, errNoAccountBound
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	workerList, err := c.fetchWorkerList()
	if err != nil {
		return nil, err
	}

	var result []any
	for i := range workerList {
		w := workerList[i]

		var env struct {
			Result []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"result"`
		}
		uri := fmt.Sprintf("accounts/%s/workers/scripts/%s/secrets", c.mqlCloudflareWorkersInternal.AccountID, w.ID)
		if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
			// Skip scripts where we lack permission rather than failing the
			// whole enumeration.
			if isUnavailable(err) {
				continue
			}
			return nil, err
		}

		for j := range env.Result {
			s := env.Result[j]
			res, err := CreateResource(c.MqlRuntime, "cloudflare.workers.secret", map[string]*llx.RawData{
				"__id":       llx.StringData("cloudflare.workers.secret@" + c.AccountID + "/" + w.ID + "/" + s.Name),
				"scriptName": llx.StringData(w.ID),
				"name":       llx.StringData(s.Name),
				"secretType": llx.StringData(s.Type),
			})
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}
	}

	return result, nil
}

type pagesDeployConfig struct {
	EnvVars map[string]*struct {
		Type string `json:"type"`
	} `json:"env_vars"`
}

// pagesDeployment is the deployment object embedded in a Pages project (the
// canonical/production deployment), decoded via the client's generic Get.
type pagesDeployment struct {
	ID          string   `json:"id"`
	ShortID     string   `json:"short_id"`
	ProjectID   string   `json:"project_id"`
	ProjectName string   `json:"project_name"`
	Environment string   `json:"environment"`
	URL         string   `json:"url"`
	Aliases     []string `json:"aliases"`
}

type pagesProject struct {
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	ProductionBranch    string           `json:"production_branch"`
	CanonicalDeployment *pagesDeployment `json:"canonical_deployment"`
	DeploymentConfigs   struct {
		Preview    pagesDeployConfig `json:"preview"`
		Production pagesDeployConfig `json:"production"`
	} `json:"deployment_configs"`
}

// pageEnvVars enumerates environment variable bindings across every Pages
// project. We expose only `{name, type, environment}` and never `value` so
// secret bindings cannot leak even if the API were to return one.
func (c *mqlCloudflareWorkers) pageEnvVars() ([]any, error) {
	if c.mqlCloudflareWorkersInternal.AccountID == "" {
		return nil, errNoAccountBound
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	projects, err := cfGetPaged[pagesProject](conn, fmt.Sprintf("accounts/%s/pages/projects", c.mqlCloudflareWorkersInternal.AccountID))
	if err != nil {
		if isUnavailable(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []any
	emit := func(env, projectName string, cfg pagesDeployConfig) error {
		for name, v := range cfg.EnvVars {
			varType := ""
			if v != nil {
				varType = v.Type
			}
			res, err := CreateResource(c.MqlRuntime, "cloudflare.pages.envVar", map[string]*llx.RawData{
				"__id":        llx.StringData("cloudflare.pages.envVar@" + c.AccountID + "/" + projectName + "/" + env + "/" + name),
				"projectName": llx.StringData(projectName),
				"environment": llx.StringData(env),
				"name":        llx.StringData(name),
				"type":        llx.StringData(varType),
			})
			if err != nil {
				return err
			}
			result = append(result, res)
		}
		return nil
	}

	for j := range projects {
		p := projects[j]
		if err := emit("preview", p.Name, p.DeploymentConfigs.Preview); err != nil {
			return nil, err
		}
		if err := emit("production", p.Name, p.DeploymentConfigs.Production); err != nil {
			return nil, err
		}
	}

	return result, nil
}
