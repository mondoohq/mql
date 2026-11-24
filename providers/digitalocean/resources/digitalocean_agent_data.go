// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"

	"github.com/digitalocean/godo"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// agentDataTokenPageSize is the page size requested from the Agent Data
// Services token list.
const agentDataTokenPageSize = 100

// agentDataPlanRegions returns the distinct regions the plan listing names,
// in order. Workspaces and tokens are listed per region and the API has no
// account-wide listing, so the plans are the region set to sweep.
func agentDataPlanRegions(plans *godo.ADSPlansResponse) []string {
	if plans == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, p := range plans.Plans {
		if p.RegionSlug == "" {
			continue
		}
		if _, ok := seen[p.RegionSlug]; ok {
			continue
		}
		seen[p.RegionSlug] = struct{}{}
		out = append(out, p.RegionSlug)
	}
	return out
}

// agentDataRegionList reads the regions Agent Data Services is offered in,
// once per scan.
func (r *mqlDigitalocean) agentDataRegionList() ([]string, error) {
	r.agentDataRegionsOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
		plans, _, err := conn.Client().ADS.ListPlans(context.Background())
		if err != nil {
			// A team the service is not offered to answers 404, which leaves
			// no region to list. Refusals propagate.
			if isDoNotFound(err) {
				return
			}
			r.agentDataRegionsErr = classifyDoError(err)
			return
		}
		r.agentDataRegions = agentDataPlanRegions(plans)
	})
	return r.agentDataRegions, r.agentDataRegionsErr
}

// skipAgentDataRegion reports whether one region's listing failed in a way
// that is a partial result rather than a failure of the whole list: a region
// without the service answers 404, and a denied read for one region should
// not hide the others.
func skipAgentDataRegion(err error, region, what string) bool {
	if isDoNotFound(err) || isDoForbidden(err) {
		log.Debug().Err(err).Str("region", region).Msgf("digitalocean> skipping agent data %s", what)
		return true
	}
	return false
}

// ----- workspaces -----

func agentDataWorkspaceArgs(w *godo.ADSWorkspace, region string) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.agentData.workspace", w.UUID)
	if err != nil {
		return nil, err
	}
	// The listing is per region; a workspace that omits its region is in
	// the region it was listed from.
	if w.Region != "" {
		region = w.Region
	}
	return map[string]*llx.RawData{
		"__id":              llx.StringData(id),
		"id":                llx.StringData(w.UUID),
		"name":              llx.StringData(w.Name),
		"region":            llx.StringData(region),
		"status":            llx.StringData(w.Status),
		"queryEndpoint":     llx.StringData(w.QueryEndpoint),
		"queryInstanceSize": llx.StringData(w.QueryInstanceSize),
		"ownerUuid":         llx.StringData(w.OwnerUUID),
	}, nil
}

func (r *mqlDigitalocean) agentDataWorkspaces() ([]any, error) {
	regions, err := r.agentDataRegionList()
	if err != nil {
		return nil, err
	}
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	out := []any{}
	for _, region := range regions {
		resp, _, err := client.ADS.ListWorkspaces(context.Background(), region)
		if err != nil {
			if skipAgentDataRegion(err, region, "workspaces") {
				continue
			}
			return nil, classifyDoError(err)
		}
		if resp == nil {
			continue
		}
		for i := range resp.Workspaces {
			args, err := agentDataWorkspaceArgs(&resp.Workspaces[i], region)
			if err != nil {
				return nil, err
			}
			res, err := CreateResource(r.MqlRuntime, "digitalocean.agentData.workspace", args)
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func (r *mqlDigitaloceanAgentDataWorkspace) id() (string, error) {
	return resourceID("digitalocean.agentData.workspace", r.Id.Data)
}

// secretKeys lists the names of the secrets stored in the workspace. The
// endpoint returns names only, never values.
func (r *mqlDigitaloceanAgentDataWorkspace) secretKeys() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	resp, _, err := conn.Client().ADS.ListWorkspaceSecrets(context.Background(), r.Region.Data, r.Id.Data)
	if err != nil {
		// A workspace deleted between the listing and this call answers 404,
		// which is genuinely no secrets.
		if isDoNotFound(err) {
			return []any{}, nil
		}
		return nil, classifyDoError(err)
	}
	if resp == nil {
		r.SecretKeys.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return toAnySlice(resp.SecretKeys), nil
}

// agentDataWorkspaceByID resolves a workspace from the workspace listing,
// read once per scan.
func (r *mqlDigitalocean) agentDataWorkspaceByID(id string) (*mqlDigitaloceanAgentDataWorkspace, error) {
	r.agentDataWorkspaceIndexOnce.Do(func() {
		workspaces := r.GetAgentDataWorkspaces()
		if workspaces.Error != nil {
			r.agentDataWorkspaceIndexErr = workspaces.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanAgentDataWorkspace, len(workspaces.Data))
		for _, w := range workspaces.Data {
			mw := w.(*mqlDigitaloceanAgentDataWorkspace)
			idx[mw.Id.Data] = mw
		}
		r.agentDataWorkspaceIndex = idx
	})
	if r.agentDataWorkspaceIndexErr != nil {
		return nil, r.agentDataWorkspaceIndexErr
	}
	return r.agentDataWorkspaceIndex[id], nil
}

// ----- tokens -----

// listAgentDataTokens walks the page/per_page pagination of one region's
// token list. The total arrives as a decimal string (proto JSON int64); an
// empty or unparseable total counts as unreported.
func listAgentDataTokens(ctx context.Context, svc godo.ADSService, region string) ([]godo.ADSTokenSummary, error) {
	return paginateOffset(ctx, agentDataTokenPageSize,
		func(t godo.ADSTokenSummary) string { return t.ID },
		func(ctx context.Context, page int) ([]godo.ADSTokenSummary, int, error) {
			resp, _, err := svc.ListTokens(ctx, &godo.ADSTokenListRequest{Region: region, Page: int64(page), PerPage: agentDataTokenPageSize})
			if err != nil {
				return nil, 0, err
			}
			if resp == nil {
				return nil, -1, nil
			}
			total := -1
			if n, err := strconv.Atoi(strings.TrimSpace(resp.Total)); err == nil {
				total = n
			}
			return resp.Tokens, total, nil
		})
}

// agentDataTokenArgs maps a token summary to its MQL fields. The summary
// never carries the token value. An empty expiry means the token never
// expires and stays null.
func agentDataTokenArgs(t *godo.ADSTokenSummary, region string) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.agentData.token", region, t.ID)
	if err != nil {
		return nil, err
	}
	return map[string]*llx.RawData{
		"__id":       llx.StringData(id),
		"id":         llx.StringData(t.ID),
		"name":       llx.StringData(t.Name),
		"region":     llx.StringData(region),
		"purpose":    llx.StringData(string(t.Purpose)),
		"queryHosts": llx.ArrayData(toAnySlice(t.QueryHosts), types.String),
		"createdAt":  llx.TimeDataPtr(parseDoTime(t.CreatedAt)),
		"expiresAt":  llx.TimeDataPtr(parseDoTime(t.ExpiresAt)),
	}, nil
}

// mqlDigitaloceanAgentDataTokenInternal keeps the uuids of the workspaces
// the token is bound to, which workspaces() resolves from the listing.
type mqlDigitaloceanAgentDataTokenInternal struct {
	cacheWorkspaceIDs []string
}

func (r *mqlDigitalocean) agentDataTokens() ([]any, error) {
	regions, err := r.agentDataRegionList()
	if err != nil {
		return nil, err
	}
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	out := []any{}
	for _, region := range regions {
		tokens, err := listAgentDataTokens(context.Background(), client.ADS, region)
		if err != nil {
			if skipAgentDataRegion(err, region, "tokens") {
				continue
			}
			return nil, classifyDoError(err)
		}
		for i := range tokens {
			args, err := agentDataTokenArgs(&tokens[i], region)
			if err != nil {
				return nil, err
			}
			res, err := CreateResource(r.MqlRuntime, "digitalocean.agentData.token", args)
			if err != nil {
				return nil, err
			}
			res.(*mqlDigitaloceanAgentDataToken).cacheWorkspaceIDs = tokens[i].WorkspaceUUIDs
			out = append(out, res)
		}
	}
	return out, nil
}

func (r *mqlDigitaloceanAgentDataToken) id() (string, error) {
	return resourceID("digitalocean.agentData.token", r.Region.Data, r.Id.Data)
}

// workspaces resolves the workspaces the token is bound to. A binding to a
// workspace the listing does not hold (deleted since) is skipped.
func (r *mqlDigitaloceanAgentDataToken) workspaces() ([]any, error) {
	out := []any{}
	if len(r.cacheWorkspaceIDs) == 0 {
		return out, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	for _, id := range r.cacheWorkspaceIDs {
		w, err := parent.agentDataWorkspaceByID(id)
		if err != nil {
			return nil, err
		}
		if w != nil {
			out = append(out, w)
		}
	}
	return out, nil
}
