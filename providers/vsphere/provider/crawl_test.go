// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type crawlSchema struct {
	Resources map[string]struct {
		Fields map[string]struct {
			Type               string `json:"type"`
			IsImplicitResource bool   `json:"is_implicit_resource"`
		} `json:"fields"`
	} `json:"resources"`
}

// TestFullProviderCrawl walks every field of every resource reachable from the
// vsphere root against the vcsim simulator, following resource and
// array-of-resource references, exercising the entire provider end-to-end in
// one pass. It logs the full per-field outcome, then fails if the crawl lacks
// breadth or if any field errors with a message outside the known set of
// simulator limitations (esxcli host config, SSO, appliance REST) — that
// residual is how a real provider bug, such as a moid-decode regression,
// surfaces.
func TestFullProviderCrawl(t *testing.T) {
	vs, srv, connRes := newTestService()
	defer vs.Close()

	raw, err := os.ReadFile("../resources/vsphere.resources.json")
	require.NoError(t, err)
	var schema crawlSchema
	require.NoError(t, json.Unmarshal(raw, &schema))

	root, err := srv.GetData(&plugin.DataReq{Connection: connRes.Id, Resource: "vsphere"})
	require.NoError(t, err)

	type node struct{ rtype, id string }
	queue := []node{{"vsphere", string(root.Data.Value)}}
	visited := map[string]bool{}
	okFields := map[string]bool{}
	errFields := map[string]string{}
	const visitCap = 5000

	for len(queue) > 0 && len(visited) < visitCap {
		n := queue[0]
		queue = queue[1:]
		vkey := n.rtype + "\x00" + n.id
		if visited[vkey] {
			continue
		}
		visited[vkey] = true

		res, ok := schema.Resources[n.rtype]
		if !ok {
			continue
		}
		for fname, f := range res.Fields {
			// Skip implicit fields: the schema synthesizes these rather than
			// the provider implementing them, so they are not resolvable
			// through GetData. Two kinds exist - the accessor named after each
			// child resource (e.g. "snapshot" on vsphere.vm for
			// vsphere.vm.snapshot), which supports chained-resource syntax,
			// and "asset" on the root, which core owns and the runtime
			// resolves (ADR 031).
			if f.IsImplicitResource {
				continue
			}
			path := n.rtype + "." + fname
			resp, err := srv.GetData(&plugin.DataReq{
				Connection: connRes.Id,
				Resource:   n.rtype,
				ResourceId: n.id,
				Field:      fname,
			})
			require.NoError(t, err, "transport error resolving %s", path)
			if resp.Error != "" {
				errFields[path] = resp.Error
				continue
			}
			okFields[path] = true
			if resp.Data == nil {
				continue
			}

			ft := types.Type(f.Type)
			switch {
			case ft.IsResource() && len(resp.Data.Value) > 0:
				queue = append(queue, node{ft.ResourceName(), string(resp.Data.Value)})
			case ft.IsArray() && ft.Child().IsResource():
				for _, el := range resp.Data.Array {
					if el != nil && len(el.Value) > 0 {
						queue = append(queue, node{ft.Child().ResourceName(), string(el.Value)})
					}
				}
			}
		}
	}

	t.Logf("crawl: %d resource instances, %d distinct fields OK, %d field paths errored",
		len(visited), len(okFields), len(errFields))

	// Sanity: the crawl must achieve real breadth against the simulator.
	require.Greater(t, len(visited), 100, "crawl reached too few resources")
	require.Greater(t, len(okFields), 200, "crawl resolved too few fields")

	// vcsim does not implement every backend (esxcli host config, SSO, the
	// appliance REST API), so those resolvers legitimately error. Tolerate
	// only those known simulator-limitation messages; any other error is a
	// real provider bug (this is how a moid-decode regression like the vSAN
	// FromString bug would be caught).
	simLimitations := []string{
		"could not be found",       // esxcli / host config not simulated
		"has already been deleted", // host service objects not fully simulated
		"managed object not found", // e.g. HostAccessManager
		"404 Not Found",            // SSO admin, appliance REST not served
	}
	tolerated := func(msg string) bool {
		for _, s := range simLimitations {
			if strings.Contains(msg, s) {
				return true
			}
		}
		return false
	}

	paths := make([]string, 0, len(errFields))
	for p := range errFields {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var unexpected []string
	for _, p := range paths {
		t.Logf("  ERR %-45s %s", p, errFields[p])
		if !tolerated(errFields[p]) {
			unexpected = append(unexpected, p+": "+errFields[p])
		}
	}
	require.Empty(t, unexpected, "unexpected resolver errors (likely real provider bugs)")
}
