// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// clusterlintResults is the body of GET /v2/kubernetes/clusters/{id}/clusterlint.
//
// godo's GetClusterlintResults decodes only the diagnostics and drops the run
// id and the completion time, and without the completion time a stale run
// cannot be told from a current one. The request therefore goes through the
// client's own NewRequest/Do (keeping the token, rate limiter and error
// decoding) into this struct. The endpoint returns a single run and is not
// paginated. The timestamps are decoded as strings because a run still in
// progress may answer with an empty completion time, which would fail a
// time.Time decode and lose the whole response.
type clusterlintResults struct {
	RunID       string                  `json:"run_id"`
	RequestedAt string                  `json:"requested_at"`
	CompletedAt string                  `json:"completed_at"`
	Diagnostics []clusterlintDiagnostic `json:"diagnostics"`
}

type clusterlintDiagnostic struct {
	CheckName string `json:"check_name"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Object    *struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Owners    []*struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"owners"`
	} `json:"object"`
}

// clusterlintOwners renders the owners of a diagnostic's object as
// "<kind>/<name>".
func clusterlintOwners(d *clusterlintDiagnostic) []any {
	out := []any{}
	if d.Object == nil {
		return out
	}
	for _, o := range d.Object.Owners {
		if o == nil {
			continue
		}
		out = append(out, o.Kind+"/"+o.Name)
	}
	return out
}

// fetchClusterlint reads the cluster's most recent clusterlint run once. A
// 412 or 404 means no run is stored for the cluster, which leaves the result
// nil and both dependent fields null.
func (r *mqlDigitaloceanKubernetesCluster) fetchClusterlint() (*clusterlintResults, error) {
	r.clusterlintOnce.Do(func() {
		if r.Id.Data == "" {
			r.clusterlintErr = errors.New("cannot read clusterlint results without a cluster id")
			return
		}
		conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
		client := conn.Client()
		ctx := context.Background()
		req, err := client.NewRequest(ctx, http.MethodGet, fmt.Sprintf("v2/kubernetes/clusters/%s/clusterlint", url.PathEscape(r.Id.Data)), nil)
		if err != nil {
			r.clusterlintErr = err
			return
		}
		root := new(clusterlintResults)
		if _, err := client.Do(ctx, req, root); err != nil {
			// The API answers 412 precondition_failed for a cluster that has
			// never been linted, and 404 when the results have expired. Both
			// mean there is no run to report, so both read as null rather
			// than as an error.
			if isDoNotFound(err) || isDoStatus(err, http.StatusPreconditionFailed) {
				return
			}
			r.clusterlintErr = classifyDoError(err)
			return
		}
		r.clusterlintValue = root
	})
	return r.clusterlintValue, r.clusterlintErr
}

func (r *mqlDigitaloceanKubernetesCluster) lintCompletedAt() (*time.Time, error) {
	res, err := r.fetchClusterlint()
	if err != nil {
		return nil, err
	}
	var t *time.Time
	if res != nil {
		t = parseDoTime(res.CompletedAt)
	}
	if t == nil {
		r.LintCompletedAt.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return t, nil
}

func (r *mqlDigitaloceanKubernetesCluster) lintDiagnostics() ([]any, error) {
	res, err := r.fetchClusterlint()
	if err != nil {
		return nil, err
	}
	if res == nil {
		// Never linted is not the same answer as "no findings": an empty
		// list would let `lintDiagnostics.none(...)` pass on a cluster
		// nobody has checked.
		r.LintDiagnostics.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Diagnostics carry no id of their own, and the same check can fire
	// more than once on one object with different messages, so the key is
	// the position within the run. The run id keeps positions from two
	// different runs apart.
	run := res.RunID
	if run == "" {
		run = "latest"
	}
	out := make([]any, 0, len(res.Diagnostics))
	for i := range res.Diagnostics {
		d := &res.Diagnostics[i]
		id, err := resourceID("digitalocean.kubernetes.lintDiagnostic", r.Id.Data, run, strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		var kind, name, ns string
		if d.Object != nil {
			kind, name, ns = d.Object.Kind, d.Object.Name, d.Object.Namespace
		}
		obj, err := CreateResource(r.MqlRuntime, "digitalocean.kubernetes.lintDiagnostic", map[string]*llx.RawData{
			"__id":            llx.StringData(id),
			"clusterId":       llx.StringData(r.Id.Data),
			"checkName":       llx.StringData(d.CheckName),
			"severity":        llx.StringData(d.Severity),
			"message":         llx.StringData(d.Message),
			"objectKind":      llx.StringData(kind),
			"objectName":      llx.StringData(name),
			"objectNamespace": llx.StringData(ns),
			"owners":          llx.ArrayData(clusterlintOwners(d), types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, obj)
	}
	return out, nil
}
