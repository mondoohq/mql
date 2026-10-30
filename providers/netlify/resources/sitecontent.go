// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
	"go.mondoo.com/mql/types"
)

// --- forms ----------------------------------------------------------------

type formRecord struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Paths           []string    `json:"paths"`
	SubmissionCount int64       `json:"submission_count"`
	CreatedAt       netlifyTime `json:"created_at"`
}

func (s *mqlNetlifySite) forms() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[formRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/forms", nil)
	if err != nil {
		if connection.IsForbidden(err) {
			s.Forms = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		// Only the form itself is modelled. Its submissions are the visitor
		// data it collected and are never read.
		form, err := CreateResource(s.MqlRuntime, "netlify.site.form", map[string]*llx.RawData{
			"__id":            llx.StringData(s.Id.Data + "/form/" + rec.ID),
			"id":              llx.StringData(rec.ID),
			"name":            llx.StringData(rec.Name),
			"paths":           llx.ArrayData(strSliceToAny(rec.Paths), types.String),
			"submissionCount": llx.IntData(rec.SubmissionCount),
			"createdAt":       llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, form)
	}
	return res, nil
}

func (f *mqlNetlifySiteForm) id() (string, error) {
	return f.Id.Data, f.Id.Error
}

// --- assets ---------------------------------------------------------------

type assetRecord struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	State       string      `json:"state"`
	ContentType string      `json:"content_type"`
	URL         string      `json:"url"`
	Key         string      `json:"key"`
	Visibility  string      `json:"visibility"`
	Size        int64       `json:"size"`
	CreatedAt   netlifyTime `json:"created_at"`
	UpdatedAt   netlifyTime `json:"updated_at"`
}

func (s *mqlNetlifySite) assets() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[assetRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/assets", nil)
	if err != nil {
		if connection.IsForbidden(err) {
			s.Assets = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		asset, err := CreateResource(s.MqlRuntime, "netlify.site.asset", map[string]*llx.RawData{
			"__id":        llx.StringData(s.Id.Data + "/asset/" + rec.ID),
			"id":          llx.StringData(rec.ID),
			"name":        llx.StringData(rec.Name),
			"state":       llx.StringData(rec.State),
			"contentType": llx.StringData(rec.ContentType),
			"url":         llx.StringData(rec.URL),
			"key":         llx.StringData(rec.Key),
			"visibility":  llx.StringData(rec.Visibility),
			"size":        llx.IntData(rec.Size),
			"createdAt":   llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":   llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, asset)
	}
	return res, nil
}

func (a *mqlNetlifySiteAsset) id() (string, error) {
	return a.Id.Data, a.Id.Error
}

// --- split tests ----------------------------------------------------------

type splitTestRecord struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Path          string      `json:"path"`
	Active        bool        `json:"active"`
	Branches      []any       `json:"branches"`
	CreatedAt     netlifyTime `json:"created_at"`
	UpdatedAt     netlifyTime `json:"updated_at"`
	UnpublishedAt netlifyTime `json:"unpublished_at"`
}

func (s *mqlNetlifySite) splitTests() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[splitTestRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/traffic_splits", nil)
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			// Split testing is plan-gated, and a site on a plan without it
			// answers 403 or 404 rather than with an empty list.
			s.SplitTests = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		// The branch split is a list of small records whose shape the API does
		// not document, so it is passed through as reported rather than
		// flattened into fields that would have to be guessed at.
		test, err := CreateResource(s.MqlRuntime, "netlify.site.splitTest", map[string]*llx.RawData{
			"__id":          llx.StringData(s.Id.Data + "/splitTest/" + rec.ID),
			"id":            llx.StringData(rec.ID),
			"name":          llx.StringData(rec.Name),
			"path":          llx.StringData(rec.Path),
			"active":        llx.BoolData(rec.Active),
			"branches":      llx.ArrayData(rec.Branches, types.Dict),
			"createdAt":     llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":     llx.TimeDataPtr(rec.UpdatedAt.Time()),
			"unpublishedAt": llx.TimeDataPtr(rec.UnpublishedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, test)
	}
	return res, nil
}

func (t *mqlNetlifySiteSplitTest) id() (string, error) {
	return t.Id.Data, t.Id.Error
}

// --- add-on integrations --------------------------------------------------

type serviceInstanceRecord struct {
	ID          string      `json:"id"`
	URL         string      `json:"url"`
	ServiceSlug string      `json:"service_slug"`
	ServicePath string      `json:"service_path"`
	ServiceName string      `json:"service_name"`
	CreatedAt   netlifyTime `json:"created_at"`
	UpdatedAt   netlifyTime `json:"updated_at"`

	// Env holds the environment variables the add-on injects into the site,
	// keyed by name. The values are the add-on's own credentials, so only the
	// keys are read out of it.
	Env map[string]string `json:"env"`
}

// serviceInstanceEnvNames returns the sorted names of the variables an add-on
// injects. The values are never read: an add-on's variables are how it hands
// the site its API credentials, so reporting one would put a live credential
// into scan results.
func serviceInstanceEnvNames(env map[string]string) []string {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *mqlNetlifySite) serviceInstances() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[serviceInstanceRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/service-instances", nil)
	if err != nil {
		if connection.IsForbidden(err) {
			s.ServiceInstances = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		// The add-on's own config, external attributes, and authorization
		// address are credentials it holds with the third party, so they are
		// left out of the resource entirely.
		instance, err := CreateResource(s.MqlRuntime, "netlify.site.serviceInstance", map[string]*llx.RawData{
			"__id":        llx.StringData(s.Id.Data + "/serviceInstance/" + rec.ID),
			"id":          llx.StringData(rec.ID),
			"serviceSlug": llx.StringData(rec.ServiceSlug),
			"serviceName": llx.StringData(rec.ServiceName),
			"servicePath": llx.StringData(rec.ServicePath),
			"url":         llx.StringData(rec.URL),
			"environmentVariableNames": llx.ArrayData(
				strSliceToAny(serviceInstanceEnvNames(rec.Env)), types.String),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt": llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, instance)
	}
	return res, nil
}

func (i *mqlNetlifySiteServiceInstance) id() (string, error) {
	return i.Id.Data, i.Id.Error
}
