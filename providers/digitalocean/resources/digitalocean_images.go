// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"time"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// --- Images ---

// newMqlDigitaloceanImage builds a digitalocean.image resource from a godo image.
// It is shared by the images() collection and the droplet baseImage() accessor.
func newMqlDigitaloceanImage(runtime *plugin.Runtime, img godo.Image) (*mqlDigitaloceanImage, error) {
	regions := make([]any, len(img.Regions))
	for i, rg := range img.Regions {
		regions[i] = rg
	}
	tags := make([]any, len(img.Tags))
	for i, t := range img.Tags {
		tags[i] = t
	}
	res, err := CreateResource(runtime, "digitalocean.image", map[string]*llx.RawData{
		"id":            llx.IntData(int64(img.ID)),
		"name":          llx.StringData(img.Name),
		"type":          llx.StringData(img.Type),
		"distribution":  llx.StringData(img.Distribution),
		"slug":          llx.StringData(img.Slug),
		"public":        llx.BoolData(img.Public),
		"regions":       llx.ArrayData(regions, "\x02"),
		"minDiskSize":   llx.IntData(int64(img.MinDiskSize)),
		"sizeGigabytes": llx.FloatData(img.SizeGigaBytes),
		"description":   llx.StringData(img.Description),
		"status":        llx.StringData(img.Status),
		"errorMessage":  llx.StringData(img.ErrorMessage),
		"tags":          llx.ArrayData(tags, "\x02"),
		"createdAt":     llx.TimeDataPtr(parseDoTime(img.Created)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanImage), nil
}

// images lists the account's own images — custom uploads, droplet and volume
// snapshots saved as images, and backups. ListUser is used instead of List so
// the result excludes the hundreds of public DigitalOcean catalog images
// (distributions and 1-Click applications), which are not account resources.
func (r *mqlDigitalocean) images() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	images, err := paginate(context.Background(), client.Images.ListUser)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(images))
	for _, img := range images {
		res, err := newMqlDigitaloceanImage(r.MqlRuntime, img)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanImage) id() (string, error) {
	return "digitalocean.image/" + strconv.FormatInt(r.Id.Data, 10), nil
}

// --- Snapshots ---

func (r *mqlDigitalocean) snapshots() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	snapshots, err := paginate(context.Background(), client.Snapshots.List)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(snapshots))
	for _, s := range snapshots {
		regions := make([]any, len(s.Regions))
		for i, rg := range s.Regions {
			regions[i] = rg
		}
		tags := make([]any, len(s.Tags))
		for i, t := range s.Tags {
			tags[i] = t
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.snapshot", map[string]*llx.RawData{
			"id":            llx.StringData(s.ID),
			"name":          llx.StringData(s.Name),
			"resourceId":    llx.StringData(s.ResourceID),
			"resourceType":  llx.StringData(s.ResourceType),
			"regions":       llx.ArrayData(regions, "\x02"),
			"minDiskSize":   llx.IntData(int64(s.MinDiskSize)),
			"sizeGigabytes": llx.FloatData(s.SizeGigaBytes),
			"tags":          llx.ArrayData(tags, "\x02"),
			"createdAt":     llx.TimeDataPtr(parseDoTime(s.Created)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanSnapshot) id() (string, error) {
	return "digitalocean.snapshot/" + r.Id.Data, nil
}

// --- Functions ---

func (r *mqlDigitalocean) functionNamespaces() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	namespaces, _, err := client.Functions.ListNamespaces(context.Background())
	if err != nil {
		return nil, err
	}

	var all []any
	for _, ns := range namespaces {
		res, err := CreateResource(r.MqlRuntime, "digitalocean.function.namespace", map[string]*llx.RawData{
			"uuid":      llx.StringData(ns.UUID),
			"namespace": llx.StringData(ns.Namespace),
			"label":     llx.StringData(ns.Label),
			"region":    llx.StringData(ns.Region),
			"apiHost":   llx.StringData(ns.ApiHost),
			"createdAt": llx.TimeData(ns.CreatedAt),
			"updatedAt": llx.TimeData(ns.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanFunctionNamespace) id() (string, error) {
	return "digitalocean.function.namespace/" + r.Uuid.Data, nil
}

func (r *mqlDigitaloceanFunctionNamespace) triggers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	triggers, _, err := client.Functions.ListTriggers(context.Background(), r.Namespace.Data)
	if err != nil {
		return nil, err
	}

	var all []any
	for _, t := range triggers {
		cron := ""
		if t.ScheduledDetails != nil {
			cron = t.ScheduledDetails.Cron
		}
		var lastRun, nextRun *time.Time
		if t.ScheduledRuns != nil {
			if !t.ScheduledRuns.LastRunAt.IsZero() {
				lr := t.ScheduledRuns.LastRunAt
				lastRun = &lr
			}
			if !t.ScheduledRuns.NextRunAt.IsZero() {
				nr := t.ScheduledRuns.NextRunAt
				nextRun = &nr
			}
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.function.trigger", map[string]*llx.RawData{
			"namespace": llx.StringData(r.Namespace.Data),
			"name":      llx.StringData(t.Name),
			"type":      llx.StringData(t.Type),
			"function":  llx.StringData(t.Function),
			"enabled":   llx.BoolData(t.IsEnabled),
			"cron":      llx.StringData(cron),
			"createdAt": llx.TimeData(t.CreatedAt),
			"updatedAt": llx.TimeData(t.UpdatedAt),
			"lastRunAt": llx.TimeDataPtr(lastRun),
			"nextRunAt": llx.TimeDataPtr(nextRun),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanFunctionTrigger) id() (string, error) {
	return "digitalocean.function.trigger/" + r.Namespace.Data + "/" + r.Name.Data, nil
}
