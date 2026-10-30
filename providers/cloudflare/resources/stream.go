// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// streamVideo mirrors the Stream video list entry. We decode it via the
// client's generic Get to keep the existing MQL schema without depending on the
// typed video union shape.
type streamVideo struct {
	UID   string         `json:"uid"`
	Meta  map[string]any `json:"meta"`
	Input struct {
		Width  int64 `json:"width"`
		Height int64 `json:"height"`
	} `json:"input"`
	Playback struct {
		Dash string `json:"dash"`
		HLS  string `json:"hls"`
	} `json:"playback"`
	Creator               string     `json:"creator"`
	Duration              float64    `json:"duration"`
	LiveInput             string     `json:"liveInput"`
	Preview               string     `json:"preview"`
	ReadyToStream         bool       `json:"readyToStream"`
	RequireSignedURLs     bool       `json:"requireSignedURLs"`
	ScheduledDeletion     *time.Time `json:"scheduledDeletion"`
	Size                  int64      `json:"size"`
	Thumbnail             string     `json:"thumbnail"`
	ThumbnailTimestampPct float64    `json:"thumbnailTimestampPct"`
	Uploaded              *time.Time `json:"uploaded"`
}

func (c *mqlCloudflareStreamsLiveInput) id() (string, error) {
	v := c.GetUid()
	if v.Error != nil {
		return "", v.Error
	}
	return v.Data, nil
}

func (c *mqlCloudflareStreamsVideo) id() (string, error) {
	v := c.GetUid()
	if v.Error != nil {
		return "", v.Error
	}
	return v.Data, nil
}

func (c *mqlCloudflareAccount) liveInputs() ([]any, error) {
	return fetchLiveInputs(c.MqlRuntime, c.Id.Data)
}

func fetchLiveInputs(runtime *plugin.Runtime, accountID string) ([]any, error) {
	conn := runtime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result []struct {
			UID                      string         `json:"uid"`
			DeleteRecordingAfterDays int64          `json:"deleteRecordingAfterDays"`
			Meta                     map[string]any `json:"meta"`
		} `json:"result"`
	}
	uri := fmt.Sprintf("accounts/%s/stream/live_inputs", accountID)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		// Stream is a gated add-on; an account without it returns 403
		// ("Cloudflare Stream not enabled"). Degrade to empty like the
		// other add-on-gated list accessors rather than failing the query.
		return degradedList(err)
	}

	var res []any
	for _, result := range env.Result {
		name, _ := result.Meta["name"].(string)

		input, err := NewResource(runtime, "cloudflare.streams.liveInput", map[string]*llx.RawData{
			"__id":                     llx.StringData(result.UID),
			"uid":                      llx.StringData(result.UID),
			"deleteRecordingAfterDays": llx.IntData(result.DeleteRecordingAfterDays),
			"name":                     llx.StringData(name),
		})
		if err != nil {
			return nil, err
		}

		res = append(res, input)
	}

	return res, nil
}

func (c *mqlCloudflareAccount) videos() ([]any, error) {
	return fetchVideos(c.MqlRuntime, c.Id.Data)
}

func fetchVideos(runtime *plugin.Runtime, accountID string) ([]any, error) {
	conn := runtime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result []streamVideo `json:"result"`
	}
	uri := fmt.Sprintf("accounts/%s/stream", accountID)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		// Stream is a gated add-on; an account without it returns 403
		// ("Cloudflare Stream not enabled"). Degrade to empty like the
		// other add-on-gated list accessors rather than failing the query.
		return degradedList(err)
	}

	var result []any
	for i := range env.Result {
		video := env.Result[i]

		name, _ := video.Meta["name"].(string)

		res, err := NewResource(runtime, "cloudflare.streams.video", map[string]*llx.RawData{
			"__id":                  llx.StringData(video.UID),
			"uid":                   llx.StringData(video.UID),
			"name":                  llx.StringData(name),
			"creator":               llx.StringData(video.Creator),
			"duration":              llx.FloatData(video.Duration),
			"height":                llx.IntData(video.Input.Height),
			"width":                 llx.IntData(video.Input.Width),
			"liveInput":             llx.StringData(video.LiveInput),
			"dash":                  llx.StringData(video.Playback.Dash),
			"hls":                   llx.StringData(video.Playback.HLS),
			"preview":               llx.StringData(video.Preview),
			"ready":                 llx.BoolData(video.ReadyToStream),
			"requireSignedUrls":     llx.BoolData(video.RequireSignedURLs),
			"scheduledDeletion":     llx.TimeDataPtr(video.ScheduledDeletion),
			"size":                  llx.IntData(video.Size),
			"thumbnail":             llx.StringData(video.Thumbnail),
			"thumbnailTimestampPct": llx.FloatData(video.ThumbnailTimestampPct),
			"uploaded":              llx.TimeDataPtr(video.Uploaded),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}
