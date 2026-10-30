// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

func newMqlPortainerTag(runtime *plugin.Runtime, t *models.PortainerTag) (*mqlPortainerTag, error) {
	res, err := CreateResource(runtime, "portainer.tag", map[string]*llx.RawData{
		"__id": llx.StringData("portainer.tag/" + strconv.FormatInt(t.ID, 10)),
		"id":   llx.IntData(t.ID),
		"name": llx.StringData(t.Name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPortainerTag), nil
}

func (r *mqlPortainer) tags() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	tags, err := conn.Tags()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(tags))
	for _, t := range tags {
		mqlTag, err := newMqlPortainerTag(r.MqlRuntime, t)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTag)
	}
	return res, nil
}

// resolvePortainerTags maps a set of tag ids to portainer.tag resources using
// the connection's cached tag list, so tag references on environments and
// environment groups become typed.
func resolvePortainerTags(runtime *plugin.Runtime, conn *connection.PortainerConnection, ids []int64) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	tags, err := conn.Tags()
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]*models.PortainerTag, len(tags))
	for _, t := range tags {
		byID[t.ID] = t
	}
	res := make([]any, 0, len(ids))
	for _, id := range ids {
		t, ok := byID[id]
		if !ok {
			continue
		}
		mqlTag, err := newMqlPortainerTag(runtime, t)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTag)
	}
	return res, nil
}
