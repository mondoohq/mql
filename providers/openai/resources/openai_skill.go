// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mapSkill builds the resource args for an openai.skill. Both the collection
// path and the single-object init share it so the two paths cannot diverge.
func mapSkill(s openai.Skill) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":           llx.StringData(s.ID),
		"id":             llx.StringData(s.ID),
		"name":           llx.StringData(s.Name),
		"description":    llx.StringData(s.Description),
		"defaultVersion": llx.StringData(s.DefaultVersion),
		"latestVersion":  llx.StringData(s.LatestVersion),
		"createdAt":      llx.TimeDataPtr(unixToNullableTime(s.CreatedAt)),
	}
}

func (r *mqlOpenai) skills() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.skills")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.Skills.ListAutoPaging(ctx, openai.SkillListParams{}),
		func(s openai.Skill) string { return s.ID },
		func(s openai.Skill) error {
			mqlSkill, err := CreateResource(r.MqlRuntime, "openai.skill", mapSkill(s))
			if err != nil {
				return err
			}
			res = append(res, mqlSkill)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list skills: %w", err)
	}
	return res, nil
}

func initOpenaiSkill(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	skillID, ok := idRaw.Value.(string)
	if !ok || skillID == "" {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.skill")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch skill %s: no project API key configured", skillID)
	}
	s, err := client.Skills.Get(context.Background(), skillID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get skill %s: %w", skillID, err)
	}
	return mapSkill(*s), nil, nil
}
