// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"
)

func (n *mqlGitlabNamespace) id() (string, error) {
	return "gitlab.namespace/" + strconv.FormatInt(n.Id.Data, 10), nil
}

// namespaceArgs converts a GitLab SDK Namespace to an MQL args map.
func namespaceArgs(ns *gitlab.Namespace) map[string]*llx.RawData {
	var trialEndsOn *time.Time
	if ns.TrialEndsOn != nil {
		t := time.Time(*ns.TrialEndsOn)
		trialEndsOn = &t
	}

	return map[string]*llx.RawData{
		"id":                          llx.IntData(ns.ID),
		"name":                        llx.StringData(ns.Name),
		"path":                        llx.StringData(ns.Path),
		"kind":                        llx.StringData(ns.Kind),
		"fullPath":                    llx.StringData(ns.FullPath),
		"parentId":                    llx.IntData(ns.ParentID),
		"webURL":                      llx.StringData(ns.WebURL),
		"membersCountWithDescendants": llx.IntData(ns.MembersCountWithDescendants),
		"billableMembersCount":        llx.IntData(ns.BillableMembersCount),
		"plan":                        llx.StringData(ns.Plan),
		"trial":                       llx.BoolData(ns.Trial),
		"trialEndsOn":                 llx.TimeDataPtr(trialEndsOn),
		"maxSeatsUsed":                llx.IntDataPtr(ns.MaxSeatsUsed),
		"seatsInUse":                  llx.IntDataPtr(ns.SeatsInUse),
	}
}

func (g *mqlGitlabGroup) namespace() (*mqlGitlabNamespace, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)

	groupID := int(g.Id.Data)
	ns, _, err := conn.Client().Namespaces.GetNamespace(groupID)
	if err != nil {
		return nil, err
	}

	mqlNs, err := CreateResource(g.MqlRuntime, "gitlab.namespace", namespaceArgs(ns))
	if err != nil {
		return nil, err
	}

	return mqlNs.(*mqlGitlabNamespace), nil
}

func initGitlabNamespace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.GitLabConnection)

	// gitlab.namespace(id: N) has to look up that namespace. Falling through to
	// the connection's own group here fetched a *different* namespace and then
	// overwrote args["id"] with its id, so the caller silently got authoritative
	// data for something they never asked for.
	if idArg, ok := args["id"]; ok && idArg != nil && idArg.Error == nil {
		nsID, ok := idArg.Value.(int64)
		if !ok {
			return nil, nil, errors.New("gitlab.namespace: id must be an integer")
		}
		ns, _, err := conn.Client().Namespaces.GetNamespace(int(nsID))
		if err != nil {
			return nil, nil, err
		}
		for k, v := range namespaceArgs(ns) {
			args[k] = v
		}
		return args, nil, nil
	}

	if !conn.IsGroup() {
		return nil, nil, errors.New("gitlab.namespace requires a group connection, use --group to specify a group")
	}

	grp, err := conn.Group()
	if err != nil {
		return nil, nil, err
	}

	ns, _, err := conn.Client().Namespaces.GetNamespace(int(grp.ID))
	if err != nil {
		return nil, nil, err
	}

	for k, v := range namespaceArgs(ns) {
		args[k] = v
	}

	return args, nil, nil
}
