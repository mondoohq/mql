// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"

	"github.com/databricks/databricks-sdk-go/service/iam"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// Access control object types accepted by the workspace permissions API. Each
// value is the path segment the API expects, so "sql/warehouses" carries its
// slash into the request path by design.
const (
	permissionObjectCluster         = "clusters"
	permissionObjectClusterPolicy   = "cluster-policies"
	permissionObjectWarehouse       = "sql/warehouses"
	permissionObjectJob             = "jobs"
	permissionObjectPipeline        = "pipelines"
	permissionObjectServingEndpoint = "serving-endpoints"
	permissionObjectRepo            = "repos"
	permissionObjectInstancePool    = "instance-pools"
	// The authorization object type has no per-instance id: the workspace-wide
	// switches it guards are addressed by a fixed name in the id position.
	permissionObjectAuthorization = "authorization"
	// authorizationObjectTokens is the id of the authorization object that
	// governs personal access tokens for the whole workspace.
	authorizationObjectTokens = "tokens"
)

// principalKinds classifies an access control entry. Exactly one of the three
// name fields is set per entry, which is what distinguishes a user from a group
// from a service principal.
const (
	principalKindUser             = "USER"
	principalKindGroup            = "GROUP"
	principalKindServicePrincipal = "SERVICE_PRINCIPAL"
)

// principalOf resolves the name and kind of the principal an access control
// entry belongs to. An entry that names no principal is reported as empty so
// the caller can drop it rather than emit an unattributable permission.
func principalOf(ac iam.AccessControlResponse) (name string, kind string) {
	switch {
	case ac.UserName != "":
		return ac.UserName, principalKindUser
	case ac.GroupName != "":
		return ac.GroupName, principalKindGroup
	case ac.ServicePrincipalName != "":
		return ac.ServicePrincipalName, principalKindServicePrincipal
	}
	return "", ""
}

// permissionRecord is one principal's hold on one permission level, flattened
// out of the grouped shape the API returns.
type permissionRecord struct {
	id                  string
	principal           string
	principalType       string
	displayName         string
	permissionLevel     string
	inherited           bool
	inheritedFromObject []string
	objectType          string
	objectId            string
}

// flattenObjectPermissions maps an access control list to one record per
// principal and permission level. The API groups a principal's levels under that
// principal, but each level carries its own inheritance, so keeping them grouped
// would lose which level is direct and which comes from a parent. An entry that
// names no principal is dropped rather than reported as held by "".
func flattenObjectPermissions(objectType string, objectId string, perms *iam.ObjectPermissions) []permissionRecord {
	out := []permissionRecord{}
	if perms == nil {
		return out
	}

	for i := range perms.AccessControlList {
		ac := perms.AccessControlList[i]
		principal, kind := principalOf(ac)
		if principal == "" {
			continue
		}

		for j := range ac.AllPermissions {
			p := ac.AllPermissions[j]
			level := string(p.PermissionLevel)
			// An entry with no level grants nothing, and since the level is what
			// makes a record's id unique, two such entries for one principal
			// would collide in the cache and the second would be dropped without
			// a trace. Dropping them here is deliberate and total.
			if level == "" {
				continue
			}
			out = append(out, permissionRecord{
				id:                  "databricks.permission/" + objectType + "/" + objectId + "/" + principal + "/" + level,
				principal:           principal,
				principalType:       kind,
				displayName:         ac.DisplayName,
				permissionLevel:     level,
				inherited:           p.Inherited,
				inheritedFromObject: p.InheritedFromObject,
				objectType:          objectType,
				objectId:            objectId,
			})
		}
	}
	return out
}

// errNoObjectId reports that the object carries no identifier the permissions
// API can be keyed on. Callers degrade the field to null rather than reporting
// an empty access control list, which would read as "nobody holds access".
var errNoObjectId = errors.New("object carries no id the permissions API can be keyed on")

// mqlDatabricksPermissions fetches the workspace access control list of a single
// object and maps it to one databricks.permission per principal and permission
// level.
func mqlDatabricksPermissions(runtime *plugin.Runtime, objectType string, objectId string) ([]any, error) {
	// The object id is interpolated into the request path, so an empty one asks
	// the API for /permissions/<type>/ and gets a 404 whose message names no
	// object. Report what is actually wrong instead.
	if objectId == "" {
		return nil, errNoObjectId
	}

	ws, err := workspaceClient(runtime)
	if err != nil {
		return nil, err
	}

	perms, err := ws.Permissions.GetByRequestObjectTypeAndRequestObjectId(context.Background(), objectType, objectId)
	if err != nil {
		return nil, err
	}

	out := []any{}
	for _, rec := range flattenObjectPermissions(objectType, objectId, perms) {
		res, err := CreateResource(runtime, "databricks.permission", map[string]*llx.RawData{
			"__id":                llx.StringData(rec.id),
			"principal":           llx.StringData(rec.principal),
			"principalType":       llx.StringData(rec.principalType),
			"displayName":         llx.StringData(rec.displayName),
			"permissionLevel":     llx.StringData(rec.permissionLevel),
			"inherited":           llx.BoolData(rec.inherited),
			"inheritedFromObject": llx.ArrayData(strSlice(rec.inheritedFromObject), types.String),
			"objectType":          llx.StringData(rec.objectType),
			"objectId":            llx.StringData(rec.objectId),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// tokenPermissions reads the access control list of the workspace-wide token
// authorization object, which is what decides who may mint a personal access
// token. It is not the ACL of any one token: personal access tokens carry no
// per-token ACL.
//
// It answers who may create a token, not whether tokens are permitted at all.
// The workspace's tokensEnabled setting answers that, and a workspace with
// tokens switched off can still carry an access control list here.
func (r *mqlDatabricks) tokenPermissions() ([]any, error) {
	return mqlDatabricksPermissions(r.MqlRuntime, permissionObjectAuthorization, authorizationObjectTokens)
}

func (r *mqlDatabricksCluster) permissions() ([]any, error) {
	return mqlDatabricksPermissions(r.MqlRuntime, permissionObjectCluster, r.Id.Data)
}

func (r *mqlDatabricksClusterPolicy) permissions() ([]any, error) {
	return mqlDatabricksPermissions(r.MqlRuntime, permissionObjectClusterPolicy, r.Id.Data)
}

func (r *mqlDatabricksWarehouse) permissions() ([]any, error) {
	return mqlDatabricksPermissions(r.MqlRuntime, permissionObjectWarehouse, r.Id.Data)
}

func (r *mqlDatabricksJob) permissions() ([]any, error) {
	return mqlDatabricksPermissions(r.MqlRuntime, permissionObjectJob, strconv.FormatInt(r.Id.Data, 10))
}

func (r *mqlDatabricksPipeline) permissions() ([]any, error) {
	return mqlDatabricksPermissions(r.MqlRuntime, permissionObjectPipeline, r.Id.Data)
}

// permissions reads the endpoint access control list. The permissions API keys
// serving endpoints on the endpoint id rather than its name, unlike the serving
// endpoints API itself.
//
// A foundation model endpoint carries no id: the serving endpoints API omits it
// from both the list and the detail response, and the permissions API rejects
// the endpoint name in its place. Its access control list is therefore
// unreadable, and the field reports null rather than an empty list so it cannot
// be mistaken for an endpoint nobody holds access to.
func (r *mqlDatabricksServingEndpoint) permissions() ([]any, error) {
	perms, err := mqlDatabricksPermissions(r.MqlRuntime, permissionObjectServingEndpoint, r.Id.Data)
	if errors.Is(err, errNoObjectId) {
		r.Permissions = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return perms, err
}
