// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"google.golang.org/api/apikeys/v2"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) apiKeys() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	serviceEnabled, err := g.isServiceEnabled(service_apikeys)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_apikeys).Str("project", projectId).Msg("gcp service is not enabled, skipping")
		return nil, nil
	}

	client, err := conn.Client(apikeys.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	apiKeysSvc, err := apikeys.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var apiKeyItems []*apikeys.V2Key
	if err := apiKeysSvc.Projects.Locations.Keys.List(fmt.Sprintf("projects/%s/locations/global", projectId)).Pages(ctx, func(page *apikeys.V2ListKeysResponse) error {
		apiKeyItems = append(apiKeyItems, page.Keys...)
		return nil
	}); err != nil {
		return nil, err
	}

	mqlKeys := make([]any, 0, len(apiKeyItems))
	for _, k := range apiKeyItems {
		// The API omits the entire restrictions block for a key that has no
		// restrictions, so the resource must be built either way: that absence
		// IS the fully-unrestricted case the `unrestricted` predicate exists to
		// report. Building it only when k.Restrictions != nil left
		// `restrictions` null for precisely the keys a posture check is looking
		// for, so `unrestricted` could never evaluate to true.
		var (
			mqlAndroidRestr   any
			mqlBrowserRest    any
			mqlIosRestr       any
			mqlServerKeyRestr any
			mqlApiTargets     = []any{}
		)
		// Null, not empty: a key with no browser restriction has no referrer
		// allowlist at all, which is a different claim from an allowlist that
		// permits nothing.
		browserRestriction := llx.NilData
		iosRestriction := llx.NilData
		serverRestriction := llx.NilData
		allowedApiTargets := []any{}
		if k.Restrictions != nil {
			if k.Restrictions.AndroidKeyRestrictions != nil {

				type mqlAllowedApp struct {
					PackageName     string `json:"packageName"`
					Sha1Fingerprint string `json:"sha1Fingerprint"`
				}
				type mqlAndroidKeyRestrictions struct {
					AllowedApplications []mqlAllowedApp `json:"allowedApplications"`
				}

				androidRestrictions := mqlAndroidKeyRestrictions{}
				for _, a := range k.Restrictions.AndroidKeyRestrictions.AllowedApplications {
					androidRestrictions.AllowedApplications = append(androidRestrictions.AllowedApplications, mqlAllowedApp{
						PackageName:     a.PackageName,
						Sha1Fingerprint: a.Sha1Fingerprint,
					})
				}

				mqlAndroidRestr, err = convert.JsonToDict(androidRestrictions)
				if err != nil {
					return nil, err
				}
			}

			mqlApiTargets = make([]any, 0, len(k.Restrictions.ApiTargets))
			if k.Restrictions.ApiTargets != nil {
				type mqlApiTarget struct {
					Service string   `json:"service"`
					Methods []string `json:"methods"`
				}

				for _, a := range k.Restrictions.ApiTargets {
					target, err := convert.JsonToDict(mqlApiTarget{
						Service: a.Service,
						Methods: a.Methods,
					})
					if err != nil {
						return nil, err
					}
					mqlApiTargets = append(mqlApiTargets, target)

					mqlTarget, err := CreateResource(g.MqlRuntime, "gcp.project.apiKey.restrictions.apiTarget", map[string]*llx.RawData{
						"__id":    llx.StringData(k.Name + "/apiTarget/" + a.Service),
						"service": llx.StringData(a.Service),
						"methods": llx.ArrayData(convert.SliceAnyToInterface(a.Methods), types.String),
					})
					if err != nil {
						return nil, err
					}
					allowedApiTargets = append(allowedApiTargets, mqlTarget)
				}
			}

			if k.Restrictions.BrowserKeyRestrictions != nil {
				type mqlBrowserKeyRestrictions struct {
					AllowedReferrers []string `json:"allowedReferrers"`
				}

				mqlBrowserRest, err = convert.JsonToDict(mqlBrowserKeyRestrictions{
					AllowedReferrers: k.Restrictions.BrowserKeyRestrictions.AllowedReferrers,
				})
				if err != nil {
					return nil, err
				}
				browserRestriction, err = newMqlApiKeyRestriction(g.MqlRuntime,
					"gcp.project.apiKey.restrictions.browserRestriction", k.Name+"/browserRestriction",
					"allowedReferrers", k.Restrictions.BrowserKeyRestrictions.AllowedReferrers)
				if err != nil {
					return nil, err
				}
			}

			if k.Restrictions.IosKeyRestrictions != nil {
				type mqlIosKeyRestrictions struct {
					AllowedBundleIds []string `json:"allowedBundleIds"`
				}

				mqlIosRestr, err = convert.JsonToDict(mqlIosKeyRestrictions{
					AllowedBundleIds: k.Restrictions.IosKeyRestrictions.AllowedBundleIds,
				})
				if err != nil {
					return nil, err
				}
				iosRestriction, err = newMqlApiKeyRestriction(g.MqlRuntime,
					"gcp.project.apiKey.restrictions.iosRestriction", k.Name+"/iosRestriction",
					"allowedBundleIds", k.Restrictions.IosKeyRestrictions.AllowedBundleIds)
				if err != nil {
					return nil, err
				}
			}

			if k.Restrictions.ServerKeyRestrictions != nil {
				type mqlServerKeyRestrictions struct {
					AllowedIps []string `json:"allowedIps"`
				}

				mqlServerKeyRestr, err = convert.JsonToDict(mqlServerKeyRestrictions{
					AllowedIps: k.Restrictions.ServerKeyRestrictions.AllowedIps,
				})
				if err != nil {
					return nil, err
				}
				serverRestriction, err = newMqlApiKeyRestriction(g.MqlRuntime,
					"gcp.project.apiKey.restrictions.serverRestriction", k.Name+"/serverRestriction",
					"allowedIps", k.Restrictions.ServerKeyRestrictions.AllowedIps)
				if err != nil {
					return nil, err
				}
			}

		}

		mqlRestrictions, err := CreateResource(g.MqlRuntime, "gcp.project.apiKey.restrictions", map[string]*llx.RawData{
			"parentResourcePath":     llx.StringData(k.Name),
			"androidKeyRestrictions": llx.DictData(mqlAndroidRestr),
			"browserKeyRestrictions": llx.DictData(mqlBrowserRest),
			"iosKeyRestrictions":     llx.DictData(mqlIosRestr),
			"serverKeyRestrictions":  llx.DictData(mqlServerKeyRestr),
			"apiTargets":             llx.ArrayData(mqlApiTargets, types.Dict),
			"browser":                browserRestriction,
			"ios":                    iosRestriction,
			"server":                 serverRestriction,
			"allowedApiTargets":      llx.ArrayData(allowedApiTargets, types.Resource("gcp.project.apiKey.restrictions.apiTarget")),
		})
		if err != nil {
			return nil, err
		}

		mqlKey, err := CreateResource(g.MqlRuntime, "gcp.project.apiKey", map[string]*llx.RawData{
			"projectId":           llx.StringData(projectId),
			"id":                  llx.StringData(parseResourceName(k.Name)),
			"name":                llx.StringData(k.DisplayName),
			"resourcePath":        llx.StringData(k.Name),
			"annotations":         llx.MapData(convert.MapToInterfaceMap(k.Annotations), types.String),
			"created":             llx.TimeDataPtr(parseTime(k.CreateTime)),
			"deleted":             llx.TimeDataPtr(parseTime(k.DeleteTime)),
			"keyString":           llx.StringData(k.KeyString),
			"restrictions":        llx.ResourceData(mqlRestrictions, "gcp.project.apiKey.restrictions"),
			"updated":             llx.TimeDataPtr(parseTime(k.UpdateTime)),
			"serviceAccountEmail": llx.StringData(k.ServiceAccountEmail),
		})
		if err != nil {
			return nil, err
		}
		mqlKeys = append(mqlKeys, mqlKey)
	}
	return mqlKeys, nil
}

func (g *mqlGcpProjectApiKey) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

func (g *mqlGcpProjectApiKey) project() (*mqlGcpProject, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	proj, err := projectRefById(g.MqlRuntime, g.ProjectId.Data)
	if err != nil {
		return nil, err
	}
	if proj == nil {
		g.Project.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return proj, nil
}

func (g *mqlGcpProjectApiKey) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.ServiceAccountEmail.Data, g.ProjectId.Data)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectApiKey) managedBy() (string, error) {
	return managedByFromLabels(g.GetAnnotations())
}

func initGcpProjectApiKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["id"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.apiKey requires a \"projectId\" argument")
	}

	// NewResource, not CreateResource: CreateResource would cache a gcp.project
	// carrying nothing but an id, and initGcpProject returns whatever is already
	// cached -- so that husk would win for every later caller, and its name,
	// state, parentId, labels, createTime and number are computed fields
	// implemented as placeholders that only ever return "not implemented".
	// servicegate.go spells out the same reasoning for the enablement lookup.
	obj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	proj := obj.(*mqlGcpProject)
	keys := proj.GetApiKeys()
	if keys.Error != nil {
		return nil, nil, keys.Error
	}

	idRaw := args["id"]
	if idRaw == nil {
		return nil, nil, errors.New("gcp.project.apiKey requires an \"id\" argument")
	}
	idVal, _ := idRaw.Value.(string)
	for _, k := range keys.Data {
		key := k.(*mqlGcpProjectApiKey)
		if key.Id.Data == idVal {
			return args, key, nil
		}
	}

	return nil, nil, fmt.Errorf("api key %q not found", idVal)
}

func (g *mqlGcpProjectApiKeyRestrictions) id() (string, error) {
	if g.ParentResourcePath.Error != nil {
		return "", g.ParentResourcePath.Error
	}
	return fmt.Sprintf("%s/restrictions", g.ParentResourcePath.Data), nil
}

func (g *mqlGcpProjectApiKeyRestrictions) unrestricted() (bool, error) {
	if g.AndroidKeyRestrictions.Error != nil {
		return false, g.AndroidKeyRestrictions.Error
	}
	if g.BrowserKeyRestrictions.Error != nil {
		return false, g.BrowserKeyRestrictions.Error
	}
	if g.IosKeyRestrictions.Error != nil {
		return false, g.IosKeyRestrictions.Error
	}
	if g.ServerKeyRestrictions.Error != nil {
		return false, g.ServerKeyRestrictions.Error
	}
	if g.ApiTargets.Error != nil {
		return false, g.ApiTargets.Error
	}
	return g.AndroidKeyRestrictions.Data == nil &&
		g.BrowserKeyRestrictions.Data == nil &&
		g.IosKeyRestrictions.Data == nil &&
		g.ServerKeyRestrictions.Data == nil &&
		len(g.ApiTargets.Data) == 0, nil
}

func (g *mqlGcpProjectApiKeyRestrictions) appliedRestrictionTypes() ([]any, error) {
	if g.AndroidKeyRestrictions.Error != nil {
		return nil, g.AndroidKeyRestrictions.Error
	}
	if g.BrowserKeyRestrictions.Error != nil {
		return nil, g.BrowserKeyRestrictions.Error
	}
	if g.IosKeyRestrictions.Error != nil {
		return nil, g.IosKeyRestrictions.Error
	}
	if g.ServerKeyRestrictions.Error != nil {
		return nil, g.ServerKeyRestrictions.Error
	}
	if g.ApiTargets.Error != nil {
		return nil, g.ApiTargets.Error
	}
	applied := []any{}
	if g.AndroidKeyRestrictions.Data != nil {
		applied = append(applied, "androidKeyRestrictions")
	}
	if g.BrowserKeyRestrictions.Data != nil {
		applied = append(applied, "browserKeyRestrictions")
	}
	if g.IosKeyRestrictions.Data != nil {
		applied = append(applied, "iosKeyRestrictions")
	}
	if g.ServerKeyRestrictions.Data != nil {
		applied = append(applied, "serverKeyRestrictions")
	}
	if len(g.ApiTargets.Data) > 0 {
		applied = append(applied, "apiTargets")
	}
	return applied, nil
}

// Always bootstrap through the parent key. apiKeys() populates restrictions
// via CreateResource (which bypasses Init), so any NewResource call here is
// a top-level `gcp.project.apiKey.restrictions` query — partial args would
// pass through to Create and yield a bare stub whose fields all error with
// "cannot convert primitive with NO type information".
func initGcpProjectApiKeyRestrictions(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	ids := getAssetIdentifier(runtime)
	if ids == nil {
		return nil, nil, errors.New("no asset identifier found; gcp.project.apiKey.restrictions requires a gcp-apikey asset context")
	}

	obj, err := NewResource(runtime, "gcp.project.apiKey", map[string]*llx.RawData{
		"id":        llx.StringData(ids.name),
		"projectId": llx.StringData(ids.project),
	})
	if err != nil {
		return nil, nil, err
	}
	key := obj.(*mqlGcpProjectApiKey)
	restrictions := key.GetRestrictions()
	if restrictions.Error != nil {
		return nil, nil, restrictions.Error
	}
	if restrictions.Data == nil {
		// Key has no restrictions. Null out all fields so the Create fallthrough
		// produces a resource whose TValues are StateIsNull|StateIsSet (via
		// RawToTValue's nil path) instead of a bare stub. Matches the pattern
		// in initGcpProjectIamServiceAccount.
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		args["parentResourcePath"] = llx.NilData
		args["androidKeyRestrictions"] = llx.NilData
		args["apiTargets"] = llx.NilData
		args["browserKeyRestrictions"] = llx.NilData
		args["iosKeyRestrictions"] = llx.NilData
		args["serverKeyRestrictions"] = llx.NilData
		args["browser"] = llx.NilData
		args["ios"] = llx.NilData
		args["server"] = llx.NilData
		args["allowedApiTargets"] = llx.NilData
		return args, nil, nil
	}
	return args, restrictions.Data, nil
}

// newMqlApiKeyRestriction builds one of the three single-list restrictions an
// API key can carry.
//
// Restrictions, IosKeyRestrictions and ServerKeyRestrictions each wrap exactly
// one allowlist, so they share a builder rather than three near-identical
// copies. The allowlist is reported as empty rather than null when the
// restriction exists but names nothing, which is a real state: it locks the key
// out of every caller.
func newMqlApiKeyRestriction(runtime *plugin.Runtime, resource, id, field string, allowed []string) (*llx.RawData, error) {
	res, err := CreateResource(runtime, resource, map[string]*llx.RawData{
		"__id": llx.StringData(id),
		field:  llx.ArrayData(convert.SliceAnyToInterface(allowed), types.String),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, resource), nil
}
