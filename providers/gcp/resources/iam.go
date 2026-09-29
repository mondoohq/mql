// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	admin "cloud.google.com/go/iam/admin/apiv1"
	iampbv1 "cloud.google.com/go/iam/apiv1/iampb"
	iamv2 "cloud.google.com/go/iam/apiv2"
	iamv2pb "cloud.google.com/go/iam/apiv2/iampb"
	"google.golang.org/api/googleapi"
	iamrest "google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	policyanalyzer "google.golang.org/api/policyanalyzer/v1"
	adminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (g *mqlGcpProjectIamService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.iamService", projectId), nil
}

type mqlGcpProjectIamServiceInternal struct {
	serviceGate
}

type mqlGcpProjectIamServiceServiceAccountInternal struct {
	keyLastAuthOnce sync.Once
	keyLastAuthMap  map[string]*time.Time
	keyLastAuthErr  error
}

type mqlGcpProjectIamServiceServiceAccountKeyInternal struct {
	// Back-reference set when the key is loaded via the parent SA's keys()
	// accessor. Nil when the key is constructed in isolation (e.g., from a
	// platform-ID asset import), in which case lastAuthenticatedTime() falls
	// back to a per-key Policy Analyzer query.
	parentSA *mqlGcpProjectIamServiceServiceAccount
}

func (g *mqlGcpProject) iam() (*mqlGcpProjectIamService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.iamService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_iam)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectIamService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_iam).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

// Direct construction (e.g. `gcp.project.iamService.serviceAccounts`) bypasses
// gcp.project.iam(), so projectId stays empty and serviceEnabled stays false —
// accessors then short-circuit and silently return empty. Delegate to the
// parent project accessor so the resulting instance is fully initialized.
func initGcpProjectIamService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["projectId"]; ok {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(conn.ResourceID()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc, err := proj.(*mqlGcpProject).iam()
	if err != nil {
		return nil, nil, err
	}
	return nil, svc, nil
}

func (g *mqlGcpProjectIamServiceServiceAccount) id() (string, error) {
	if g.UniqueId.Error != nil {
		return "", g.UniqueId.Error
	}
	if g.UniqueId.IsNull() || g.UniqueId.Data == "" {
		// Fall back to email so not-found / asset-context instances still get a
		// stable, non-colliding cache key.
		if g.Email.Error != nil {
			return "", g.Email.Error
		}
		if !g.Email.IsNull() && g.Email.Data != "" {
			return "gcp.project.iamService.serviceAccount/email/" + g.Email.Data, nil
		}
		return "", errors.New("service account has no uniqueId or email for cache key")
	}
	return g.UniqueId.Data, nil
}

func (g *mqlGcpProjectIamServiceServiceAccount) project() (*mqlGcpProject, error) {
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

func (g *mqlGcpProjectIamServiceServiceAccountKey) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func initGcpProjectIamServiceServiceAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID. This happens
	// when the resource is initialized from a gcp-iam-service-account asset.
	// The platform ID encodes the service account's uniqueId as the name segment
	// (see discovery.go and NewResourcePlatformID).
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["projectId"] = llx.StringData(ids.project)
			args["uniqueId"] = llx.StringData(ids.name)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	if args["projectId"] == nil {
		return args, nil, nil
	}
	if args["email"] == nil && args["uniqueId"] == nil {
		return args, nil, nil
	}

	// Go through gcp.project so the iamService picks up its `serviceEnabled`
	// flag — constructing the iamService directly leaves the flag at its
	// zero value, which short-circuits serviceAccounts() to nil and makes the
	// SA lookup miss every typed-ref query.
	// NewResource, not CreateResource: CreateResource would cache a gcp.project
	// carrying nothing but an id, and initGcpProject returns whatever is already
	// cached -- so that husk would win for every later caller, and its name,
	// state, parentId, labels, createTime and number are computed fields
	// implemented as placeholders that only ever return "not implemented".
	// servicegate.go spells out the same reasoning for the enablement lookup.
	projObj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	iamRes := projObj.(*mqlGcpProject).GetIam()
	if iamRes.Error != nil {
		return nil, nil, iamRes.Error
	}
	iamSvc := iamRes.Data
	sas := iamSvc.GetServiceAccounts()
	if sas.Error != nil {
		return nil, nil, sas.Error
	}

	for _, s := range sas.Data {
		sa := s.(*mqlGcpProjectIamServiceServiceAccount)

		if args["email"] != nil {
			email := sa.GetEmail()
			if email.Error != nil {
				return nil, nil, email.Error
			}
			if email.Data == args["email"].Value {
				return args, sa, nil
			}
		}

		if args["uniqueId"] != nil {
			uniqueId := sa.GetUniqueId()
			if uniqueId.Error != nil {
				return nil, nil, uniqueId.Error
			}
			if uniqueId.Data == args["uniqueId"].Value {
				return args, sa, nil
			}
		}
	}

	// Capture the original lookup values before we null out missing fields,
	// so the "not found" log reflects what we actually searched for.
	var lookupEmail, lookupUniqueId any
	if args["email"] != nil {
		lookupEmail = args["email"].Value
	}
	if args["uniqueId"] != nil {
		lookupUniqueId = args["uniqueId"].Value
	}

	// Not found: null out all fields so downstream field access returns null
	// instead of hitting "cannot convert primitive with NO type information".
	if args["name"] == nil {
		args["name"] = llx.NilData
	}
	if args["uniqueId"] == nil {
		args["uniqueId"] = llx.NilData
	}
	if args["email"] == nil {
		args["email"] = llx.NilData
	}
	if args["displayName"] == nil {
		args["displayName"] = llx.NilData
	}
	if args["description"] == nil {
		args["description"] = llx.NilData
	}
	if args["oauth2ClientId"] == nil {
		args["oauth2ClientId"] = llx.NilData
	}
	if args["disabled"] == nil {
		args["disabled"] = llx.NilData
	}
	log.Error().
		Interface("email", lookupEmail).
		Interface("uniqueId", lookupUniqueId).
		Err(errors.New("service account not found")).
		Send()
	return args, nil, nil
}

func (g *mqlGcpProjectIamService) serviceAccounts() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(admin.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	adminSvc, err := admin.NewIamClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer adminSvc.Close()

	var serviceAccounts []any
	it := adminSvc.ListServiceAccounts(ctx, &adminpb.ListServiceAccountsRequest{Name: fmt.Sprintf("projects/%s", projectId)})
	for {
		s, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlSA, err := CreateResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
			"projectId":      llx.StringData(s.ProjectId),
			"name":           llx.StringData(s.Name),
			"uniqueId":       llx.StringData(s.UniqueId),
			"email":          llx.StringData(s.Email),
			"displayName":    llx.StringData(s.DisplayName),
			"description":    llx.StringData(s.Description),
			"oauth2ClientId": llx.StringData(s.Oauth2ClientId),
			"disabled":       llx.BoolData(s.Disabled),
		})
		if err != nil {
			return nil, err
		}
		serviceAccounts = append(serviceAccounts, mqlSA)
	}
	return serviceAccounts, nil
}

func (g *mqlGcpProjectIamServiceServiceAccount) keys() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Email.Error != nil {
		return nil, g.Email.Error
	}
	email := g.Email.Data

	// if the unique id is null, we were not able to find a record of this service account
	// so skip the keys discovery
	if g.UniqueId.IsNull() {
		g.Keys.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(iamrest.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	iamSvc, err := iamrest.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// The keys are read over REST rather than through the admin gRPC client
	// because disableReason and extendedStatus exist only on the REST
	// ServiceAccountKey. The admin protobuf message carries neither, so on the
	// gRPC path a key Google disabled because it found the private key
	// published is indistinguishable from one an operator disabled on purpose.
	//
	// Both transports are governed by iam.serviceAccountKeys.list and return
	// the same key set with the same enum spellings. This endpoint reports every
	// key in one response: ListServiceAccountKeysResponse has no page token, and
	// a service account is capped well below any page limit.
	resp, err := iamSvc.Projects.ServiceAccounts.Keys.
		List(fmt.Sprintf("projects/%s/serviceAccounts/%s", projectId, email)).
		Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	mqlKeys := make([]any, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		if k == nil {
			continue
		}
		mqlKey, err := CreateResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount.key", serviceAccountKeyArgs(k))
		if err != nil {
			return nil, err
		}
		// Back-reference the parent SA so key.lastAuthenticatedTime() can
		// reuse a single batched Policy Analyzer query per SA instead of
		// querying once per key.
		mqlKey.(*mqlGcpProjectIamServiceServiceAccountKey).parentSA = g
		mqlKeys = append(mqlKeys, mqlKey)
	}
	return mqlKeys, nil
}

// serviceAccountKeyArgs maps a service account key onto its MQL resource
// arguments.
//
// extendedStatus is keyed by the detection kind (EXPOSED, COMPROMISE_DETECTED)
// so a query can ask for one directly. An entry with an empty key is dropped
// rather than collapsing into a "" bucket, and the first value wins for a
// repeated key, so the map size is the number of distinct detections reported.
func serviceAccountKeyArgs(k *iamrest.ServiceAccountKey) map[string]*llx.RawData {
	extendedStatus := map[string]any{}
	for _, st := range k.ExtendedStatus {
		if st == nil || st.Key == "" {
			continue
		}
		if _, seen := extendedStatus[st.Key]; seen {
			continue
		}
		extendedStatus[st.Key] = st.Value
	}
	return map[string]*llx.RawData{
		"name":            llx.StringData(k.Name),
		"keyAlgorithm":    llx.StringData(k.KeyAlgorithm),
		"validAfterTime":  llx.TimeDataPtr(parseTime(k.ValidAfterTime)),
		"validBeforeTime": llx.TimeDataPtr(parseTime(k.ValidBeforeTime)),
		"keyOrigin":       llx.StringData(k.KeyOrigin),
		"keyType":         llx.StringData(k.KeyType),
		"userManaged":     llx.BoolData(k.KeyType == "USER_MANAGED"),
		"disabled":        llx.BoolData(k.Disabled),
		"disableReason":   llx.StringData(k.DisableReason),
		"extendedStatus":  llx.MapData(extendedStatus, types.String),
	}
}

// lastAuthActivity matches the JSON shape returned by the Policy Analyzer
// serviceAccountLastAuthentication activity type.
type lastAuthActivity struct {
	ServiceAccount struct {
		ProjectNumber    string `json:"projectNumber"`
		FullResourceName string `json:"fullResourceName"`
	} `json:"serviceAccount"`
	LastAuthenticatedTime string `json:"lastAuthenticatedTime"`
}

func (g *mqlGcpProjectIamServiceServiceAccount) hasUserManagedKeys() (bool, error) {
	keys, err := g.activeUserManagedKeys()
	if err != nil {
		return false, err
	}
	return len(keys) > 0, nil
}

func (g *mqlGcpProjectIamServiceServiceAccount) activeUserManagedKeys() ([]any, error) {
	keys := g.GetKeys()
	if keys.Error != nil {
		return nil, keys.Error
	}
	res := make([]any, 0)
	for _, raw := range keys.Data {
		key, ok := raw.(*mqlGcpProjectIamServiceServiceAccountKey)
		if !ok || key == nil {
			continue
		}
		userManaged := key.GetUserManaged()
		if userManaged.Error != nil {
			return nil, userManaged.Error
		}
		if !userManaged.Data {
			continue
		}
		disabled := key.GetDisabled()
		if disabled.Error != nil {
			return nil, disabled.Error
		}
		if disabled.Data {
			continue
		}
		res = append(res, key)
	}
	return res, nil
}

func (g *mqlGcpProjectIamServiceServiceAccount) lastAuthenticatedTime() (*time.Time, error) {
	// If the SA wasn't found at init time, UniqueId is null; skip the call.
	if g.UniqueId.IsNull() {
		g.LastAuthenticatedTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Email.Error != nil {
		return nil, g.Email.Error
	}
	email := g.Email.Data
	if email == "" {
		g.LastAuthenticatedTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(policyanalyzer.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	paSvc, err := policyanalyzer.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	parent := fmt.Sprintf("projects/%s/locations/global/activityTypes/serviceAccountLastAuthentication", projectId)
	filter := fmt.Sprintf("activities.full_resource_name=\"//iam.googleapis.com/projects/%s/serviceAccounts/%s\"", projectId, email)
	resp, err := paSvc.Projects.Locations.ActivityTypes.Activities.Query(parent).Filter(filter).Context(ctx).Do()
	if err != nil {
		// Gracefully degrade if the Policy Analyzer API is disabled or the
		// caller lacks the policyanalyzer.* permissions.
		if gerr, ok := err.(*googleapi.Error); ok && (gerr.Code == 403 || gerr.Code == 404) {
			log.Debug().Str("email", email).Int("code", gerr.Code).Msg("policyanalyzer lastAuthenticatedTime unavailable")
			g.LastAuthenticatedTime.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var latest *time.Time
	for _, a := range resp.Activities {
		if a == nil || len(a.Activity) == 0 {
			continue
		}
		var parsed lastAuthActivity
		if err := json.Unmarshal(a.Activity, &parsed); err != nil {
			log.Debug().Err(err).Msg("failed to parse lastAuthenticatedTime activity")
			continue
		}
		if parsed.LastAuthenticatedTime == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, parsed.LastAuthenticatedTime)
		if err != nil {
			log.Debug().Err(err).Str("value", parsed.LastAuthenticatedTime).Msg("failed to parse lastAuthenticatedTime timestamp")
			continue
		}
		if latest == nil || t.After(*latest) {
			latest = &t
		}
	}

	if latest == nil {
		g.LastAuthenticatedTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return latest, nil
}

// isDefault reports whether this is a Google-created default service account.
// The default Compute Engine SA has the form
// <projectNumber>-compute@developer.gserviceaccount.com and the default App
// Engine SA has the form <projectId>@appspot.gserviceaccount.com. Both are
// created automatically with broad project-editor permissions.
func (g *mqlGcpProjectIamServiceServiceAccount) isDefault() (bool, error) {
	if g.Email.Error != nil {
		return false, g.Email.Error
	}
	email := g.Email.Data
	if email == "" {
		return false, nil
	}
	if strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") {
		return true, nil
	}
	if strings.HasSuffix(email, "@appspot.gserviceaccount.com") {
		return true, nil
	}
	return false, nil
}

// lastAuthKeyActivity matches the JSON shape returned by the Policy Analyzer
// serviceAccountKeyLastAuthentication activity type.
type lastAuthKeyActivity struct {
	ServiceAccountKey struct {
		ProjectNumber    string `json:"projectNumber"`
		FullResourceName string `json:"fullResourceName"`
	} `json:"serviceAccountKey"`
	LastAuthenticatedTime string `json:"lastAuthenticatedTime"`
}

// fetchKeyLastAuthTimes batch-queries Policy Analyzer for the last-auth
// timestamp of every key on this service account in a single Activities.Query
// call. Returns a map keyed by full key resource name
// (projects/{p}/serviceAccounts/{email}/keys/{keyId}) to the latest auth time
// observed for that key. Subsequent calls return the cached result.
func (g *mqlGcpProjectIamServiceServiceAccount) fetchKeyLastAuthTimes() (map[string]*time.Time, error) {
	g.keyLastAuthOnce.Do(func() {
		g.keyLastAuthMap = map[string]*time.Time{}

		if g.ProjectId.Error != nil {
			g.keyLastAuthErr = g.ProjectId.Error
			return
		}
		if g.Email.Error != nil {
			g.keyLastAuthErr = g.Email.Error
			return
		}
		projectId := g.ProjectId.Data
		email := g.Email.Data
		if email == "" {
			return
		}

		conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
		client, err := conn.Client(policyanalyzer.CloudPlatformScope)
		if err != nil {
			g.keyLastAuthErr = err
			return
		}

		ctx := context.Background()
		paSvc, err := policyanalyzer.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			g.keyLastAuthErr = err
			return
		}

		// The Policy Analyzer key-last-auth filter only supports equality on a
		// single key's full_resource_name, not a service-account-prefix match.
		// To batch the lookup we fetch every key-last-auth activity in the
		// project and filter to this SA's keys client-side; the SA-level
		// sync.Once ensures we only pay for one API call per SA even when many
		// keys' lastAuthenticatedTime is requested.
		parent := fmt.Sprintf("projects/%s/locations/global/activityTypes/serviceAccountKeyLastAuthentication", projectId)
		saPrefix := fmt.Sprintf("//iam.googleapis.com/projects/%s/serviceAccounts/%s/keys/", projectId, email)

		call := paSvc.Projects.Locations.ActivityTypes.Activities.Query(parent).Context(ctx)
		err = call.Pages(ctx, func(resp *policyanalyzer.GoogleCloudPolicyanalyzerV1QueryActivityResponse) error {
			for _, a := range resp.Activities {
				if a == nil || len(a.Activity) == 0 {
					continue
				}
				var parsed lastAuthKeyActivity
				if err := json.Unmarshal(a.Activity, &parsed); err != nil {
					log.Debug().Err(err).Msg("failed to parse key lastAuthenticatedTime activity")
					continue
				}
				if !strings.HasPrefix(parsed.ServiceAccountKey.FullResourceName, saPrefix) {
					continue
				}
				if parsed.LastAuthenticatedTime == "" {
					continue
				}
				t, err := time.Parse(time.RFC3339, parsed.LastAuthenticatedTime)
				if err != nil {
					log.Debug().Err(err).Str("value", parsed.LastAuthenticatedTime).Msg("failed to parse key lastAuthenticatedTime timestamp")
					continue
				}
				// The FRN is "//iam.googleapis.com/{name}" — strip the prefix to
				// match the key resource's `name` field.
				keyName := strings.TrimPrefix(parsed.ServiceAccountKey.FullResourceName, "//iam.googleapis.com/")
				if existing, ok := g.keyLastAuthMap[keyName]; !ok || t.After(*existing) {
					tc := t
					g.keyLastAuthMap[keyName] = &tc
				}
			}
			return nil
		})
		if err != nil {
			if gerr, ok := err.(*googleapi.Error); ok && (gerr.Code == 403 || gerr.Code == 404) {
				log.Debug().Str("email", email).Int("code", gerr.Code).Msg("policyanalyzer key lastAuthenticatedTime unavailable")
				return
			}
			g.keyLastAuthErr = err
		}
	})
	return g.keyLastAuthMap, g.keyLastAuthErr
}

// keyLastAuthFallback queries Policy Analyzer for a single key when the
// batched path through the parent SA is unavailable (typically because the
// key was constructed from a platform-ID asset import and has no back-ref).
func (g *mqlGcpProjectIamServiceServiceAccountKey) keyLastAuthFallback(projectId, keyName string) (*time.Time, error) {
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(policyanalyzer.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	paSvc, err := policyanalyzer.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	parent := fmt.Sprintf("projects/%s/locations/global/activityTypes/serviceAccountKeyLastAuthentication", projectId)
	filter := fmt.Sprintf("activities.full_resource_name=\"//iam.googleapis.com/%s\"", keyName)
	resp, err := paSvc.Projects.Locations.ActivityTypes.Activities.Query(parent).Filter(filter).Context(ctx).Do()
	if err != nil {
		if gerr, ok := err.(*googleapi.Error); ok && (gerr.Code == 403 || gerr.Code == 404) {
			log.Debug().Str("key", keyName).Int("code", gerr.Code).Msg("policyanalyzer key lastAuthenticatedTime unavailable")
			return nil, nil
		}
		return nil, err
	}

	var latest *time.Time
	for _, a := range resp.Activities {
		if a == nil || len(a.Activity) == 0 {
			continue
		}
		var parsed lastAuthKeyActivity
		if err := json.Unmarshal(a.Activity, &parsed); err != nil {
			log.Debug().Err(err).Msg("failed to parse key lastAuthenticatedTime activity")
			continue
		}
		if parsed.LastAuthenticatedTime == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, parsed.LastAuthenticatedTime)
		if err != nil {
			log.Debug().Err(err).Str("value", parsed.LastAuthenticatedTime).Msg("failed to parse key lastAuthenticatedTime timestamp")
			continue
		}
		if latest == nil || t.After(*latest) {
			latest = &t
		}
	}
	return latest, nil
}

func (g *mqlGcpProjectIamServiceServiceAccountKey) lastAuthenticatedTime() (*time.Time, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	keyName := g.Name.Data
	if keyName == "" {
		g.LastAuthenticatedTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Parse projects/{project}/serviceAccounts/{email}/keys/{keyId}.
	parts := strings.Split(keyName, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "serviceAccounts" || parts[4] != "keys" {
		g.LastAuthenticatedTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	projectId := parts[1]

	// Preferred path: reuse the SA's batched Policy Analyzer query.
	if g.parentSA != nil {
		times, err := g.parentSA.fetchKeyLastAuthTimes()
		if err != nil {
			return nil, err
		}
		if t, ok := times[keyName]; ok {
			return t, nil
		}
		g.LastAuthenticatedTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Fallback for keys constructed without a parent SA back-reference (e.g.,
	// from a platform-ID asset import).
	latest, err := g.keyLastAuthFallback(projectId, keyName)
	if err != nil {
		return nil, err
	}
	if latest == nil {
		g.LastAuthenticatedTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return latest, nil
}

// ageInDays returns the whole-day age of the key, computed from validAfterTime
// to the current time. CIS key-rotation audits compare this against a 90-day
// threshold.
func (g *mqlGcpProjectIamServiceServiceAccountKey) ageInDays() (int64, error) {
	if g.ValidAfterTime.Error != nil {
		return 0, g.ValidAfterTime.Error
	}
	if g.ValidAfterTime.IsNull() || g.ValidAfterTime.Data == nil {
		g.AgeInDays.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	age := time.Since(*g.ValidAfterTime.Data)
	return int64(age.Hours() / 24), nil
}

func (g *mqlGcpProjectIamServiceDenyPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectIamService) denyPolicies() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	return listDenyPolicies(g.MqlRuntime, "projects/"+projectId)
}

// denyPolicyParent returns the IAM v2 ListPolicies parent for the deny
// policies attached to a Cloud Resource Manager node.
//
// IAM v2 wants the URL-encoded resource path of the policy's attachment point,
// with its path separators percent-encoded as %2F. For "projects/my-project"
// this yields
// "policies/cloudresourcemanager.googleapis.com%2Fprojects%2Fmy-project/denypolicies".
func denyPolicyParent(attachmentPoint string) string {
	encoded := strings.ReplaceAll("cloudresourcemanager.googleapis.com/"+attachmentPoint, "/", "%2F")
	return "policies/" + encoded + "/denypolicies"
}

// listDenyPolicies lists the deny policies attached to a Cloud Resource
// Manager node: "projects/{id}", "folders/{id}", or "organizations/{id}".
// The policy names embed the attachment point, so policies attached to two
// nodes never share a cache id.
func listDenyPolicies(runtime *plugin.Runtime, attachmentPoint string) ([]any, error) {
	conn := runtime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(iamv2.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := iamv2.NewPoliciesClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	parent := denyPolicyParent(attachmentPoint)

	var policies []any
	it := client.ListPolicies(ctx, &iamv2pb.ListPoliciesRequest{Parent: parent})
	for {
		p, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		rules := make([]any, 0, len(p.Rules))
		for _, r := range p.Rules {
			rule := map[string]any{"description": r.Description}
			if denyRule := r.GetDenyRule(); denyRule != nil {
				rule["deniedPrincipals"] = denyRule.DeniedPrincipals
				rule["exceptionPrincipals"] = denyRule.ExceptionPrincipals
				rule["deniedPermissions"] = denyRule.DeniedPermissions
				rule["exceptionPermissions"] = denyRule.ExceptionPermissions
				if cond := denyRule.DenialCondition; cond != nil {
					rule["denialCondition"] = map[string]any{
						"expression":  cond.Expression,
						"title":       cond.Title,
						"description": cond.Description,
						"location":    cond.Location,
					}
				}
			}
			ruleDict, err := convert.JsonToDict(rule)
			if err != nil {
				return nil, err
			}
			rules = append(rules, ruleDict)
		}

		denyRules, err := newMqlIamDenyRules(runtime, p.Name, p.Rules)
		if err != nil {
			return nil, err
		}

		mqlPolicy, err := CreateResource(runtime, "gcp.project.iamService.denyPolicy", map[string]*llx.RawData{
			"name":        llx.StringData(p.Name),
			"uid":         llx.StringData(p.Uid),
			"displayName": llx.StringData(p.DisplayName),
			"annotations": llx.MapData(convert.MapToInterfaceMap(p.Annotations), types.String),
			"rules":       llx.ArrayData(rules, types.Dict),
			"denyRules":   llx.ArrayData(denyRules, types.Resource("gcp.project.iamService.denyPolicy.denyRule")),
			"etag":        llx.StringData(p.Etag),
			"created":     llx.TimeDataPtr(timestampAsTimePtr(p.CreateTime)),
			"updated":     llx.TimeDataPtr(timestampAsTimePtr(p.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		policies = append(policies, mqlPolicy)
	}
	return policies, nil
}

// denyPolicies on an organization or folder reads the same deny policy type
// as a project. A refusal there is classified rather than failing the query
// with an unattributed error.
func (g *mqlGcpOrganization) denyPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	attachment := organizationResourceName(g.Id.Data)
	res, err := listDenyPolicies(g.MqlRuntime, attachment)
	if err != nil {
		return listRefusal(err, "could not list organization deny policies", "iam.denypolicies.list")
	}
	return res, nil
}

func (g *mqlGcpFolder) denyPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := listDenyPolicies(g.MqlRuntime, folderResourceName(g.Id.Data))
	if err != nil {
		return listRefusal(err, "could not list folder deny policies", "iam.denypolicies.list")
	}
	return res, nil
}

// organizationResourceName returns "organizations/{id}" for an organization
// id given with or without the prefix. gcp.organization carries the prefixed
// form, but a bare number must not be double-prefixed or left bare.
func organizationResourceName(id string) string {
	if strings.HasPrefix(id, "organizations/") {
		return id
	}
	return "organizations/" + id
}

func (g *mqlGcpProjectIamServiceServiceAccount) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Email.Error != nil {
		return nil, g.Email.Error
	}
	projectId := g.ProjectId.Data
	email := g.Email.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(admin.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	adminSvc, err := admin.NewIamClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer adminSvc.Close()

	resource := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectId, email)
	// Request policy schema version 3 so conditional role bindings are returned
	// (version 1 silently omits any binding that carries an IAM condition).
	policy, err := adminSvc.GetIamPolicy(ctx, &iampbv1.GetIamPolicyRequest{
		Resource: resource,
		Options:  &iampbv1.GetPolicyOptions{RequestedPolicyVersion: 3},
	})
	if err != nil {
		// tolerate access-denied: return no bindings rather than failing the whole query
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			return nil, nil
		}
		return nil, err
	}
	if policy == nil || policy.InternalProto == nil {
		return nil, nil
	}
	// Iterate the raw bindings (rather than policy.Roles()/Members()) so IAM
	// conditions attached to each binding are preserved.
	return iampbBindingsToMql(g.MqlRuntime, resource, policy.InternalProto.Bindings)
}

func (g *mqlGcpProjectIamServiceServiceAccount) canBeImpersonated() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	for _, raw := range bindings.Data {
		b, ok := raw.(*mqlGcpResourcemanagerBinding)
		if !ok || b == nil {
			continue
		}
		role := b.GetRole()
		if role.Error != nil {
			return false, role.Error
		}
		switch role.Data {
		case "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser", "roles/iam.workloadIdentityUser":
			members := b.GetMembers()
			if members.Error != nil {
				return false, members.Error
			}
			if len(members.Data) > 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectIamService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_iam)
}

// newMqlIamDenyRules promotes the rules of a deny policy.
//
// A deny rule overrides every allow policy that would otherwise grant the
// permission, so what a principal can actually do is only knowable by reading
// them. PolicyRule carries its rule kind as a oneof and DenyRule is the only
// arm the API populates today; a rule of any other kind is skipped rather than
// published as a deny rule that denies nothing.
func newMqlIamDenyRules(runtime *plugin.Runtime, policyName string, rules []*iamv2pb.PolicyRule) ([]any, error) {
	res := make([]any, 0, len(rules))
	for i, r := range rules {
		if r == nil {
			continue
		}
		denyRule := r.GetDenyRule()
		if denyRule == nil {
			continue
		}

		var expression, title, description, location string
		if cond := denyRule.DenialCondition; cond != nil {
			expression = cond.Expression
			title = cond.Title
			description = cond.Description
			location = cond.Location
		}

		mqlRule, err := CreateResource(runtime, "gcp.project.iamService.denyPolicy.denyRule", map[string]*llx.RawData{
			"__id":                       llx.StringData(policyName + "/rule/" + strconv.Itoa(i)),
			"description":                llx.StringData(r.Description),
			"deniedPrincipals":           llx.ArrayData(convert.SliceAnyToInterface(denyRule.DeniedPrincipals), types.String),
			"exceptionPrincipals":        llx.ArrayData(convert.SliceAnyToInterface(denyRule.ExceptionPrincipals), types.String),
			"deniedPermissions":          llx.ArrayData(convert.SliceAnyToInterface(denyRule.DeniedPermissions), types.String),
			"exceptionPermissions":       llx.ArrayData(convert.SliceAnyToInterface(denyRule.ExceptionPermissions), types.String),
			"denialConditionExpression":  llx.StringData(expression),
			"denialConditionTitle":       llx.StringData(title),
			"denialConditionDescription": llx.StringData(description),
			"denialConditionLocation":    llx.StringData(location),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}
