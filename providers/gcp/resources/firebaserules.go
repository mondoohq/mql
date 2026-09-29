// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/firebaserules/v1"
	"google.golang.org/api/option"
)

const (
	firebaseRulesServiceFirestore = "cloud.firestore"
	firebaseRulesServiceStorage   = "firebase.storage"
)

type mqlGcpProjectFirebaseRulesServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) firebaseRules() (*mqlGcpProjectFirebaseRulesService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	serviceEnabled, err := g.isServiceEnabled(service_firebaserules)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.firebaseRulesService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlGcpProjectFirebaseRulesService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_firebaserules).Msg("gcp service is not enabled, skipping")
	}
	return svc, nil
}

func initGcpProjectFirebaseRulesService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectFirebaseRulesService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.firebaseRulesService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectFirebaseRulesService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_firebaserules)
}

// firebaseRulesHTTPClient returns the authenticated HTTP client for the API. Each caller
// constructs its own service from it, inline, so the permission extractor can
// trace the calls made on it.
func firebaseRulesHTTPClient(runtime *plugin.Runtime) (*http.Client, error) {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return conn.Client(firebaserules.CloudPlatformScope)
}

// firebaseReleaseTarget is what a release protects, read from its name.
type firebaseReleaseTarget struct {
	// service is cloud.firestore, firebase.storage, or "" for any other name.
	service string
	// database is the Firestore database id, "(default)" for a bare
	// cloud.firestore release.
	database string
	// bucket is the Cloud Storage bucket name.
	bucket string
}

// parseFirebaseReleaseName derives the target of a release from its name.
//
// Firebase names releases by convention: "projects/{p}/releases/cloud.firestore"
// for the default Firestore database, ".../releases/cloud.firestore/{database}"
// for a named one, and ".../releases/firebase.storage/{bucket}" for a Cloud
// Storage bucket. Any other release name targets nothing this knows about.
func parseFirebaseReleaseName(name string) firebaseReleaseTarget {
	_, rest, ok := strings.Cut(name, "/releases/")
	if !ok {
		return firebaseReleaseTarget{}
	}
	switch {
	case rest == firebaseRulesServiceFirestore:
		return firebaseReleaseTarget{service: firebaseRulesServiceFirestore, database: "(default)"}
	case strings.HasPrefix(rest, firebaseRulesServiceFirestore+"/"):
		db := strings.TrimPrefix(rest, firebaseRulesServiceFirestore+"/")
		if db == "" || strings.Contains(db, "/") {
			return firebaseReleaseTarget{}
		}
		return firebaseReleaseTarget{service: firebaseRulesServiceFirestore, database: db}
	case strings.HasPrefix(rest, firebaseRulesServiceStorage+"/"):
		bucket := strings.TrimPrefix(rest, firebaseRulesServiceStorage+"/")
		if bucket == "" || strings.Contains(bucket, "/") {
			return firebaseReleaseTarget{}
		}
		return firebaseReleaseTarget{service: firebaseRulesServiceStorage, bucket: bucket}
	}
	return firebaseReleaseTarget{}
}

type mqlGcpProjectFirebaseRulesServiceReleaseInternal struct {
	cacheProjectId   string
	cacheRulesetName string
	cacheTarget      firebaseReleaseTarget
}

func (g *mqlGcpProjectFirebaseRulesServiceRelease) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectFirebaseRulesService) releases() ([]any, error) {
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
	httpClient, err := firebaseRulesHTTPClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := firebaserules.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	res := []any{}
	err = svc.Projects.Releases.List("projects/"+projectId).Pages(context.Background(), func(page *firebaserules.ListReleasesResponse) error {
		for _, r := range page.Releases {
			if r == nil {
				continue
			}
			target := parseFirebaseReleaseName(r.Name)
			mqlRelease, err := CreateResource(g.MqlRuntime, "gcp.project.firebaseRulesService.release", map[string]*llx.RawData{
				"name":    llx.StringData(r.Name),
				"service": llx.StringData(target.service),
				"created": llx.TimeDataPtr(parseTime(r.CreateTime)),
				"updated": llx.TimeDataPtr(parseTime(r.UpdateTime)),
			})
			if err != nil {
				return err
			}
			ref := mqlRelease.(*mqlGcpProjectFirebaseRulesServiceRelease)
			ref.cacheProjectId = projectId
			ref.cacheRulesetName = r.RulesetName
			ref.cacheTarget = target
			res = append(res, mqlRelease)
		}
		return nil
	})
	if err != nil {
		return listRefusal(err, "could not list Firebase Rules releases", "firebaserules.releases.list")
	}
	return res, nil
}

func (g *mqlGcpProjectFirebaseRulesServiceRelease) ruleset() (*mqlGcpProjectFirebaseRulesServiceRuleset, error) {
	if g.cacheRulesetName == "" {
		g.Ruleset.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	httpClient, err := firebaseRulesHTTPClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := firebaserules.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	rs, err := svc.Projects.Rulesets.Get(g.cacheRulesetName).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "firebaserules.rulesets.get"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	mqlRuleset, err := newMqlFirebaseRuleset(g.MqlRuntime, rs)
	if err != nil {
		return nil, err
	}
	// A ruleset already created from the list carries no source yet; hand it
	// the one just read so files does not fetch it a second time.
	mqlRuleset.seed(rs)
	return mqlRuleset, nil
}

func (g *mqlGcpProjectFirebaseRulesServiceRelease) database() (*mqlGcpProjectFirestoreServiceDatabase, error) {
	if g.cacheTarget.service != firebaseRulesServiceFirestore || g.cacheTarget.database == "" {
		g.Database.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// Match against the project's cached database list rather than the
	// database init, which fails outright for a database that does not
	// exist. Rules released for a database that was never created, or has
	// been deleted, protect nothing, and read as null.
	obj, err := CreateResource(g.MqlRuntime, "gcp.project.firestoreService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.cacheProjectId),
	})
	if err != nil {
		return nil, err
	}
	databases := obj.(*mqlGcpProjectFirestoreService).GetDatabases()
	if databases.Error != nil {
		return nil, databases.Error
	}
	for _, d := range databases.Data {
		db, ok := d.(*mqlGcpProjectFirestoreServiceDatabase)
		if ok && lastPathSegment(db.Name.Data) == g.cacheTarget.database {
			return db, nil
		}
	}
	g.Database.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (g *mqlGcpProjectFirebaseRulesServiceRelease) bucket() (*mqlGcpProjectStorageServiceBucket, error) {
	if g.cacheTarget.service != firebaseRulesServiceStorage || g.cacheTarget.bucket == "" {
		g.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.storageService.bucket", map[string]*llx.RawData{
		"name":      llx.StringData(g.cacheTarget.bucket),
		"projectId": llx.StringData(g.cacheProjectId),
	})
	if err != nil {
		// Rules released for a bucket that no longer exists protect nothing.
		if gerr, ok := googleAPIError(err); ok && gerr.Code == http.StatusNotFound {
			g.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlGcpProjectStorageServiceBucket), nil
}

// Rulesets

type mqlGcpProjectFirebaseRulesServiceRulesetInternal struct {
	lock          sync.Mutex
	fetched       bool
	cacheFiles    []any
	cacheServices []any
}

func (g *mqlGcpProjectFirebaseRulesServiceRuleset) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func newMqlFirebaseRuleset(runtime *plugin.Runtime, rs *firebaserules.Ruleset) (*mqlGcpProjectFirebaseRulesServiceRuleset, error) {
	res, err := CreateResource(runtime, "gcp.project.firebaseRulesService.ruleset", map[string]*llx.RawData{
		"name":    llx.StringData(rs.Name),
		"created": llx.TimeDataPtr(parseTime(rs.CreateTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectFirebaseRulesServiceRuleset), nil
}

func (g *mqlGcpProjectFirebaseRulesService) rulesets() ([]any, error) {
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
	httpClient, err := firebaseRulesHTTPClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := firebaserules.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	res := []any{}
	err = svc.Projects.Rulesets.List("projects/"+g.ProjectId.Data).Pages(context.Background(), func(page *firebaserules.ListRulesetsResponse) error {
		for _, rs := range page.Rulesets {
			if rs == nil {
				continue
			}
			mqlRuleset, err := newMqlFirebaseRuleset(g.MqlRuntime, rs)
			if err != nil {
				return err
			}
			res = append(res, mqlRuleset)
		}
		return nil
	})
	if err != nil {
		return listRefusal(err, "could not list Firebase Rules rulesets", "firebaserules.rulesets.list")
	}
	return res, nil
}

// firebaseRulesetFiles maps a ruleset's source onto the documented file dicts.
func firebaseRulesetFiles(rs *firebaserules.Ruleset) []any {
	files := []any{}
	if rs == nil || rs.Source == nil {
		return files
	}
	for _, f := range rs.Source.Files {
		if f == nil {
			continue
		}
		files = append(files, map[string]any{
			"name":        f.Name,
			"content":     f.Content,
			"fingerprint": f.Fingerprint,
		})
	}
	return files
}

func firebaseRulesetServices(rs *firebaserules.Ruleset) []any {
	if rs == nil || rs.Metadata == nil {
		return []any{}
	}
	return convert.SliceAnyToInterface(rs.Metadata.Services)
}

// seed stores a ruleset read with its source, unless one was stored already.
func (g *mqlGcpProjectFirebaseRulesServiceRuleset) seed(rs *firebaserules.Ruleset) {
	g.lock.Lock()
	defer g.lock.Unlock()
	if g.fetched {
		return
	}
	g.cacheFiles = firebaseRulesetFiles(rs)
	g.cacheServices = firebaseRulesetServices(rs)
	g.fetched = true
}

// fetch reads the ruleset's source. The list call returns rulesets without
// it, so it is read once per ruleset, on demand, and feeds both files and
// services.
func (g *mqlGcpProjectFirebaseRulesServiceRuleset) fetch() error {
	g.lock.Lock()
	defer g.lock.Unlock()
	if g.fetched {
		return nil
	}
	if g.Name.Error != nil {
		return g.Name.Error
	}
	httpClient, err := firebaseRulesHTTPClient(g.MqlRuntime)
	if err != nil {
		return err
	}
	svc, err := firebaserules.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return err
	}
	rs, err := svc.Projects.Rulesets.Get(g.Name.Data).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "firebaserules.rulesets.get"); rerr != nil {
			return rerr
		}
		return err
	}
	g.cacheFiles = firebaseRulesetFiles(rs)
	g.cacheServices = firebaseRulesetServices(rs)
	g.fetched = true
	return nil
}

func (g *mqlGcpProjectFirebaseRulesServiceRuleset) files() ([]any, error) {
	if err := g.fetch(); err != nil {
		return nil, err
	}
	return g.cacheFiles, nil
}

func (g *mqlGcpProjectFirebaseRulesServiceRuleset) services() ([]any, error) {
	if err := g.fetch(); err != nil {
		return nil, err
	}
	return g.cacheServices, nil
}
