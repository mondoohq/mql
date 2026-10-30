// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	postgresflex "github.com/stackitcloud/stackit-sdk-go/services/postgresflex/v2api"
	redis "github.com/stackitcloud/stackit-sdk-go/services/redis/v2api"
	sqlserverflex "github.com/stackitcloud/stackit-sdk-go/services/sqlserverflex/v2api"
)

// TestFlexBackupArgs pins the Flex backup mapping: the run bounds parse
// from the RFC 3339 strings the API sends, a failed run keeps its error text,
// and an absent end time reads null rather than the zero time.
func TestFlexBackupArgs(t *testing.T) {
	var ok postgresflex.Backup
	if err := json.Unmarshal([]byte(`{"id": "b-1", "name": "daily", "startTime": "2026-09-08T02:00:00Z", "endTime": "2026-09-08T02:07:30Z", "size": 5242880, "labels": ["auto"]}`), &ok); err != nil {
		t.Fatalf("decoding backup: %v", err)
	}
	args := flexBackupArgs("stackit.postgresFlex.instance.backup/i1", &ok, "")
	if args["__id"].Value != "stackit.postgresFlex.instance.backup/i1/b-1" {
		t.Fatalf("__id = %v", args["__id"].Value)
	}
	want := time.Date(2026, 9, 8, 2, 7, 30, 0, time.UTC)
	if got, _ := args["finishedAt"].Value.(*time.Time); got == nil || !got.Equal(want) {
		t.Fatalf("finishedAt = %v, want %v", got, want)
	}
	if args["error"].Value != "" || args["size"].Value != int64(5242880) {
		t.Fatalf("error/size = %v/%v", args["error"].Value, args["size"].Value)
	}

	var failed postgresflex.Backup
	if err := json.Unmarshal([]byte(`{"id": "b-2", "name": "daily", "startTime": "2026-09-09T02:00:00Z", "error": "snapshot timed out"}`), &failed); err != nil {
		t.Fatalf("decoding failed backup: %v", err)
	}
	fargs := flexBackupArgs("base", &failed, "")
	if fargs["error"].Value != "snapshot timed out" {
		t.Fatalf("error = %v", fargs["error"].Value)
	}
	if got, _ := fargs["finishedAt"].Value.(*time.Time); got != nil {
		t.Fatalf("absent endTime = %v, want null", got)
	}
}

// TestSqlServerBackupsFlatten pins the per-database grouping SQL Server Flex
// uses: every backup comes out once, stamped with its database, and a group
// with no backups contributes nothing.
func TestSqlServerBackupsFlatten(t *testing.T) {
	var resp sqlserverflex.ListBackupsResponse
	if err := json.Unmarshal([]byte(`{"databases": [
		{"name": "orders", "backups": [{"id": "o-1", "name": "full"}, {"id": "o-2", "name": "diff"}]},
		{"name": "empty", "backups": []},
		{"name": "users", "backups": [{"id": "u-1", "name": "full"}]}
	]}`), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	flat := sqlServerBackups(resp.GetDatabases())
	if len(flat) != 3 {
		t.Fatalf("flattened %d backups, want 3", len(flat))
	}
	if flat[0].database != "orders" || flat[0].backup.GetId() != "o-1" || flat[2].database != "users" {
		t.Fatalf("flatten order/database wrong: %+v", flat)
	}
	args := flexBackupArgs("base", flat[2].backup, flat[2].database)
	if args["database"].Value != "users" {
		t.Fatalf("database = %v", args["database"].Value)
	}
	if got := sqlServerBackups(nil); len(got) != 0 {
		t.Fatalf("nil groups = %d, want 0", len(got))
	}
}

// TestCfBackupArgs pins the CF-broker backup mapping: the numeric id becomes
// a string, size and downloadable are tri-state, and an absent trigger time
// reads null.
func TestCfBackupArgs(t *testing.T) {
	var b redis.Backup
	if err := json.Unmarshal([]byte(`{"id": 42, "status": "finished", "size": 1024, "downloadable": true, "triggered_at": "2026-09-09T01:00:00Z", "finished_at": "2026-09-09T01:02:00Z"}`), &b); err != nil {
		t.Fatalf("decoding backup: %v", err)
	}
	args := cfBackupArgs("stackit.redis.instance.backup/i1", &b)
	if args["id"].Value != "42" || args["__id"].Value != "stackit.redis.instance.backup/i1/42" {
		t.Fatalf("id = %v, __id = %v", args["id"].Value, args["__id"].Value)
	}
	if args["size"].Value != int64(1024) || args["downloadable"].Value != true {
		t.Fatalf("size/downloadable = %v/%v", args["size"].Value, args["downloadable"].Value)
	}

	var bare redis.Backup
	if err := json.Unmarshal([]byte(`{"id": 7, "status": "running", "finished_at": ""}`), &bare); err != nil {
		t.Fatalf("decoding bare backup: %v", err)
	}
	bargs := cfBackupArgs("base", &bare)
	if bargs["size"].Value != nil || bargs["downloadable"].Value != nil {
		t.Fatalf("absent size/downloadable = %v/%v, want null", bargs["size"].Value, bargs["downloadable"].Value)
	}
	if got, _ := bargs["triggeredAt"].Value.(*time.Time); got != nil {
		t.Fatalf("absent triggered_at = %v, want null", got)
	}
}

// TestCfOfferingArgs pins the offering mapping and the engine-scoped id that
// keeps two versions of the same engine apart; an absent lifecycle reads
// empty, which is what a current version carries.
func TestCfOfferingArgs(t *testing.T) {
	var current, old redis.Offering
	if err := json.Unmarshal([]byte(`{"name": "redis", "version": "7", "latest": true, "description": "", "documentationUrl": "", "imageUrl": "", "quotaCount": 5, "plans": [{"id": "p-1", "name": "stackit-redis-1.2.10-single", "skuName": "redis-single", "free": false, "description": ""}]}`), &current); err != nil {
		t.Fatalf("decoding offering: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"name": "redis", "version": "6", "latest": false, "lifecycle": "deprecated", "description": "", "documentationUrl": "", "imageUrl": "", "quotaCount": 5, "plans": []}`), &old); err != nil {
		t.Fatalf("decoding old offering: %v", err)
	}
	a, b := cfOfferingArgs("base", &current), cfOfferingArgs("base", &old)
	if a["__id"].Value == b["__id"].Value {
		t.Fatalf("two versions share an id: %v", a["__id"].Value)
	}
	if a["latest"].Value != true || a["lifecycle"].Value != "" {
		t.Fatalf("current = latest %v lifecycle %q", a["latest"].Value, a["lifecycle"].Value)
	}
	if b["latest"].Value != false || b["lifecycle"].Value != "deprecated" {
		t.Fatalf("old = latest %v lifecycle %q", b["latest"].Value, b["lifecycle"].Value)
	}
	plans := current.GetPlans()
	p := cfPlanArgs("base/plan", &plans[0])
	if p["id"].Value != "p-1" || p["free"].Value != false || p["skuName"].Value != "redis-single" {
		t.Fatalf("plan = %v", p)
	}
}

// fakeOffering and fakePlan stand in for an engine's offering and plan
// resources in the index test, since the index only reads the two
// catalog interfaces.
type fakeOffering struct {
	version string
	plans   []any
}

func (f *fakeOffering) offeringVersion() string { return f.version }
func (f *fakeOffering) offeringPlans() []any    { return f.plans }

type fakePlan struct{ id string }

func (f *fakePlan) planID() string { return f.id }

// TestDbaasOfferingIndex pins the catalog index the instance offering() and
// plan() edges resolve through: one build for many lookups, first offering
// wins on a duplicate version, unknown versions and plans miss, and a failed
// catalog read is memoized rather than retried.
func TestDbaasOfferingIndex(t *testing.T) {
	calls := 0
	list := func() ([]any, error) {
		calls++
		return []any{
			&fakeOffering{version: "7", plans: []any{&fakePlan{id: "p-7a"}, &fakePlan{id: "p-7b"}}},
			&fakeOffering{version: "6", plans: []any{&fakePlan{id: "p-6"}}},
			&fakeOffering{version: "7", plans: []any{&fakePlan{id: "p-dup"}}},
			"not an offering",
		}, nil
	}
	var idx dbaasOfferingIndex
	byVersion, byPlan, err := idx.build(list)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, _, err := idx.build(list); err != nil || calls != 1 {
		t.Fatalf("second build re-listed (calls=%d, err=%v)", calls, err)
	}
	if o, ok := byVersion["7"].(*fakeOffering); !ok || len(o.plans) != 2 {
		t.Fatalf("version 7 = %+v, want the first offering with two plans", byVersion["7"])
	}
	if _, ok := byVersion["5"]; ok {
		t.Fatal("unknown version must miss")
	}
	for _, id := range []string{"p-7a", "p-7b", "p-6", "p-dup"} {
		if _, ok := byPlan[id]; !ok {
			t.Fatalf("plan %s missing from index", id)
		}
	}
	if _, ok := byPlan["p-x"]; ok {
		t.Fatal("unknown plan must miss")
	}

	failing := 0
	var bad dbaasOfferingIndex
	fail := func() ([]any, error) { failing++; return nil, errTest }
	if _, _, err := bad.build(fail); err == nil {
		t.Fatal("failed list must surface its error")
	}
	if _, _, err := bad.build(fail); err == nil || failing != 1 {
		t.Fatalf("failure not memoized (calls=%d, err=%v)", failing, err)
	}
}

// errTest is a sentinel for tests that need a failing call.
var errTest = errors.New("test failure")
