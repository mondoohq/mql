// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runningSpaceBody is a live entry from
// GET /api/spaces?expand[]=runtime&expand[]=sdk&expand[]=region&expand[]=subdomain
// for enzostvs/deepsite, a running Docker Space with three bound domains.
const runningSpaceBody = `{
  "_id":"67e454cdd4f34388bcd19c38",
  "id":"enzostvs/deepsite",
  "author":"enzostvs",
  "disabled":false,
  "lastModified":"2026-02-06T12:47:43.000Z",
  "likes":16610,
  "private":false,
  "sha":"d4c8bedc29019597fa5dd25cd8a73e875f1ea8b9",
  "subdomain":"enzostvs-deepsite",
  "sdk":"docker",
  "runtime":{
    "stage":"RUNNING",
    "hardware":{"current":"cpu-xl","requested":"cpu-xl"},
    "gcTimeout":172800,
    "replicas":{"current":1,"requested":1},
    "devMode":false,
    "domains":[
      {"domain":"enzostvs-space-generator.hf.space","stage":"READY"},
      {"domain":"deepsite.hf.co","stage":"EXPIRED_CHALLENGE"}
    ],
    "pySpacesVersion":"0.48.2"
  },
  "region":"us",
  "tags":["docker","region:us"],
  "createdAt":"2025-03-26T19:26:05.000Z"
}`

// Every widened Space field has to come off the wire under its real key. A
// mistyped tag on any of them is silent: sdk, region and subdomain read empty,
// and devMode reads as "not enabled" on a Space that has it on.
func TestSpaceDecodeRunning(t *testing.T) {
	var sp Space
	require.NoError(t, json.Unmarshal([]byte(runningSpaceBody), &sp))

	assert.Equal(t, "enzostvs/deepsite", sp.ID)
	assert.Equal(t, "docker", sp.SDK)
	assert.Equal(t, "us", sp.Region)
	assert.Equal(t, "enzostvs-deepsite", sp.Subdomain)
	assert.False(t, sp.Disabled)
	assert.Equal(t, "2025-03-26T19:26:05.000Z", sp.CreatedAt)
	assert.Equal(t, "2026-02-06T12:47:43.000Z", sp.LastModified)
	assert.Equal(t, "d4c8bedc29019597fa5dd25cd8a73e875f1ea8b9", sp.Sha)

	require.NotNil(t, sp.Runtime)
	rt := sp.Runtime
	assert.Equal(t, "RUNNING", rt.Stage)

	require.NotNil(t, rt.Hardware.Current)
	assert.Equal(t, "cpu-xl", *rt.Hardware.Current)
	require.NotNil(t, rt.Hardware.Requested)
	assert.Equal(t, "cpu-xl", *rt.Hardware.Requested)

	require.NotNil(t, rt.Replicas.Current.Count)
	assert.Equal(t, 1, *rt.Replicas.Current.Count)
	assert.False(t, rt.Replicas.Requested.Auto)

	require.NotNil(t, rt.GcTimeout)
	assert.Equal(t, 172800, *rt.GcTimeout)

	// devMode is present and off. The pointer has to be non-nil here, or the
	// resource cannot tell "reported as off" from "never reported".
	require.NotNil(t, rt.DevMode)
	assert.False(t, *rt.DevMode)

	require.Len(t, rt.Domains, 2)
	assert.Equal(t, "enzostvs-space-generator.hf.space", rt.Domains[0].Domain)
	assert.Equal(t, "READY", rt.Domains[0].Stage)
	// A custom domain whose certificate challenge lapsed still appears, with a
	// stage that is not READY.
	assert.Equal(t, "deepsite.hf.co", rt.Domains[1].Domain)
	assert.Equal(t, "EXPIRED_CHALLENGE", rt.Domains[1].Stage)
}

// A Space with developer mode on is the case the field exists for: SSH into the
// running container. Reading it as a plain bool would also produce true here, so
// the paired absent case below is what pins the pointer.
func TestSpaceDecodeDevModeOn(t *testing.T) {
	var rt SpaceRuntime
	require.NoError(t, json.Unmarshal([]byte(`{"stage":"RUNNING","devMode":true}`), &rt))
	require.NotNil(t, rt.DevMode)
	assert.True(t, *rt.DevMode)
}

// A paused Space reports no current hardware, no replica count, no sleep
// timeout, no devMode and no domains. Each has to stay nil rather than collapse
// to a zero value: a zero gcTimeout reads as "sleeps immediately", a false
// devMode reads as "SSH is off", and an empty currentHardware reads as the free
// tier. Changing any of these fields from a pointer to a value type fails here.
func TestSpaceDecodeAbsentOptionals(t *testing.T) {
	// Live shape of a PAUSED Space: hardware.current is explicitly null while
	// requested keeps the configured flavor, and the optional keys are missing.
	const pausedRuntime = `{
	  "stage":"PAUSED",
	  "hardware":{"current":null,"requested":"cpu-basic"},
	  "replicas":{"current":null,"requested":1}
	}`

	var rt SpaceRuntime
	require.NoError(t, json.Unmarshal([]byte(pausedRuntime), &rt))

	assert.Equal(t, "PAUSED", rt.Stage)
	assert.Nil(t, rt.Hardware.Current, "a paused Space runs on no hardware; that is not the free tier")
	require.NotNil(t, rt.Hardware.Requested)
	assert.Equal(t, "cpu-basic", *rt.Hardware.Requested)

	assert.Nil(t, rt.Replicas.Current.Count)
	require.NotNil(t, rt.Replicas.Requested.Count)
	assert.Equal(t, 1, *rt.Replicas.Requested.Count)

	assert.Nil(t, rt.GcTimeout, "an absent gcTimeout must not read as zero seconds")
	assert.Nil(t, rt.DevMode, "an absent devMode must not read as disabled")
	assert.Empty(t, rt.Domains)
}

// A Space list entry with no runtime block at all must leave Runtime nil, so the
// resource resolves the field to null instead of building a zeroed record that
// would report a stopped Space with developer mode off.
func TestSpaceDecodeNoRuntimeBlock(t *testing.T) {
	var sp Space
	require.NoError(t, json.Unmarshal([]byte(`{"id":"acme/app","sdk":"static"}`), &sp))
	assert.Equal(t, "static", sp.SDK)
	assert.Nil(t, sp.Runtime)
}

// The Hub reports a Space that scales itself with the string "auto" where a
// replica count would otherwise be. A *int cannot hold that, and because the
// list decoder abandons the whole array on a decode error, one autoscaling
// Space used to empty the entire collection. Live example:
// black-forest-labs/FLUX.1-dev, "replicas":{"current":3,"requested":"auto"}.
func TestSpaceDecodeAutoscalingReplicas(t *testing.T) {
	const autoRuntime = `{
	  "stage":"RUNNING",
	  "hardware":{"current":"zero-a10g","requested":"zero-a10g"},
	  "replicas":{"current":3,"requested":"auto"}
	}`

	var rt SpaceRuntime
	require.NoError(t, json.Unmarshal([]byte(autoRuntime), &rt))

	require.NotNil(t, rt.Replicas.Current.Count)
	assert.Equal(t, 3, *rt.Replicas.Current.Count)
	assert.False(t, rt.Replicas.Current.Auto)

	assert.Nil(t, rt.Replicas.Requested.Count, "an autoscaling Space has no fixed requested count")
	assert.True(t, rt.Replicas.Requested.Auto)
}

// A whole list must survive one autoscaling Space. Before ReplicaCount this
// input produced zero Spaces and an error blaming the wrapper type.
func TestSpaceListSurvivesAutoscalingEntry(t *testing.T) {
	const body = `[
	  {"id":"acme/plain","runtime":{"stage":"RUNNING","replicas":{"current":1,"requested":1}}},
	  {"id":"acme/auto","runtime":{"stage":"RUNNING","replicas":{"current":3,"requested":"auto"}}},
	  {"id":"acme/third","runtime":{"stage":"SLEEPING"}}
	]`

	var sl SpaceList
	require.NoError(t, json.Unmarshal([]byte(body), &sl))
	require.Len(t, sl.Spaces, 3, "one autoscaling Space must not drop the others")
	assert.Equal(t, "acme/auto", sl.Spaces[1].ID)
	assert.True(t, sl.Spaces[1].Runtime.Replicas.Requested.Auto)
}

// An unfamiliar replica value must degrade that one field rather than fail the
// decode and take every Space in the response with it.
func TestReplicaCountUnknownValueDegradesQuietly(t *testing.T) {
	var rc ReplicaCount
	require.NoError(t, json.Unmarshal([]byte(`"something-new"`), &rc))
	assert.Nil(t, rc.Count)
	assert.False(t, rc.Auto, "only \"auto\" means autoscaling")

	var null ReplicaCount
	require.NoError(t, json.Unmarshal([]byte(`null`), &null))
	assert.Nil(t, null.Count)
	assert.False(t, null.Auto)
}

// A genuinely malformed array must report why the array would not decode, not
// a confusing complaint about the object wrapper it never was.
func TestSpaceListReportsArrayError(t *testing.T) {
	var sl SpaceList
	err := json.Unmarshal([]byte(`[{"id":"acme/one","likes":"not-a-number"}]`), &sl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "likes")
}
