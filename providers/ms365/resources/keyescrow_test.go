// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	kjson "github.com/microsoft/kiota-serialization-json-go"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// A LAPS list response as documented by Graph, plus a credentials array that
// a $select=credentials response would carry. The mapping must not pick the
// password up even if Graph ever returned it unasked.
const lapsListJSON = `{
  "value": [
    {
      "id": "b465e4e8-e4e8-b465-e8e4-65b4e8e465b4",
      "deviceName": "LAPS_TEST",
      "lastBackupDateTime": "2026-09-01T10:00:00Z",
      "refreshDateTime": "2026-10-01T10:00:00Z",
      "credentials": [
        {"accountName": "Administrator", "accountSid": "S-1-5-21", "backupDateTime": "2026-09-01T10:00:00Z", "passwordBase64": "EXAMPLE-FAKE-VALUE"}
      ]
    },
    {
      "id": "c565e4e8-e4e8-b465-e8e4-65b4e8e465b5",
      "deviceName": "NEVER_ROTATED"
    }
  ]
}`

const bitlockerListJSON = `{
  "value": [
    {
      "id": "b465e4e8-e4e8-4e8e-b465-e8e465b4e8e4",
      "createdDateTime": "2026-08-15T12:30:00Z",
      "volumeType": "operatingSystemVolume",
      "deviceId": "1ab40ab2-32a8-4b00-b828-6e4e7b4b4c3f",
      "key": "123456-123456-123456-123456-123456-123456-123456-123456"
    },
    {
      "id": "f2a6e3c1-0000-4e8e-b465-e8e465b4e8e5",
      "volumeType": "fixedDataVolume",
      "deviceId": "1ab40ab2-32a8-4b00-b828-6e4e7b4b4c3f"
    },
    {
      "id": "a1b2c3d4-0000-4e8e-b465-e8e465b4e8e6",
      "volumeType": "somethingNew"
    }
  ]
}`

func parseLapsList(t *testing.T) []models.DeviceLocalCredentialInfoable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(lapsListJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDeviceLocalCredentialInfoCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.DeviceLocalCredentialInfoCollectionResponseable).GetValue()
}

func parseBitlockerList(t *testing.T) []models.BitlockerRecoveryKeyable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(bitlockerListJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateBitlockerRecoveryKeyCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.BitlockerRecoveryKeyCollectionResponseable).GetValue()
}

func TestDeviceLocalCredentialArgs(t *testing.T) {
	infos := parseLapsList(t)
	require.Len(t, infos, 2)

	args := deviceLocalCredentialArgs(infos[0])
	assert.Equal(t, "b465e4e8-e4e8-b465-e8e4-65b4e8e465b4", rawString(t, args, "id"))
	assert.Equal(t, "microsoft.deviceLocalCredential/b465e4e8-e4e8-b465-e8e4-65b4e8e465b4", rawString(t, args, "__id"))
	assert.Equal(t, "LAPS_TEST", rawString(t, args, "deviceName"))
	assert.Equal(t, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), args["lastBackupDateTime"].Value.(*time.Time).UTC())
	assert.Equal(t, time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC), args["refreshDateTime"].Value.(*time.Time).UTC())
	assert.ElementsMatch(t, []string{"__id", "id", "deviceName", "lastBackupDateTime", "refreshDateTime"}, escrowArgKeys(args))
	for k, v := range args {
		assert.NotContains(t, fmt.Sprint(v.Value), "EXAMPLE-FAKE-VALUE", "argument %q carries the password", k)
	}

	// absent timestamps stay null rather than year 1
	missing := deviceLocalCredentialArgs(infos[1])
	assert.Nil(t, missing["lastBackupDateTime"].Value)
	assert.Nil(t, missing["refreshDateTime"].Value)
}

func TestBitlockerRecoveryKeyArgs(t *testing.T) {
	keys := parseBitlockerList(t)
	require.Len(t, keys, 3)

	args := bitlockerRecoveryKeyArgs(keys[0])
	assert.Equal(t, "b465e4e8-e4e8-4e8e-b465-e8e465b4e8e4", rawString(t, args, "id"))
	assert.Equal(t, "microsoft.bitlockerRecoveryKey/b465e4e8-e4e8-4e8e-b465-e8e465b4e8e4", rawString(t, args, "__id"))
	assert.Equal(t, "1ab40ab2-32a8-4b00-b828-6e4e7b4b4c3f", rawString(t, args, "deviceId"))
	assert.Equal(t, "operatingSystemVolume", rawString(t, args, "volumeType"))
	assert.Equal(t, time.Date(2026, 8, 15, 12, 30, 0, 0, time.UTC), args["createdDateTime"].Value.(*time.Time).UTC())
	assert.ElementsMatch(t, []string{"__id", "id", "createdDateTime", "deviceId", "volumeType"}, escrowArgKeys(args))
	for k, v := range args {
		assert.NotContains(t, fmt.Sprint(v.Value), "123456-123456", "argument %q carries the recovery key", k)
	}

	assert.Equal(t, "fixedDataVolume", rawString(t, bitlockerRecoveryKeyArgs(keys[1]), "volumeType"))
	assert.Nil(t, bitlockerRecoveryKeyArgs(keys[1])["createdDateTime"].Value)

	// an enum value the SDK does not know must be null, not the zero value
	// operatingSystemVolume, and an absent deviceId stays null
	unknown := bitlockerRecoveryKeyArgs(keys[2])
	assert.Nil(t, unknown["volumeType"].Value)
	assert.Nil(t, unknown["deviceId"].Value)
}

func TestClassifyGraphError_Escrow(t *testing.T) {
	forbidden := odataerrors.NewODataError()
	forbidden.ResponseStatusCode = http.StatusForbidden
	err := classifyGraphError(forbidden, permBitlockerReadBasic)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	var lerr *llx.Error
	require.True(t, errors.As(err, &lerr))
	assert.Equal(t, []string{permBitlockerReadBasic}, lerr.Permissions)

	// a refusal that already went through transformError still classifies
	wrapped := classifyGraphError(&graphRequestError{msg: "denied", cause: forbidden}, permLapsReadBasic)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(wrapped))

	notFound := odataerrors.NewODataError()
	notFound.ResponseStatusCode = http.StatusNotFound
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyGraphError(notFound, permLapsReadBasic)))

	transport := errors.New("dial tcp: connection refused")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyGraphError(transport, permLapsReadBasic)))
	assert.NoError(t, classifyGraphError(nil, permLapsReadBasic))
}

func escrowArgKeys(m map[string]*llx.RawData) []string {
	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	return res
}

// escrowServer serves canned pages keyed by path and records every query
// string it receives, so a test can prove no request asked for secrets.
type escrowServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	queries []string
}

func newEscrowServer(t *testing.T, routes map[string]fakeRoute) *escrowServer {
	e := &escrowServer{}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.queries = append(e.queries, r.URL.RawQuery)
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		route, ok := routes[strings.TrimPrefix(r.URL.Path, "/v1.0")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`))
			return
		}
		w.WriteHeader(route.status)
		_, _ = w.Write([]byte(strings.ReplaceAll(route.body, "{{base}}", e.srv.URL+"/v1.0")))
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *escrowServer) client(t *testing.T) *msgraphsdkgo.GraphServiceClient {
	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(t, err)
	adapter.SetBaseUrl(e.srv.URL + "/v1.0")
	return msgraphsdkgo.NewGraphServiceClient(adapter)
}

func TestFetchKeyEscrow_PagesWithoutRequestingSecrets(t *testing.T) {
	e := newEscrowServer(t, map[string]fakeRoute{
		"/directory/deviceLocalCredentials": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/directory/deviceLocalCredentials/page2",
			"value": [{"id": "dev-1", "deviceName": "PC-1"}]}`},
		"/directory/deviceLocalCredentials/page2": {status: 200, body: `{
			"value": [{"id": "dev-2", "deviceName": "PC-2"}]}`},
		"/informationProtection/bitlocker/recoveryKeys": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/informationProtection/bitlocker/recoveryKeys/page2",
			"value": [{"id": "key-1", "deviceId": "dev-1", "volumeType": "operatingSystemVolume"}]}`},
		"/informationProtection/bitlocker/recoveryKeys/page2": {status: 200, body: `{
			"value": [{"id": "key-2", "deviceId": "dev-1", "volumeType": "fixedDataVolume"}]}`},
	})
	ctx := context.Background()

	creds, err := fetchDeviceLocalCredentials(ctx, e.client(t))
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "PC-2", *creds[1].GetDeviceName())

	keys, err := fetchBitlockerRecoveryKeys(ctx, e.client(t))
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, "key-2", *keys[1].GetId())

	e.mu.Lock()
	defer e.mu.Unlock()
	require.Len(t, e.queries, 4)
	for _, q := range e.queries {
		assert.NotContains(t, strings.ToLower(q), "select", "an escrow request must not use $select")
	}
}

func TestFetchKeyEscrow_RefusalIsForbidden(t *testing.T) {
	denied := fakeRoute{status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}`}
	e := newEscrowServer(t, map[string]fakeRoute{
		"/directory/deviceLocalCredentials":             denied,
		"/informationProtection/bitlocker/recoveryKeys": denied,
	})
	ctx := context.Background()

	_, err := fetchDeviceLocalCredentials(ctx, e.client(t))
	var lerr *llx.Error
	require.True(t, errors.As(err, &lerr), "got %v", err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, lerr.Kind)
	assert.Equal(t, []string{permLapsReadBasic}, lerr.Permissions)

	_, err = fetchBitlockerRecoveryKeys(ctx, e.client(t))
	require.True(t, errors.As(err, &lerr), "got %v", err)
	assert.Equal(t, []string{permBitlockerReadBasic}, lerr.Permissions)
}
