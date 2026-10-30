// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stmcginnis/gofish/schemas"
)

// ServiceRootPath is the fixed path of the Redfish service root.
const ServiceRootPath = "/redfish/v1/"

// anonymousProbeTimeout bounds the unauthenticated probe. The probe is a single
// GET against a controller that the authenticated client already reached, so a
// short timeout is enough and keeps a hung BMC from stalling a scan.
const anonymousProbeTimeout = 10 * time.Second

// maxRawBody caps how much of a Redfish response body the provider reads. The
// documents the provider parses are a few kilobytes at most, so the cap stops a
// malfunctioning controller from exhausting memory.
const maxRawBody = 8 << 20

// serviceRootAnswersAnonymously reports whether the Redfish service root at
// endpoint answers a request that carries no credentials. It returns true only
// for a 200 response whose body is a JSON object that looks like a service
// root, so a login page or an error document does not count as a disclosure.
func serviceRootAnswersAnonymously(client *http.Client, endpoint string) (bool, error) {
	url := strings.TrimSuffix(endpoint, "/") + ServiceRootPath

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRawBody))
	if err != nil {
		return false, err
	}
	return looksLikeServiceRoot(body), nil
}

// looksLikeServiceRoot reports whether body is a Redfish service root document.
// A controller that rejects anonymous callers can still answer 200 with an
// error payload, so the check requires a field that only the service root
// carries.
func looksLikeServiceRoot(body []byte) bool {
	var root struct {
		ODataID        string `json:"@odata.id"`
		ODataType      string `json:"@odata.type"`
		RedfishVersion string `json:"RedfishVersion"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return false
	}
	if root.RedfishVersion != "" {
		return true
	}
	if strings.Contains(root.ODataType, "ServiceRoot") {
		return true
	}
	return strings.TrimSuffix(root.ODataID, "/") == strings.TrimSuffix(ServiceRootPath, "/")
}

// ServiceRootUnauthenticated reports whether the controller returns its service
// root to a caller that sends no credentials. The result is cached because the
// answer cannot change during a scan.
func (c *RedfishConnection) ServiceRootUnauthenticated() (bool, error) {
	c.anonOnce.Do(func() {
		if c.endpoint == "" {
			c.anonErr = errors.New("no redfish endpoint available")
			return
		}
		client := &http.Client{
			Timeout: anonymousProbeTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: c.insecure}, //nolint:gosec // mirrors the --insecure flag of the authenticated client
			},
			// A redirect to a login page is not a service root, so stop and let
			// the status check reject it.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		c.anon, c.anonErr = serviceRootAnswersAnonymously(client, c.endpoint)
	})
	return c.anon, c.anonErr
}

// ErrNotFound reports that a controller does not serve a Redfish resource.
// Controllers differ in which optional resources they implement, so a caller
// can skip the resource instead of failing the scan.
var ErrNotFound = errors.New("redfish: resource not found")

// GetRaw fetches uri from the management service with the authenticated client
// and returns the response body. It is used where the provider parses the
// Redfish document itself, so it can tell a property the controller reports as
// disabled apart from one the controller does not report at all.
func (c *RedfishConnection) GetRaw(uri string) ([]byte, error) {
	if c.client == nil {
		return nil, errors.New("no redfish client available")
	}
	if uri == "" {
		return nil, errors.New("missing redfish resource uri")
	}

	resp, err := c.client.Get(uri)
	if err != nil {
		return nil, classifyGetError(uri, err)
	}
	defer resp.Body.Close()

	return io.ReadAll(io.LimitReader(resp.Body, maxRawBody))
}

// classifyGetError wraps a GET failure in ErrNotFound when the controller
// answered that it does not serve the resource. gofish turns every non-success
// status into a typed error, so the status has to be read back out of it.
func classifyGetError(uri string, err error) error {
	if redfishErr, ok := errors.AsType[*schemas.Error](err); ok {
		switch redfishErr.HTTPReturnedStatusCode {
		case http.StatusNotFound, http.StatusNotImplemented:
			return fmt.Errorf("%w: GET %s returned status %d: %w", ErrNotFound, uri, redfishErr.HTTPReturnedStatusCode, err)
		}
	}
	return fmt.Errorf("redfish: GET %s failed: %w", uri, err)
}
