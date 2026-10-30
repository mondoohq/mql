// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const maxStoredResponseProbeBody = 8 << 10

// StoredResponseObservation is the verdict on whether the per-response
// retrieval route answers an unauthenticated caller.
//
// vLLM retains the responses created through /v1/responses server-side, so a
// readable /v1/responses/{id} hands one caller's prompts and completions to
// another. The probe addresses the route with a synthetic identifier that
// cannot name a real response, so it distinguishes "the handler answered me"
// from "authentication stopped me" without ever reading stored content.
type StoredResponseObservation struct {
	// Readable is true when the retrieval handler answered an anonymous
	// request. Known is false when nothing could be concluded, so the caller
	// renders null rather than a "not exposed" that was never observed.
	Readable bool
	Known    bool
	// StatusCode is the status the anonymous probe received, if any.
	StatusCode *int
	// Note explains the verdict in the terms the probe observed.
	Note string
}

// StoredResponses probes the stored-response retrieval route once per
// connection.
func (c *VllmConnection) StoredResponses(ctx context.Context) (StoredResponseObservation, error) {
	c.storedResponsesOnce.Do(func() {
		resp, err := c.Request(ctx, http.MethodGet, StoredResponsePath, false, "")
		if err != nil {
			c.storedResponses = StoredResponseObservation{Note: "anonymous probe error: " + err.Error()}
			c.storedResponsesErr = err
			return
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxStoredResponseProbeBody))
		if readErr != nil {
			body = nil
		}
		c.storedResponses = ClassifyStoredResponseProbe(resp.StatusCode, body)
	})
	return c.storedResponses, c.storedResponsesErr
}

// ClassifyStoredResponseProbe turns the status and body of the synthetic-id
// retrieval probe into a verdict.
//
// The body is inspected only to tell two 404s apart: the router's "no such
// route" and the handler's "no such response". It is never retained, and
// because the probed identifier is synthetic, the handler's message can only
// ever echo the identifier the probe itself supplied.
func ClassifyStoredResponseProbe(status int, body []byte) StoredResponseObservation {
	obs := StoredResponseObservation{StatusCode: &status}

	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		obs.Known = true
		obs.Note = "anonymous retrieval was rejected by an authentication-like response"
		return obs
	case status >= 500:
		obs.Note = "server error left stored-response exposure undetermined"
		return obs
	case status == http.StatusNotFound:
		if isStoredResponseHandlerError(body) {
			obs.Readable = true
			obs.Known = true
			obs.Note = "the retrieval handler answered an anonymous request, so stored responses are readable without credentials"
			return obs
		}
		obs.Known = true
		obs.Note = "the stored-response retrieval route is not registered"
		return obs
	case status >= 200 && status < 300:
		obs.Readable = true
		obs.Known = true
		obs.Note = "the retrieval handler answered an anonymous request"
		return obs
	case status == http.StatusMethodNotAllowed:
		obs.Known = true
		obs.Note = "the path is registered but rejected the retrieval method"
		return obs
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		// Reaching vLLM's own request validation means the route answered an
		// anonymous caller rather than turning it away.
		obs.Readable = true
		obs.Known = true
		obs.Note = "the anonymous request reached route validation"
		return obs
	default:
		// Anything else does not show that the retrieval handler answered. A
		// 3xx is typically a proxy redirecting to a login page, and 408 or 429
		// come from in front of the handler, not from it. Treating those as
		// readable would report exposure on a server that never served the
		// route, so the verdict stays undetermined.
		obs.Note = "the response did not show whether the retrieval route answered"
		return obs
	}
}

// isStoredResponseHandlerError reports whether a 404 body came from vLLM's
// responses handler rather than from the router. The handler answers with an
// OpenAI-shaped error naming response_id; the router answers with FastAPI's
// bare {"detail": "Not Found"}.
func isStoredResponseHandlerError(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	// Current releases nest the error; older ones render it flat.
	var nested struct {
		Error *struct {
			Type  string `json:"type"`
			Param string `json:"param"`
		} `json:"error"`
		Object string `json:"object"`
		Type   string `json:"type"`
		Param  string `json:"param"`
	}
	if err := json.Unmarshal(body, &nested); err != nil {
		return false
	}
	if nested.Error != nil {
		return matchesResponseIDError(nested.Error.Type, nested.Error.Param)
	}
	if nested.Object == "error" {
		return true
	}
	return matchesResponseIDError(nested.Type, nested.Param)
}

func matchesResponseIDError(errType string, param string) bool {
	if strings.EqualFold(param, "response_id") {
		return true
	}
	return strings.EqualFold(errType, "invalid_request_error")
}
