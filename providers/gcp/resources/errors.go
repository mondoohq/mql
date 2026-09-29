// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Error classification for the two transports GCP client libraries use.
//
// google.golang.org/api (REST) reports failures as *googleapi.Error carrying an
// HTTP status; cloud.google.com/go (gRPC) reports them as a status.Status
// carrying a codes.Code. The same condition therefore reaches us in two shapes,
// and this file is the single place that maps both onto one vocabulary:
//
//	isServiceDisabled  the API itself is not turned on for this project
//	isSkippable        ... or we lack permission, or it does not exist
//	isInapplicable     ... or the request does not apply in this location
//
// The three are nested, widest last. Pick the narrowest one that is true for
// the call site: every code folded into a "degrade to empty" check is a real
// failure the user will never see.
//
// Both lookups unwrap. A classification has to survive fmt.Errorf("...: %w",
// err), or a caller that wraps for context silently loses its degrade path and
// fails the whole listing instead of returning what it could read.

// serviceDisabledMarkers are the phrases Google returns when an API has not
// been enabled on the project, e.g.
//
//	Cloud Composer API has not been used in project 1234 before or it is
//	disabled. Enable it by visiting ...
//
// The wording varies per service and the capitalization is not stable, so the
// match is case-insensitive.
var serviceDisabledMarkers = []string{
	"has not been used",
	"not enabled",
}

// googleAPIError extracts a *googleapi.Error from err, unwrapping as needed.
//
// The unwrapping matters: a bare err.(*googleapi.Error) assertion misses any
// error a caller wrapped for context, so the degrade path does not fire and a
// permission gap on one sub-resource fails the entire query.
func googleAPIError(err error) (*googleapi.Error, bool) {
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		return gerr, true
	}
	return nil, false
}

// grpcStatusOf extracts a gRPC status from err.
//
// Unlike the googleapi path this does not unwrap by hand, because
// status.FromError does it internally (errors.As on the GRPCStatus interface)
// in the grpc-go we pin. That is a property of the dependency rather than of
// this file, so it is pinned by test rather than trusted: the gRPC cases in
// TestClassifiersSurviveWrapping go through fmt.Errorf("...: %w", err), and a
// downgrade to a grpc-go whose FromError used a bare type assertion would fail
// them here rather than silently stop classifying wrapped errors in production.
//
// The one thing FromError does not handle is nil: it reports (nil, true), so
// guard that first.
func grpcStatusOf(err error) (*status.Status, bool) {
	if err == nil {
		return nil, false
	}
	return status.FromError(err)
}

// saysServiceDisabled matches the not-enabled marker against the rendered
// error, which covers both transports at once: googleapi.Error.Error() embeds
// the API message, and a gRPC status message is rendered the same way.
func saysServiceDisabled(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, marker := range serviceDisabledMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// isServiceDisabled reports whether err means the API itself is not enabled on
// this project.
//
// It deliberately excludes a bare permission denial: a 403 carrying no
// not-enabled marker is a real access problem, and a caller that only wants to
// skip a disabled API should still surface it. Use isSkippable when denial
// should degrade too.
func isServiceDisabled(err error) bool {
	if err == nil {
		return false
	}
	if saysServiceDisabled(err) {
		return true
	}
	if gerr, ok := googleAPIError(err); ok {
		return gerr.Code == http.StatusNotFound
	}
	if s, ok := grpcStatusOf(err); ok {
		return s.Code() == codes.Unimplemented
	}
	return false
}

// isSkippable reports whether err means "this caller cannot see anything here":
// permission was denied, the resource or its parent does not exist, or the API
// is not enabled.
//
// All three mean there is nothing to read rather than that the system is
// broken, so callers log one line and degrade to an empty result instead of
// failing the query. Note what that costs: an empty collection is the most
// dangerous wrong answer for a posture check, because assertions over it pass
// vacuously. Only reach for this where an empty result is genuinely the truth.
func isSkippable(err error) bool {
	if err == nil {
		return false
	}
	if isServiceDisabled(err) {
		return true
	}
	if gerr, ok := googleAPIError(err); ok {
		return gerr.Code == http.StatusForbidden || gerr.Code == http.StatusNotFound
	}
	if s, ok := grpcStatusOf(err); ok {
		switch s.Code() {
		case codes.PermissionDenied, codes.NotFound, codes.Unimplemented:
			return true
		}
	}
	return false
}

// isInapplicable extends isSkippable with the codes GCP uses for "your request
// does not apply here": a regional API not offered in the requested location,
// or a sub-resource the instance's configuration does not have (a Memorystore
// instance on AUTH_DISABLED has no token auth users to list).
//
// Regional services report these as InvalidArgument or FailedPrecondition
// rather than as an empty result, so a fan-out across regions must treat them
// as "nothing here" or one unsupported region fails the whole query.
//
// This is the widest classifier. InvalidArgument in particular can also mean we
// built a malformed request, so prefer isSkippable unless the call really is
// location- or configuration-dependent.
func isInapplicable(err error) bool {
	if err == nil {
		return false
	}
	if isSkippable(err) {
		return true
	}
	if s, ok := grpcStatusOf(err); ok {
		switch s.Code() {
		case codes.InvalidArgument, codes.FailedPrecondition:
			return true
		}
	}
	return false
}

// classifyRefusal maps a refused call onto an ADR 046 error kind, naming the
// permission the call needed. It returns nil when err is not a refusal, so the
// caller returns the error unchanged.
//
// An API that is not enabled is NotApplicable, whichever transport reported
// it: GCP answers a disabled API with a 403 carrying the not-enabled marker.
// Every other 403 or PermissionDenied is Forbidden. A 404 is left alone,
// because on these APIs it is as likely a malformed parent as a real absence.
func classifyRefusal(err error, permissions ...string) error {
	if err == nil {
		return nil
	}
	if saysServiceDisabled(err) {
		return llx.NotApplicable(err)
	}
	if gerr, ok := googleAPIError(err); ok {
		if gerr.Code == http.StatusForbidden {
			return llx.Forbidden(err, llx.WithPermissions(permissions...))
		}
		return nil
	}
	if s, ok := grpcStatusOf(err); ok && s.Code() == codes.PermissionDenied {
		return llx.Forbidden(err, llx.WithPermissions(permissions...))
	}
	return nil
}

// listRefusal is the return path of a list accessor whose call failed. A
// refusal is logged and read as an empty list unless structured errors are
// on, in which case it is returned classified. Anything else is returned as
// is.
func listRefusal(err error, msg string, permissions ...string) ([]any, error) {
	rerr := classifyRefusal(err, permissions...)
	if rerr == nil {
		return nil, err
	}
	if !plugin.StructuredErrors() {
		log.Warn().Err(err).Msg(msg)
		return nil, nil
	}
	return nil, rerr
}
