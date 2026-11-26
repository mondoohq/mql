// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"go.mondoo.com/mql/llx"
)

var (
	// ErrTrustRootExpired is a cached trust root past its expiry that could
	// not be refreshed.
	ErrTrustRootExpired = errors.New("the Sigstore trust root has expired and could not be refreshed")
	// ErrTrustRootRollback is a trust root older than one already used on
	// this machine, or older than the root embedded in the caller.
	ErrTrustRootRollback = errors.New("the Sigstore trust root is older than one already trusted")
	// ErrNoTrustRoot is no trust root at all: none configured, none ever
	// fetched, none embedded, and the TUF repository unreachable.
	ErrNoTrustRoot = errors.New("no Sigstore trust root is available")
	// ErrIndexSubject is a verification asked of an image index digest. An
	// index is never a subject; each platform manifest is verified.
	ErrIndexSubject = errors.New("the subject is an image index; verify each platform manifest digest")
)

// classifyRegistry gives a registry or network failure its error kind. A
// refusal is Forbidden or Unauthenticated, a registry or log that cannot be
// reached is Unavailable, and anything else is returned as is.
func classifyRegistry(err error) error {
	if err == nil {
		return nil
	}
	if llx.KindOf(err) != llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		return err
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		switch {
		case terr.StatusCode == http.StatusUnauthorized:
			return llx.Unauthenticated(err)
		case terr.StatusCode == http.StatusForbidden:
			return llx.Forbidden(err)
		case terr.StatusCode == http.StatusTooManyRequests:
			return llx.TooManyRequests(err)
		case terr.StatusCode >= 500:
			return llx.Unavailable(err)
		}
		for _, d := range terr.Errors {
			switch d.Code {
			case transport.UnauthorizedErrorCode:
				return llx.Unauthenticated(err)
			case transport.DeniedErrorCode:
				return llx.Forbidden(err)
			}
		}
		return err
	}
	if isNetwork(err) {
		return llx.Unavailable(err)
	}
	return err
}

// isNetwork reports a failure to reach the other side.
func isNetwork(err error) bool {
	var nerr net.Error
	var uerr *url.Error
	var operr *net.OpError
	return errors.As(err, &nerr) || errors.As(err, &uerr) || errors.As(err, &operr) ||
		errors.Is(err, context.DeadlineExceeded)
}

// isNotFound reports a registry answering that a manifest or tag does not
// exist: a genuine absence.
func isNotFound(err error) bool {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return false
	}
	if terr.StatusCode == http.StatusNotFound {
		return true
	}
	for _, d := range terr.Errors {
		if d.Code == transport.ManifestUnknownErrorCode || d.Code == transport.NameUnknownErrorCode {
			return true
		}
	}
	return false
}
