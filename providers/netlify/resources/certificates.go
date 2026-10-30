// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
)

// sniCertificateRecord is the TLS certificate Netlify serves for a site. The
// endpoint answers for one site, so it is read once per site and shared by
// every certificate field rather than once per field.
type sniCertificateRecord struct {
	State     string      `json:"state"`
	Domains   []string    `json:"domains"`
	CreatedAt netlifyTime `json:"created_at"`
	UpdatedAt netlifyTime `json:"updated_at"`
	ExpiresAt netlifyTime `json:"expires_at"`
}

// certificate reads the site's TLS certificate, once for the whole site.
//
// A site with no certificate provisioned answers 404, and a token that cannot
// administer the site answers 403. Both yield a nil record, which every caller
// reports as null: a site whose certificate could not be read has not been
// shown to be without one.
func (s *mqlNetlifySite) certificate() (*sniCertificateRecord, error) {
	s.certOnce.Do(func() {
		c := netlifyConn(s.MqlRuntime)

		var rec sniCertificateRecord
		err := c.Get(context.Background(), "/sites/"+url.PathEscape(s.Id.Data)+"/ssl", nil, &rec)
		if err != nil {
			if connection.IsNotFound(err) || connection.IsForbidden(err) {
				return
			}
			s.certErr = err
			return
		}
		s.cert = &rec
	})
	return s.cert, s.certErr
}

func (s *mqlNetlifySite) certificateState() (string, error) {
	rec, err := s.certificate()
	if err != nil {
		return "", err
	}
	if rec == nil || rec.State == "" {
		s.CertificateState.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return rec.State, nil
}

func (s *mqlNetlifySite) certificateDomains() ([]any, error) {
	rec, err := s.certificate()
	if err != nil {
		return nil, err
	}
	if rec == nil {
		s.CertificateDomains = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return strSliceToAny(rec.Domains), nil
}

func (s *mqlNetlifySite) certificateExpiresAt() (*time.Time, error) {
	rec, err := s.certificate()
	if err != nil {
		return nil, err
	}
	if rec == nil {
		s.CertificateExpiresAt = plugin.TValue[*time.Time]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return rec.ExpiresAt.Time(), nil
}
