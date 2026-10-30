// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tlsshake

import (
	"crypto/x509"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/utils/multierr"
)

const (
	// crlHTTPTimeout bounds a single CRL download. Revocation is one input to a
	// certificate's findings, not a reason to hold up the whole scan.
	crlHTTPTimeout = 10 * time.Second
	// maxCRLSize caps what is read from a distribution point. Public CRLs run to
	// tens of kilobytes; the cap is what stops a hostile or misconfigured
	// endpoint from streaming until the scanner runs out of memory.
	maxCRLSize = 8 << 20
	// maxCachedCRLs bounds the cache. A chain touches one or two distribution
	// points and a scan reuses an issuer's list across hosts, so this is well
	// above what a real run needs.
	maxCachedCRLs = 16
)

// crlEntry is one cache slot. It is created before the download starts and its
// ready channel is closed when the download finishes, so callers that arrive
// while a list is in flight wait for that result instead of starting their own.
type crlEntry struct {
	ready chan struct{}
	list  *x509.RevocationList
	err   error
}

var (
	crlCacheLock sync.Mutex
	crlCache     = map[string]*crlEntry{}
)

// fetchCRL downloads and parses a certificate revocation list, reusing a cached
// copy until the list's own NextUpdate has passed.
//
// The list states how long it is good for, so honoring NextUpdate is both the
// correct cache policy and the one that keeps a scan of many hosts behind the
// same issuer down to a single download. Only one download per URL runs at a
// time: a scan opens many hosts at once and their chains share an issuer, so
// without that they would all miss an empty cache together and each fetch the
// same list.
func fetchCRL(url string) (*x509.RevocationList, error) {
	for {
		crlCacheLock.Lock()
		entry, inFlightOrCached := crlCache[url]
		if !inFlightOrCached {
			// Claim the slot before releasing the lock, so anyone arriving
			// during the download waits on this entry rather than starting
			// another.
			entry = &crlEntry{ready: make(chan struct{})}
			crlCache[url] = entry
			crlCacheLock.Unlock()

			entry.list, entry.err = downloadCRL(url)
			close(entry.ready)

			// A list that could not be read is not worth keeping, and neither
			// is one that arrived already past its NextUpdate. Drop both so the
			// next caller retries rather than inheriting the failure.
			keep := entry.err == nil && time.Now().Before(entry.list.NextUpdate)
			crlCacheLock.Lock()
			if !keep || len(crlCache) > maxCachedCRLs {
				if crlCache[url] == entry {
					delete(crlCache, url)
				}
			}
			crlCacheLock.Unlock()

			return entry.list, entry.err
		}
		crlCacheLock.Unlock()

		<-entry.ready
		if entry.err == nil && time.Now().Before(entry.list.NextUpdate) {
			return entry.list, nil
		}

		// The entry is stale or failed. Drop it and go round again to become
		// the downloader, unless someone else has already replaced it.
		crlCacheLock.Lock()
		if crlCache[url] == entry {
			delete(crlCache, url)
		}
		crlCacheLock.Unlock()
	}
}

// downloadCRL fetches and parses one list, with no caching of its own.
func downloadCRL(url string) (*x509.RevocationList, error) {
	client := &http.Client{Timeout: crlHTTPTimeout}
	res, err := client.Get(url)
	if err != nil {
		return nil, multierr.Wrap(err, "failed to download CRL")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("CRL request returned " + res.Status)
	}

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxCRLSize))
	if err != nil {
		return nil, multierr.Wrap(err, "failed to read CRL")
	}

	list, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil, multierr.Wrap(err, "failed to parse CRL")
	}

	return list, nil
}

// crlRevocation reports whether a certificate appears on one of the CRLs it
// points at.
//
// The first return says whether a determination was reached at all. A CRL that
// cannot be downloaded, parsed, or attributed to the issuer decides nothing:
// reporting "not revoked" from a list that was never read is the failure this
// whole path exists to avoid.
//
// The list's signature is checked against the issuing certificate, so a CRL
// substituted on the wire cannot vouch for a certificate that has been revoked.
func crlRevocation(cert *x509.Certificate, issuer *x509.Certificate) (bool, *Revocation, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return false, nil, errors.New("no CRL distribution point specified for revocation check")
	}

	var errs multierr.Errors
	for _, url := range cert.CRLDistributionPoints {
		list, err := fetchCRL(url)
		if err != nil {
			errs.Add(err)
			continue
		}

		// Without an issuer there is nothing to check the list against, and an
		// unverified list must not decide anything: whoever answers the
		// distribution point would otherwise be able to clear a certificate
		// that has been revoked.
		if issuer == nil {
			errs.Add(errors.New("CRL at " + url + " has no issuing certificate to verify its signature against"))
			continue
		}
		if err := list.CheckSignatureFrom(issuer); err != nil {
			errs.Add(multierr.Wrap(err, "CRL at "+url+" is not signed by the issuing certificate"))
			continue
		}

		for i := range list.RevokedCertificateEntries {
			entry := list.RevokedCertificateEntries[i]
			if entry.SerialNumber.Cmp(cert.SerialNumber) != 0 {
				continue
			}
			return true, &Revocation{
				At:     entry.RevocationTime,
				Via:    url,
				Reason: entry.ReasonCode,
			}, nil
		}

		// The list was read and does not carry this serial, which is what a CRL
		// says when a certificate is good.
		return true, nil, nil
	}

	return false, nil, errs.Deduplicate()
}
