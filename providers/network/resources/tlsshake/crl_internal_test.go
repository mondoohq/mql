// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tlsshake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCA is a throwaway issuer plus one certificate it signed, with a CRL
// distribution point pointing at a local server.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCA{cert: cert, key: key}
}

func (ca *testCA) issue(t *testing.T, serial int64, crlURL string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: []string{crlURL},
	}
	if crlURL == "" {
		tmpl.CRLDistributionPoints = nil
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// crl builds a signed revocation list naming the given serials as revoked.
func (ca *testCA) crl(t *testing.T, revokedAt time.Time, serials ...int64) []byte {
	t.Helper()

	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, serial := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(serial),
			RevocationTime: revokedAt,
			ReasonCode:     1,
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Minute),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	require.NoError(t, err)
	return der
}

// crlServer serves whatever body is currently set, counting requests so the
// cache can be observed.
type crlServer struct {
	url    string
	body   atomic.Pointer[[]byte]
	status atomic.Int32
	hits   atomic.Int32
}

func newCRLServer(t *testing.T) *crlServer {
	t.Helper()

	s := &crlServer{}
	s.status.Store(http.StatusOK)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if code := int(s.status.Load()); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		if body := s.body.Load(); body != nil {
			_, _ = w.Write(*body)
		}
	}))
	t.Cleanup(srv.Close)

	s.url = srv.URL + "/crl"
	return s
}

func (s *crlServer) serve(der []byte) { s.body.Store(&der) }

// clearCRLCache keeps cases from seeing each other's downloads.
func clearCRLCache(t *testing.T) {
	t.Helper()
	crlCacheLock.Lock()
	crlCache = map[string]*crlEntry{}
	crlCacheLock.Unlock()
}

func TestCrlRevocationFindsARevokedCertificate(t *testing.T) {
	clearCRLCache(t)

	ca := newTestCA(t, "test ca")
	server := newCRLServer(t)
	cert := ca.issue(t, 42, server.url)

	revokedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	server.serve(ca.crl(t, revokedAt, 42))

	determined, revocation, err := crlRevocation(cert, ca.cert)
	require.NoError(t, err)
	require.True(t, determined)
	require.NotNil(t, revocation, "a certificate listed on the CRL is revoked")
	assert.Equal(t, revokedAt, revocation.At.UTC())
	assert.Equal(t, server.url, revocation.Via)
}

func TestCrlRevocationClearsACertificateTheListDoesNotName(t *testing.T) {
	clearCRLCache(t)

	ca := newTestCA(t, "test ca")
	server := newCRLServer(t)
	cert := ca.issue(t, 42, server.url)

	// The list was read and does not carry this serial, which is a real answer.
	server.serve(ca.crl(t, time.Now(), 99))

	determined, revocation, err := crlRevocation(cert, ca.cert)
	require.NoError(t, err)
	assert.True(t, determined)
	assert.Nil(t, revocation)
}

func TestCrlRevocationRejectsAListTheIssuerDidNotSign(t *testing.T) {
	clearCRLCache(t)

	ca := newTestCA(t, "test ca")
	impostor := newTestCA(t, "impostor")
	server := newCRLServer(t)
	cert := ca.issue(t, 42, server.url)

	// A list signed by anyone else must decide nothing. Accepting it would let
	// whoever answers the distribution point vouch for a revoked certificate.
	server.serve(impostor.crl(t, time.Now(), 99))

	determined, revocation, err := crlRevocation(cert, ca.cert)
	assert.False(t, determined)
	assert.Nil(t, revocation)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not signed by the issuing certificate")
}

func TestCrlRevocationDeterminesNothingWhenTheListCannotBeRead(t *testing.T) {
	ca := newTestCA(t, "test ca")

	t.Run("no distribution point", func(t *testing.T) {
		clearCRLCache(t)
		cert := ca.issue(t, 42, "")

		determined, revocation, err := crlRevocation(cert, ca.cert)
		assert.False(t, determined)
		assert.Nil(t, revocation)
		require.Error(t, err)
	})

	t.Run("distribution point returns an error", func(t *testing.T) {
		clearCRLCache(t)
		server := newCRLServer(t)
		server.status.Store(http.StatusNotFound)
		cert := ca.issue(t, 42, server.url)

		determined, revocation, err := crlRevocation(cert, ca.cert)
		assert.False(t, determined)
		assert.Nil(t, revocation)
		require.Error(t, err)
	})

	t.Run("distribution point returns something that is not a CRL", func(t *testing.T) {
		clearCRLCache(t)
		server := newCRLServer(t)
		server.serve([]byte("not a crl"))
		cert := ca.issue(t, 42, server.url)

		determined, revocation, err := crlRevocation(cert, ca.cert)
		assert.False(t, determined)
		assert.Nil(t, revocation)
		require.Error(t, err)
	})
}

func TestCrlRevocationRefusesAListItCannotAttributeToAnIssuer(t *testing.T) {
	// With no issuer there is nothing to check the signature against. Trusting
	// the list anyway would let whoever answers the distribution point clear a
	// certificate that has been revoked.
	clearCRLCache(t)

	ca := newTestCA(t, "test ca")
	server := newCRLServer(t)
	cert := ca.issue(t, 42, server.url)
	server.serve(ca.crl(t, time.Now(), 42))

	determined, revocation, err := crlRevocation(cert, nil)
	assert.False(t, determined, "an unverifiable list must decide nothing")
	assert.Nil(t, revocation)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no issuing certificate")
}

func TestFetchCRLDownloadsOncePerUrlUnderConcurrency(t *testing.T) {
	// A scan opens many hosts at once and their chains share an issuer, so
	// without single-flight they all miss an empty cache together and each
	// fetch the same list.
	clearCRLCache(t)

	ca := newTestCA(t, "test ca")
	server := newCRLServer(t)
	cert := ca.issue(t, 42, server.url)
	server.serve(ca.crl(t, time.Now(), 42))

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			determined, _, err := crlRevocation(cert, ca.cert)
			assert.NoError(t, err)
			assert.True(t, determined)
		})
	}
	wg.Wait()

	assert.Equal(t, int32(1), server.hits.Load(), "concurrent callers should share one download")
}

func TestFetchCRLRetriesAfterAFailedDownload(t *testing.T) {
	// A failure must not be cached, or one blip would report every certificate
	// behind that issuer as unchecked for the rest of the run.
	clearCRLCache(t)

	ca := newTestCA(t, "test ca")
	server := newCRLServer(t)
	cert := ca.issue(t, 42, server.url)

	server.status.Store(http.StatusInternalServerError)
	determined, _, err := crlRevocation(cert, ca.cert)
	require.False(t, determined)
	require.Error(t, err)

	server.status.Store(http.StatusOK)
	server.serve(ca.crl(t, time.Now(), 42))

	determined, revocation, err := crlRevocation(cert, ca.cert)
	require.NoError(t, err)
	assert.True(t, determined)
	assert.NotNil(t, revocation)
}

func TestFetchCRLReusesAListUntilItsNextUpdate(t *testing.T) {
	// A scan behind one issuer touches the same distribution point for every
	// host; downloading the list once per certificate would be the expensive
	// part of adding CRL support.
	clearCRLCache(t)

	ca := newTestCA(t, "test ca")
	server := newCRLServer(t)
	cert := ca.issue(t, 42, server.url)
	server.serve(ca.crl(t, time.Now(), 42))

	for range 3 {
		determined, _, err := crlRevocation(cert, ca.cert)
		require.NoError(t, err)
		require.True(t, determined)
	}

	assert.Equal(t, int32(1), server.hits.Load(), "the list should be downloaded once")
}

// staleCRL builds a signed list whose NextUpdate has already passed, the shape
// an unattended or misconfigured distribution point serves.
func (ca *testCA) staleCRL(t *testing.T, serials ...int64) []byte {
	t.Helper()

	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, serial := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(serial),
			RevocationTime: time.Now().Add(-48 * time.Hour),
			ReasonCode:     1,
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-48 * time.Hour),
		NextUpdate:                time.Now().Add(-24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	require.NoError(t, err)
	return der
}

func TestFetchCRLDownloadsAStaleListOnceInsteadOfRetrying(t *testing.T) {
	// A list that arrives already past its NextUpdate is not cached, since
	// caching it would pin an expired answer for the rest of the run. Not
	// caching it must not turn into re-fetching it: one call is one download,
	// or a distribution point serving a stale list would see a request per
	// loop for as long as the scan runs.
	clearCRLCache(t)

	ca := newTestCA(t, "test ca")
	stale := ca.staleCRL(t, 42)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stop answering after a handful of requests, so a caller that did
		// loop fails here in milliseconds instead of hanging until the test
		// timeout.
		if hits.Add(1) > 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(stale)
	}))
	t.Cleanup(srv.Close)

	cert := ca.issue(t, 42, srv.URL+"/crl")

	determined, revocation, err := crlRevocation(cert, ca.cert)
	require.NoError(t, err)
	require.True(t, determined)
	require.NotNil(t, revocation)

	assert.Equal(t, int32(1), hits.Load(), "a stale list costs one download per call, not a retry loop")
}
