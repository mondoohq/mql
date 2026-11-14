// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/fastly/go-fastly/v10/fastly"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/fastly/connection"
	"go.mondoo.com/mql/types"
)

func fastlyConnection(runtime *plugin.Runtime) *connection.FastlyConnection {
	return runtime.Connection.(*connection.FastlyConnection)
}

func (r *mqlFastly) id() (string, error) {
	return "fastly", nil
}

func (r *mqlFastly) services() ([]any, error) {
	conn := fastlyConnection(r.MqlRuntime)
	services, err := conn.Client().ListServices(&fastly.ListServicesInput{})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(services))
	for _, s := range services {
		res, err := newService(r.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlFastly) tlsSubscriptions() ([]any, error) {
	conn := fastlyConnection(r.MqlRuntime)
	subs, err := paginateAll(func(page int) ([]*fastly.TLSSubscription, error) {
		return conn.Client().ListTLSSubscriptions(&fastly.ListTLSSubscriptionsInput{
			PageNumber: page,
			PageSize:   tlsPageSize,
		})
	})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(subs))
	for _, s := range subs {
		res, err := newTLSSubscription(r.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlFastly) tlsCertificates() ([]any, error) {
	conn := fastlyConnection(r.MqlRuntime)
	certs, err := paginateAll(func(page int) ([]*fastly.CustomTLSCertificate, error) {
		return conn.Client().ListCustomTLSCertificates(&fastly.ListCustomTLSCertificatesInput{
			PageNumber: page,
			PageSize:   tlsPageSize,
		})
	})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(certs))
	for _, c := range certs {
		res, err := newTLSCertificate(r.MqlRuntime, c)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlFastly) tlsActivations() ([]any, error) {
	conn := fastlyConnection(r.MqlRuntime)
	activations, err := paginateAll(func(page int) ([]*fastly.TLSActivation, error) {
		return conn.Client().ListTLSActivations(&fastly.ListTLSActivationsInput{
			// Pull the certificate and domain inline so the activation can
			// resolve them without a request per activation.
			Include:    "tls_certificate,tls_domain",
			PageNumber: page,
			PageSize:   tlsPageSize,
		})
	})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(activations))
	for _, a := range activations {
		res, err := newTLSActivation(r.MqlRuntime, a)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlFastly) users() ([]any, error) {
	conn := fastlyConnection(r.MqlRuntime)
	customerID := conn.CustomerID()
	if customerID == "" {
		// Without a customer the users endpoint cannot be addressed. The token
		// authenticated, so this is an empty result, not a failure.
		return []any{}, nil
	}

	users, err := conn.Client().ListCustomerUsers(&fastly.ListCustomerUsersInput{
		CustomerID: customerID,
	})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(users))
	for _, u := range users {
		res, err := newUser(r.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// tlsPageSize is the page size for the JSON:API TLS endpoints, which otherwise
// return only their default first page.
const tlsPageSize = 100

// maxPages caps a page walk so a server that ignores the page parameter and
// keeps returning a full page cannot loop forever.
const maxPages = 10000

// paginateAll walks a page-numbered endpoint from page 1, accumulating every
// record. It stops on the first short page, or at maxPages as a guard against a
// cursor that never advances.
func paginateAll[T any](fetch func(page int) ([]*T, error)) ([]*T, error) {
	var all []*T
	for page := 1; page <= maxPages; page++ {
		batch, err := fetch(page)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < tlsPageSize {
			return all, nil
		}
	}
	return all, nil
}

// stringSlice wraps a []string as MQL array data.
func stringSlice(in []string) *llx.RawData {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return llx.ArrayData(out, types.String)
}
