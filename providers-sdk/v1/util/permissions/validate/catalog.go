// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// catalog is the set of permission strings a cloud's IAM actually knows about.
// How each cloud's catalog is sourced and parsed lives in aws.go, gcp.go and
// azure.go; this file holds what they share.
//
// exact holds the catalog's own spelling. folded maps the lower-cased spelling
// back to that canonical form, so a case-insensitive lookup can still report
// what the canonical spelling is. services holds the first segment of every
// permission (IAM prefix, GCP service, ARM namespace) so an unknown service can
// be reported as such instead of as one more unknown permission.
//
// operations is filled only for AWS: "<service>/<Operation>" to the actions
// AWS says authorize that operation (nil when AWS lists the operation but
// maps it to nothing). gcp is filled only for GCP: what the IAM API says about
// each permission (scopes, stage, custom-role support, alias).
type catalog struct {
	exact      map[string]struct{}
	folded     map[string]string
	services   map[string]struct{}
	operations map[string][]string
	gcp        map[string]gcpPermission
}

func newCatalog() *catalog {
	return &catalog{
		exact:      map[string]struct{}{},
		folded:     map[string]string{},
		services:   map[string]struct{}{},
		operations: map[string][]string{},
		gcp:        map[string]gcpPermission{},
	}
}

// add records one permission together with its service.
func (c *catalog) add(perm string) {
	perm = strings.TrimSpace(perm)
	if perm == "" {
		return
	}
	c.exact[perm] = struct{}{}
	lower := strings.ToLower(perm)
	if _, dup := c.folded[lower]; !dup {
		c.folded[lower] = perm
	}
	c.addService(serviceOf(perm))
}

func (c *catalog) addService(name string) {
	c.services[strings.ToLower(name)] = struct{}{}
}

func (c *catalog) hasExact(perm string) bool {
	_, ok := c.exact[perm]
	return ok
}

// canonical returns the catalog spelling of perm, matched without regard to
// case, and whether any spelling of it exists.
func (c *catalog) canonical(perm string) (string, bool) {
	canon, ok := c.folded[strings.ToLower(perm)]
	return canon, ok
}

func (c *catalog) hasService(perm string) bool {
	_, ok := c.services[strings.ToLower(serviceOf(perm))]
	return ok
}

// serviceOf returns the service segment of a permission in any of the three
// clouds' syntaxes: "ec2" of ec2:DescribeInstances, "compute" of
// compute.instances.list, "Microsoft.Compute" of
// Microsoft.Compute/virtualMachines/read.
func serviceOf(perm string) string {
	if i := strings.IndexByte(perm, ':'); i >= 0 {
		return perm[:i]
	}
	if i := strings.IndexByte(perm, '/'); i >= 0 {
		return perm[:i]
	}
	if i := strings.IndexByte(perm, '.'); i >= 0 {
		return perm[:i]
	}
	return perm
}

// loadCatalog builds the catalog for the provider whose manifest this is.
func loadCatalog(m manifest, f *fetcher, gcpProject, gcpOrganization string) (*catalog, error) {
	switch m.Provider {
	case "aws":
		return loadAWSCatalog(f, m)
	case "gcp":
		return loadGCPCatalog(f, gcpProject, gcpOrganization)
	case "azure":
		return loadAzureCatalog(f)
	default:
		return nil, fmt.Errorf("no permission catalog for provider %q", m.Provider)
	}
}

// fetcher downloads the AWS and Azure catalog sources. Downloads stay in
// memory and are parsed straight away; nothing fetched over HTTP is written to
// disk.
type fetcher struct {
	client *http.Client
	log    io.Writer
}

func newFetcher(log io.Writer) *fetcher {
	return &fetcher{
		client: &http.Client{Timeout: 2 * time.Minute},
		log:    log,
	}
}

// get returns the body of url, retrying transient failures.
func (f *fetcher) get(url string) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Fprintf(f.log, "  downloading %s\n", url)
		resp, err := f.client.Get(url)
		if err == nil {
			data, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK && len(data) > 0 {
				return data, nil
			}
			err = readErr
			if err == nil {
				err = fmt.Errorf("HTTP %d (%d bytes)", resp.StatusCode, len(data))
			}
		}
		lastErr = fmt.Errorf("fetch %s: %w", url, err)
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	return nil, lastErr
}
