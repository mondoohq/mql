// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// An AWS permission is real when it is an IAM action, "<prefix>:<Action>", in
// AWS's Service Reference: the machine-readable, first-party list of every IAM
// service's actions, published per service at servicereference.us-east-1.
// amazonaws.com. Matching is exact: the reference gives every action one
// canonical spelling, and the manifest should carry it even though IAM
// evaluates actions case-insensitively.
//
// The reference also maps each API operation to the actions that authorize
// it ("GetFindingV2 is authorized by access-analyzer:GetFinding"), which the
// manifest's details let us check too: an entry whose operation AWS maps to a
// different action is wrong even though the action it names exists. The
// mapping is incomplete (about one operation in twenty has none), so an
// operation without one is simply not checked at that level.
const awsServiceReferenceIndexURL = "https://servicereference.us-east-1.amazonaws.com/"

// awsServiceReference is one service's file from the reference. Only the
// fields the validator reads are declared.
type awsServiceReference struct {
	Name    string `json:"Name"`
	Actions []struct {
		Name string `json:"Name"`
	} `json:"Actions"`
	Operations []struct {
		Name              string `json:"Name"`
		AuthorizedActions []struct {
			Service string `json:"Service"`
			Name    string `json:"Name"`
		} `json:"AuthorizedActions"`
	} `json:"Operations"`
}

// loadAWSCatalog fetches the reference for every IAM service the manifest
// names. The index lists all 455 services; the manifest uses about a quarter
// of them, so only those are downloaded (about 7 MB in all).
func loadAWSCatalog(f *fetcher, m manifest) (*catalog, error) {
	data, err := f.get(awsServiceReferenceIndexURL)
	if err != nil {
		return nil, err
	}
	var index []struct {
		Service string `json:"service"`
		URL     string `json:"url"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("service reference index: %w", err)
	}
	if len(index) == 0 {
		return nil, errors.New("service reference index: no services")
	}
	urls := map[string]string{}
	c := newCatalog()
	for _, e := range index {
		urls[e.Service] = e.URL
		// Every service the reference knows counts as a known prefix, so an
		// unknown one can be reported as such.
		c.addService(e.Service)
	}

	needed := map[string]bool{}
	for _, p := range m.Permissions {
		needed[serviceOf(p)] = true
	}
	for _, d := range m.Details {
		needed[d.Service] = true
	}
	var services []string
	for svc := range needed {
		if _, ok := urls[svc]; ok {
			services = append(services, svc)
		}
	}
	sort.Strings(services)

	// Fetch concurrently; the files are small and the latency is per request.
	type fetched struct {
		svc  string
		data []byte
		err  error
	}
	results := make([]fetched, len(services))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, svc := range services {
		wg.Add(1)
		go func(i int, svc string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			data, err := f.get(urls[svc])
			results[i] = fetched{svc, data, err}
		}(i, svc)
	}
	wg.Wait()
	for _, r := range results {
		if r.err != nil {
			return nil, r.err
		}
		if err := parseAWSServiceReference(r.data, c); err != nil {
			return nil, fmt.Errorf("service reference for %s: %w", r.svc, err)
		}
	}
	return c, nil
}

// parseAWSServiceReference adds one service's actions, and records which
// actions authorize each of its operations.
func parseAWSServiceReference(data []byte, into *catalog) error {
	var ref awsServiceReference
	if err := json.Unmarshal(data, &ref); err != nil {
		return err
	}
	if ref.Name == "" {
		return errors.New("no service name")
	}
	if len(ref.Actions) == 0 {
		return fmt.Errorf("%s: no actions", ref.Name)
	}
	for _, a := range ref.Actions {
		into.add(ref.Name + ":" + a.Name)
	}
	for _, op := range ref.Operations {
		key := ref.Name + "/" + op.Name
		into.operations[key] = nil // the operation exists, even with no mapping
		for _, a := range op.AuthorizedActions {
			into.operations[key] = append(into.operations[key], a.Service+":"+a.Name)
		}
	}
	return nil
}
