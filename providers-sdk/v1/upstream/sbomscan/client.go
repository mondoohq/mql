// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sbomscan is the Mondoo Platform proto client for dependency
// vulnerability scanning (ExtendedVulnMgmt.ScanUploadedSbom). The message types
// are generated from vulnscan.proto; the ranger client below is a hand-written
// wrapper mirroring the server's generated stub (a ranger client is a thin
// DoClientRequest call).
//
//go:generate protoc --plugin=protoc-gen-go=../../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-go-vtproto=../../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=. --proto_path=../../../.. --go_out=. --go_opt=paths=source_relative --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size vulnscan.proto
package sbomscan

import (
	"context"
	"net/url"
	"strings"

	ranger "go.mondoo.com/ranger-rpc"
)

// ExtendedVulnMgmtClient is a minimal client for the platform's
// /ExtendedVulnMgmt/ service, exposing only ScanUploadedSbom.
type ExtendedVulnMgmtClient struct {
	ranger.Client
	httpclient ranger.HTTPClient
	prefix     string
}

// NewExtendedVulnMgmtClient builds a client targeting addr (the Mondoo API
// endpoint). plugins carry authentication (e.g. the service-account ranger plugin).
func NewExtendedVulnMgmtClient(addr string, client ranger.HTTPClient, plugins ...ranger.ClientPlugin) (*ExtendedVulnMgmtClient, error) {
	base, err := url.Parse(ranger.SanitizeUrl(addr))
	if err != nil {
		return nil, err
	}
	u, err := url.Parse("./ExtendedVulnMgmt")
	if err != nil {
		return nil, err
	}
	c := &ExtendedVulnMgmtClient{
		httpclient: client,
		prefix:     base.ResolveReference(u).String(),
	}
	c.AddPlugins(plugins...)
	return c, nil
}

// ScanUploadedSbom scans an SBOM for vulnerabilities scoped to a space. The scan
// is ephemeral; the returned VEX is uploaded separately by the caller.
func (c *ExtendedVulnMgmtClient) ScanUploadedSbom(ctx context.Context, in *ScanUploadedSbomRequest) (*ScanUploadedSbomResponse, error) {
	out := new(ScanUploadedSbomResponse)
	err := c.DoClientRequest(ctx, c.httpclient, strings.Join([]string{c.prefix, "/ScanUploadedSbom"}, ""), in, out)
	return out, err
}
