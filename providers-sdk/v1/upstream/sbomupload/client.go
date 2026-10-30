// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sbomupload is the Mondoo Platform proto client for uploading SBOMs
// (Sbom.BulkUploadSbom). Uploading an SBOM stores it and lets the platform
// enrich it into vulnerabilities automatically — clients do not compute VEX. The
// message types are generated from sbomupload.proto; the ranger client below is a
// hand-written wrapper mirroring the server's generated stub.
//
//go:generate protoc --plugin=protoc-gen-go=../../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-go-vtproto=../../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=. --proto_path=../../../.. --go_out=. --go_opt=paths=source_relative --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size sbomupload.proto
package sbomupload

import (
	"context"
	"net/url"
	"strings"

	ranger "go.mondoo.com/ranger-rpc"
)

// SbomClient is a minimal client for the platform's /Sbom/ service, exposing only
// BulkUploadSbom.
type SbomClient struct {
	ranger.Client
	httpclient ranger.HTTPClient
	prefix     string
}

// NewSbomClient builds a client targeting addr (the Mondoo API endpoint). plugins
// carry authentication (e.g. the service-account ranger plugin).
func NewSbomClient(addr string, client ranger.HTTPClient, plugins ...ranger.ClientPlugin) (*SbomClient, error) {
	base, err := url.Parse(ranger.SanitizeUrl(addr))
	if err != nil {
		return nil, err
	}
	u, err := url.Parse("./Sbom")
	if err != nil {
		return nil, err
	}
	c := &SbomClient{
		httpclient: client,
		prefix:     base.ResolveReference(u).String(),
	}
	c.AddPlugins(plugins...)
	return c, nil
}

// BulkUploadSbom uploads SBOMs to a space; the platform stores and enriches them.
func (c *SbomClient) BulkUploadSbom(ctx context.Context, in *BulkUploadSbomRequest) (*BulkUploadSbomResponse, error) {
	out := new(BulkUploadSbomResponse)
	err := c.DoClientRequest(ctx, c.httpclient, strings.Join([]string{c.prefix, "/BulkUploadSbom"}, ""), in, out)
	return out, err
}
