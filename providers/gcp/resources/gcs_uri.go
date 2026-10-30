// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// gcsBucketFromURI pulls the bucket name out of a Cloud Storage URI.
//
// Callers hand us whatever the owning API reported, which is not always a
// well-formed gs:// URI: a scheme-less "my-bucket/dump.sql" and a bare bucket
// name both appear in practice, and an empty value means the feature is simply
// not configured. Anything without a usable bucket segment returns "" so the
// reference reads as null rather than resolving to something invented.
func gcsBucketFromURI(uri string) string {
	s := strings.TrimSpace(uri)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "gs://")
	// A URI that was nothing but the scheme names no bucket.
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	// Guard against a leading slash producing an empty first segment.
	if s == "" {
		return ""
	}
	return s
}

// resolveGcsBucketFromURI resolves the bucket named in a Cloud Storage URI.
//
// Bucket names are globally unique, so the bucket resource's init resolves one
// from its name alone. A bucket in a project this credential cannot read is a
// supported configuration -- a BigLake table may well read from a bucket owned
// by another team -- so a failed lookup reports null rather than failing the
// parent resource.
func resolveGcsBucketFromURI(runtime *plugin.Runtime, uri string, field *plugin.TValue[*mqlGcpProjectStorageServiceBucket]) (*mqlGcpProjectStorageServiceBucket, error) {
	name := gcsBucketFromURI(uri)
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(runtime, "gcp.project.storageService.bucket", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		log.Debug().Err(err).Str("bucket", name).Msg("could not resolve Cloud Storage bucket")
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlGcpProjectStorageServiceBucket), nil
}
