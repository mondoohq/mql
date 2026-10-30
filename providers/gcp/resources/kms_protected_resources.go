// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	kmsinventory "google.golang.org/api/kmsinventory/v1"
	"google.golang.org/api/option"
)

// partialDataWarningCodes are the KMS Inventory warning codes that mean the
// asset search behind a protected-resources summary did not see everything.
//
// Any of them makes every count a lower bound. That distinction is the whole
// point of surfacing the warnings: the headline use of this summary is finding
// orphaned keys, and a resourceCount of 0 that came back with one of these
// warnings is not evidence that a key protects nothing.
var partialDataWarningCodes = map[string]struct{}{
	"INSUFFICIENT_PERMISSIONS_PARTIAL_DATA": {},
	"RESOURCE_LIMIT_EXCEEDED_PARTIAL_DATA":  {},
	"ORG_LESS_PROJECT_PARTIAL_DATA":         {},
}

// protectedResourcesWarnings extracts the warning codes from a summary and
// reports whether any of them means the data is partial.
//
// Codes are sorted so the field does not reorder between two reads of the same
// key, and repeats are collapsed. An unrecognized code is still reported, but
// does not set partialData: treating an unknown code as "incomplete" would flip
// a complete summary to a lower bound on the strength of a string we do not
// know, and WARNING_CODE_UNSPECIFIED is documented as unused.
func protectedResourcesWarnings(warnings []*kmsinventory.GoogleCloudKmsInventoryV1Warning) (codes []any, partial bool) {
	seen := map[string]struct{}{}
	names := make([]string, 0, len(warnings))
	for _, w := range warnings {
		if w == nil || w.WarningCode == "" {
			continue
		}
		if _, dup := seen[w.WarningCode]; dup {
			continue
		}
		seen[w.WarningCode] = struct{}{}
		names = append(names, w.WarningCode)
		if _, isPartial := partialDataWarningCodes[w.WarningCode]; isPartial {
			partial = true
		}
	}
	sort.Strings(names)
	codes = make([]any, 0, len(names))
	for _, n := range names {
		codes = append(codes, n)
	}
	return codes, partial
}

// protectedResourcesArgs maps a protected-resources summary onto its MQL
// resource arguments.
//
// The per-product, per-type and per-region breakdowns are counts the API
// returns as strings, and they are passed through as strings rather than parsed:
// a parse failure would have to invent a number, and the map is a breakdown to
// read rather than a value to compare against.
func protectedResourcesArgs(keyPath string, summary *kmsinventory.GoogleCloudKmsInventoryV1ProtectedResourcesSummary) map[string]*llx.RawData {
	warnings, partial := protectedResourcesWarnings(summary.Warnings)
	return map[string]*llx.RawData{
		"__id":          llx.StringData(keyPath + "/protectedResourcesSummary"),
		"resourceCount": llx.IntData(summary.ResourceCount),
		"projectCount":  llx.IntData(summary.ProjectCount),
		"cloudProducts": llx.MapData(convert.MapToInterfaceMap(summary.CloudProducts), types.String),
		"resourceTypes": llx.MapData(convert.MapToInterfaceMap(summary.ResourceTypes), types.String),
		"locations":     llx.MapData(convert.MapToInterfaceMap(summary.Locations), types.String),
		"partialData":   llx.BoolData(partial),
		"warnings":      llx.ArrayData(warnings, types.String),
	}
}

// protectedResources reports what this key actually protects.
//
// The summary comes from KMS Inventory, which reads Cloud Asset Inventory rather
// than KMS, so it spans the key's whole organization and answers the two
// questions the per-resource CMEK references cannot: whether anything uses this
// key, and whether its blast radius leaves the project.
//
// The field is null whenever the summary cannot be read: the API is not enabled
// on the project, the caller lacks cloudkms.protectedResources.search, or the
// KMS organization service agent has not been granted the org-level role the
// asset search behind this API needs. Null rather than a zero-count summary,
// because a fabricated resourceCount of 0 is exactly the reading an
// orphaned-key audit acts on, and none of those failures is evidence that a key
// protects nothing. The distinction that has to survive is null ("not read")
// against resourceCount 0 ("read, and it protects nothing"), and that one holds:
// null does not satisfy resourceCount == 0.
//
// The reason for degrading rather than returning the error was measured, not
// assumed. The org service agent grant is a separate manual step, so a project
// with keys and the API enabled still answers 403 until someone performs it, and
// returning that error failed the whole cryptokeys collection: a query asking
// for name alongside this field lost the names too. The error is logged with the
// message the API supplied, which names the service agent and the grant to make,
// so the reason a field is null is recoverable from the scan log.
func (g *mqlGcpProjectKmsServiceKeyringCryptokey) protectedResources() (*mqlGcpProjectKmsServiceKeyringCryptokeyProtectedResources, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	keyPath := g.ResourcePath.Data
	if keyPath == "" {
		return nil, errors.New("crypto key has no resource path")
	}

	projectId := projectFromResourceName(keyPath)
	if projectId == "" {
		return nil, fmt.Errorf("could not extract project id from crypto key path %q", keyPath)
	}

	enabled, err := serviceEnabledForInit(g.MqlRuntime, projectId, service_kmsinventory)
	if err != nil {
		return nil, err
	}
	if !enabled {
		log.Debug().Str("service", service_kmsinventory).Str("project", projectId).
			Msg("gcp service is not enabled, cannot read protected resources summary")
		g.ProtectedResources.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(kmsinventory.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	invSvc, err := kmsinventory.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	summary, err := invSvc.Projects.Locations.KeyRings.CryptoKeys.
		GetProtectedResourcesSummary(keyPath).
		Context(ctx).Do()
	if err != nil {
		if isSkippable(err) {
			// Warn, not debug: unlike most skippable reads this one is usually
			// fixable, and the API's own message names the service agent and the
			// role it needs.
			log.Warn().Err(err).Str("key", keyPath).
				Msg("could not read the protected resources summary for this key")
			g.ProtectedResources.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(g.MqlRuntime,
		"gcp.project.kmsService.keyring.cryptokey.protectedResources",
		protectedResourcesArgs(keyPath, summary))
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokeyProtectedResources), nil
}
