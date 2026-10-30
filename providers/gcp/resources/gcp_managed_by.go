// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// managedByFromLabels infers the infrastructure-management system that owns a
// GCP resource from the provenance labels and annotations Google and common
// IaC tools stamp on managed resources. Callers pass every label/annotation map
// the resource exposes; the maps are inspected in priority order and the first
// recognized signal wins. It returns an empty string when no management signal
// is present (a resource created manually or through the console) and propagates
// any error from resolving a computed map.
//
// Recognized signals, highest priority first:
//   - "terraform": the goog-terraform-provisioned label Google stamps on
//     resources created through the Terraform Google provider.
//   - "config-connector": the cnrm.cloud.google.com/* annotations (or the
//     managed-by-cnrm label) the GKE Config Connector controller applies to
//     resources it reconciles.
//   - "cloud-composer": the goog-composer-* labels applied to resources a Cloud
//     Composer environment provisions.
func managedByFromLabels(maps ...*plugin.TValue[map[string]any]) (string, error) {
	for _, m := range maps {
		if m != nil && m.Error != nil {
			return "", m.Error
		}
	}
	for _, m := range maps {
		if m == nil {
			continue
		}
		if v, ok := m.Data["goog-terraform-provisioned"]; ok && labelValueTrue(v) {
			return "terraform", nil
		}
	}
	for _, m := range maps {
		if m == nil {
			continue
		}
		for k := range m.Data {
			if k == "managed-by-cnrm" || strings.HasPrefix(k, "cnrm.cloud.google.com/") {
				return "config-connector", nil
			}
		}
	}
	for _, m := range maps {
		if m == nil {
			continue
		}
		for k := range m.Data {
			if strings.HasPrefix(k, "goog-composer-") {
				return "cloud-composer", nil
			}
		}
	}
	return "", nil
}

// labelValueTrue reports whether a label value is the string "true"
// (case-insensitive). GCP label values are always strings.
func labelValueTrue(v any) bool {
	s, ok := v.(string)
	return ok && strings.EqualFold(s, "true")
}
