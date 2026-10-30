// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	corev1 "k8s.io/api/core/v1"
)

// LabelNamespaceLabelConflict marks a container image whose in-scope namespaces
// disagree on an inherited label key. Its value lists the conflicting keys,
// sorted and comma-separated, so a routing rule can match on it.
const LabelNamespaceLabelConflict = "k8s.mondoo.com/namespace-label-conflict"

// imageLabelVerdict is what the in-scope namespaces running an image agreed on:
// the inherited labels every voter shares, and the keys they disagree on.
type imageLabelVerdict struct {
	Labels    map[string]string `json:"labels,omitempty"`
	Conflicts []string          `json:"conflicts,omitempty"`
}

// imageLabelVerdicts folds the votes. imagesByNamespace lists the images each
// in-scope namespace runs; nsLabels holds each namespace's own labels; patterns
// are the inherited keys. Only namespaces carrying a key vote on it: all voters
// agree → the key becomes a label; they disagree → the key is a conflict; no
// voter → nothing. Images with neither are absent from the result.
func imageLabelVerdicts(imagesByNamespace map[string][]string, nsLabels map[string]map[string]string, patterns []string) map[string]imageLabelVerdict {
	// votes[image][key] is the set of values the namespaces running image carry for key.
	votes := map[string]map[string]map[string]struct{}{}
	for ns, images := range imagesByNamespace {
		inherited := inheritedNamespaceLabels(nsLabels[ns], patterns)
		if len(inherited) == 0 {
			continue
		}
		for _, image := range images {
			keys := votes[image]
			if keys == nil {
				keys = map[string]map[string]struct{}{}
				votes[image] = keys
			}
			for k, v := range inherited {
				if keys[k] == nil {
					keys[k] = map[string]struct{}{}
				}
				keys[k][v] = struct{}{}
			}
		}
	}

	verdicts := make(map[string]imageLabelVerdict, len(votes))
	for image, keys := range votes {
		var verdict imageLabelVerdict
		for k, values := range keys {
			if len(values) > 1 {
				verdict.Conflicts = append(verdict.Conflicts, k)
				continue
			}
			if verdict.Labels == nil {
				verdict.Labels = map[string]string{}
			}
			for v := range values {
				verdict.Labels[k] = v
			}
		}
		sort.Strings(verdict.Conflicts)
		verdicts[image] = verdict
	}
	return verdicts
}

// verdictsForImages returns the subset of verdicts for the given images.
func verdictsForImages(verdicts map[string]imageLabelVerdict, images []string) map[string]imageLabelVerdict {
	subset := map[string]imageLabelVerdict{}
	for _, image := range images {
		if v, ok := verdicts[image]; ok {
			subset[image] = v
		}
	}
	return subset
}

// imageLabelVerdictsMaxBytes caps the encoded verdicts handed to one namespace
// stage. Beyond it the stage receives imageLabelVerdictsSentinel and labels no
// image rather than labeling some wrongly. A var so tests can lower it.
var imageLabelVerdictsMaxBytes = 256 << 10

// imageLabelVerdictsSentinel tells a namespace stage that its verdicts did not
// fit the transport.
const imageLabelVerdictsSentinel = "*"

// encodeImageLabelVerdicts marshals verdicts for the stage-2 option: "{}" for
// an empty map, the sentinel when the JSON is longer than imageLabelVerdictsMaxBytes.
func encodeImageLabelVerdicts(verdicts map[string]imageLabelVerdict) string {
	if len(verdicts) == 0 {
		return "{}"
	}
	raw, err := json.Marshal(verdicts)
	if err != nil {
		// Unreachable for a map of strings; still, a marshal failure is a bug,
		// not a capacity problem, so say so before degrading to the sentinel.
		log.Error().Err(err).Msg("encoding container image label verdicts")
		return imageLabelVerdictsSentinel
	}
	if len(raw) > imageLabelVerdictsMaxBytes {
		return imageLabelVerdictsSentinel
	}
	return string(raw)
}

// decodeImageLabelVerdicts parses the stage-2 option; skip is true for the sentinel.
func decodeImageLabelVerdicts(raw string) (verdicts map[string]imageLabelVerdict, skip bool, err error) {
	if raw == imageLabelVerdictsSentinel {
		return nil, true, nil
	}
	if err := json.Unmarshal([]byte(raw), &verdicts); err != nil {
		return nil, false, fmt.Errorf("invalid %s option: %w", shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS, err)
	}
	return verdicts, false, nil
}

func isImageAsset(a *inventory.Asset) bool {
	return len(a.Connections) > 0 && a.Connections[0].Type == registryImageConnectionType
}

// applyImageLabelVerdicts stamps each registry-image asset in assets (matched by
// Connections[0].Host) with its verdict's labels and, when it has conflicts,
// the marker label. Assets without a verdict are left untouched.
func applyImageLabelVerdicts(assets []*inventory.Asset, verdicts map[string]imageLabelVerdict) {
	if len(verdicts) == 0 {
		return
	}
	for _, a := range assets {
		if !isImageAsset(a) {
			continue
		}
		verdict, ok := verdicts[a.Connections[0].Host]
		if !ok || (len(verdict.Labels) == 0 && len(verdict.Conflicts) == 0) {
			continue
		}
		if a.Labels == nil {
			a.Labels = map[string]string{}
		}
		maps.Copy(a.Labels, verdict.Labels)
		if len(verdict.Conflicts) > 0 {
			a.Labels[LabelNamespaceLabelConflict] = strings.Join(verdict.Conflicts, ",")
		}
	}
}

// clusterImagesByNamespace lists the pods of each namespace in namespaces
// through conn and returns, per namespace, the sorted unique images its pods
// run, counting only pods that pass labelFilters and images that pass
// imgFilter. It never fetches pull secrets.
//
// One list per namespace rather than one cluster-wide list: a namespace-scoped
// service account may list pods only where it was granted, and the API
// connection answers a forbidden cluster-wide list with nothing, which would
// leave every image silently unlabeled.
func clusterImagesByNamespace(conn shared.Connection, namespaces []string, labelFilters *LabelSelectorFilters, imgFilter FilterOpts) (map[string][]string, error) {
	kind := gvkString(corev1.SchemeGroupVersion.WithKind("pods"))
	out := make(map[string][]string, len(namespaces))
	for _, ns := range namespaces {
		res, err := conn.Resources(kind, "", ns)
		if err != nil {
			return nil, err
		}
		if res == nil {
			continue
		}
		set := map[string]struct{}{}
		for _, obj := range res.Resources {
			pod, ok := obj.(*corev1.Pod)
			if !ok || pod.Namespace != ns || !labelFilters.MatchObject(pod) {
				continue
			}
			for _, ref := range podImageRefs(pod) {
				if !imgFilter.skip(ref) {
					set[ref] = struct{}{}
				}
			}
		}
		if len(set) == 0 {
			continue
		}
		refs := make([]string, 0, len(set))
		for ref := range set {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		out[ns] = refs
	}
	return out, nil
}

// imageRefs returns the image references of the registry-image assets in assets.
func imageRefs(assets []*inventory.Asset) []string {
	var refs []string
	for _, a := range assets {
		if isImageAsset(a) {
			refs = append(refs, a.Connections[0].Host)
		}
	}
	return refs
}

// applyNamespaceStageImageLabels labels the image assets of one namespace stage.
// With the verdict option from the cluster stage it applies those verdicts; the
// sentinel means they did not fit, so no image is labeled and a warning says so;
// without the option (the stage was started directly) the namespace is the only
// one in scope, so its own labels are the verdict.
func applyNamespaceStageImageLabels(assets []*inventory.Asset, cfg *inventory.Config, nsName string, nsLabels map[string]string, patterns []string) error {
	if len(patterns) == 0 {
		return nil
	}
	raw, ok := cfg.Options[shared.OPTION_INHERIT_NAMESPACE_LABELS_VERDICTS]
	if !ok {
		verdicts := imageLabelVerdicts(
			map[string][]string{nsName: imageRefs(assets)},
			map[string]map[string]string{nsName: nsLabels},
			patterns,
		)
		applyImageLabelVerdicts(assets, verdicts)
		return nil
	}
	verdicts, skip, err := decodeImageLabelVerdicts(raw)
	if err != nil {
		return err
	}
	if skip {
		log.Warn().Str("namespace", nsName).Msg("too many container images with namespace label verdicts; leaving container images unlabeled")
		return nil
	}
	applyImageLabelVerdicts(assets, verdicts)
	return nil
}
