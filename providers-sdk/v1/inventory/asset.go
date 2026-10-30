// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"encoding/json"
	"errors"
	fmt "fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

// Printable Keys and Values are used by the cli/components package.
var assetPrintableKeys = []string{"name", "platform-id"}

func (a *Asset) PrintableKeys() []string {
	return assetPrintableKeys
}

func (a *Asset) PrintableValue(index int) string {
	switch assetPrintableKeys[index] {
	case "name":
		return a.Display()
	case "platform-id":
		return strings.Join(a.PlatformIds, " ")
	default:
		return a.String()
	}
}

// Display implements SelectableItem from the cli/components package.
func (a *Asset) Display() string {
	return a.HumanName()
}

func (a *Asset) HumanName() string {
	if a == nil {
		return ""
	}

	if a.Platform != nil {
		return fmt.Sprint(a.Name + " (" + a.Platform.Title + ")")
	}

	return a.Name
}

func (a *Asset) EnsurePlatformID(ids ...string) {
	if a.PlatformIds == nil {
		a.PlatformIds = ids
		return
	}

	// check if the id is already included
	keys := map[string]bool{}
	for _, k := range a.PlatformIds {
		keys[k] = true
	}

	// append entry
	for _, id := range ids {
		_, ok := keys[id]
		if !ok {
			a.PlatformIds = append(a.PlatformIds, id)
		}
	}
}

func (a *Asset) AddPlatformID(ids ...string) {
	if a.PlatformIds == nil {
		a.PlatformIds = []string{}
	}

	a.PlatformIds = append(a.PlatformIds, ids...)
}

// AddLabels adds the provided labels
// existing labels with the same key will be overwritten
func (a *Asset) AddLabels(labels map[string]string) {
	if a.Labels == nil {
		a.Labels = map[string]string{}
	}

	// copy labels
	for k := range labels {
		a.Labels[k] = labels[k]
	}
}

// AnnotationAwsAccountId is the asset annotation naming the AWS account an
// asset belongs to, as the 12-digit account id. It gives every AWS-hosted
// asset, whatever scanned it, one key to be grouped by.
//
// A provider sets it where it knows the account and the asset's own identity
// does not name it, such as the workloads of an EKS cluster. Assets whose
// platform identifiers carry the account (every resource the aws provider
// discovers, EC2 instances) need no provider to set it: the platform derives
// it from those identifiers on ingest.
//
// It is an annotation rather than a label because the platform replaces an
// asset's labels on every scan but merges its annotations, so the account
// survives a later scan by a path that does not know it.
const AnnotationAwsAccountId = "mondoo.com/aws-account-id"

func (a *Asset) AddAnnotations(annotations map[string]string) {
	if len(annotations) == 0 {
		return
	}

	if a.Annotations == nil {
		a.Annotations = map[string]string{}
	}

	for k := range annotations {
		a.Annotations[k] = annotations[k]
	}
}

func NewState(state string) State {
	switch state {
	case "STATE_UNKNOWN":
		return State_STATE_UNKNOWN
	case "STATE_ERROR":
		return State_STATE_ERROR
	case "STATE_PENDING":
		return State_STATE_PENDING
	case "STATE_RUNNING":
		return State_STATE_RUNNING
	case "STATE_STOPPING":
		return State_STATE_STOPPING
	case "STATE_STOPPED":
		return State_STATE_STOPPED
	case "STATE_SHUTDOWN":
		return State_STATE_SHUTDOWN
	case "STATE_TERMINATED":
		return State_STATE_TERMINATED
	case "STATE_REBOOT":
		return State_STATE_REBOOT
	case "STATE_ONLINE":
		return State_STATE_ONLINE
	case "STATE_OFFLINE":
		return State_STATE_OFFLINE
	case "STATE_DELETED":
		return State_STATE_DELETED
	default:
		log.Debug().Str("state", state).Msg("unknown asset state")
		return State_STATE_UNKNOWN
	}
}

var AssetCategory_schemevalue = map[string]AssetCategory{
	// FIXME: DEPRECATED, remove in v15.0 vv
	"fleet": AssetCategory_CATEGORY_INVENTORY,
	// ^^
	"inventory": AssetCategory_CATEGORY_INVENTORY,
	"cicd":      AssetCategory_CATEGORY_CICD,
}

// deprecatedAssetCategories maps retired category names to the name that
// replaced them. Values here still resolve, but warn on use so v15 can drop
// them from AssetCategory_schemevalue.
// FIXME: DEPRECATED, remove in v15.0 vv
var deprecatedAssetCategories = map[string]string{
	"fleet": "inventory",
}

// ^^

// UnmarshalJSON parses either an int or a string representation of
// AssetCategory into the struct
func (s *AssetCategory) UnmarshalJSON(data []byte) error {
	// check if we have a number
	var code int32
	err := json.Unmarshal(data, &code)
	if err == nil {
		*s = AssetCategory(code)
	} else {
		var name string
		// we can ignore the error here because we just look it up and otherwise
		// tell users that we can't find the category value
		_ = json.Unmarshal(data, &name)
		name = strings.TrimSpace(name)
		code, ok := AssetCategory_schemevalue[name]
		if !ok {
			return errors.New("unknown asset category value: " + string(data))
		}
		// FIXME: DEPRECATED, remove in v15.0 vv
		if replacement, deprecated := deprecatedAssetCategories[name]; deprecated {
			log.Warn().
				Str("category", name).
				Str("use", replacement).
				Msg("deprecated asset category in inventory, please switch to the replacement")
		}
		// ^^
		*s = code
	}
	return nil
}

var mondooLabelRegex = regexp.MustCompile(`^[a-z0-9]*\.?(mondoo.com\/)[a-z0-9\-]*`)

// Merges the mondoo-specific labels from the provided root into the provided asset
func (a *Asset) AddMondooLabels(root *Asset) {
	if a.Labels == nil {
		a.Labels = map[string]string{}
	}
	for k, v := range root.Labels {
		if mondooLabelRegex.MatchString(k) {
			a.Labels[k] = v
		}
	}
}

// MergePlatform merges the provided platform into the asset's platform.
// If the asset's platform is `nil`, the provided platform is set.
func (a *Asset) MergePlatform(pf *Platform) {
	if a.Platform == nil {
		a.Platform = pf
	} else {
		a.Platform.Merge(pf)
	}
}
