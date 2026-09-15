// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/filteropts"
)

type DiscoveryFilters struct {
	Ec2                  Ec2DiscoveryFilters
	Ecr                  EcrDiscoveryFilters
	Ecs                  EcsDiscoveryFilters
	S3                   S3DiscoveryFilters
	General              GeneralDiscoveryFilters
	PropagateAccountTags bool
	// AccountTags, when non-empty, is used as the source of account-level tags
	// for PropagateAccountTags instead of calling Organizations. Intended for
	// callers that can fetch tags from a management-account context (member
	// accounts can't reach Organizations APIs).
	AccountTags map[string]string
}

func DiscoveryFiltersFromOpts(opts map[string]string) DiscoveryFilters {
	d := DiscoveryFilters{
		General: GeneralDiscoveryFilters{
			Regions:        filteropts.ParseCsvSliceOpt(opts, "regions"),
			ExcludeRegions: filteropts.ParseCsvSliceOpt(opts, "exclude:regions"),
			Tags:           parseMapOpt(opts, "tag:"),
			ExcludeTags:    parseMapOpt(opts, "exclude:tag:"),
		},
		Ec2: Ec2DiscoveryFilters{
			InstanceIds:        filteropts.ParseCsvSliceOpt(opts, "ec2:instance-ids"),
			ExcludeInstanceIds: filteropts.ParseCsvSliceOpt(opts, "ec2:exclude:instance-ids"),
		},
		Ecr: EcrDiscoveryFilters{
			Tags:                   filteropts.ParseCsvSliceOpt(opts, "ecr:tags"),
			ExcludeTags:            filteropts.ParseCsvSliceOpt(opts, "ecr:exclude:tags"),
			PrivateRepositoryNames: filteropts.ParseCsvSliceOpt(opts, "ecr:private-repository-names"),
			PublicRepositoryNames:  filteropts.ParseCsvSliceOpt(opts, "ecr:public-repository-names"),
			Scope:                  parseStringOpt(opts, "ecr:scope"),
		},
		Ecs: EcsDiscoveryFilters{
			OnlyRunningContainers: filteropts.ParseBoolOpt(opts, "ecs:only-running-containers", false),
			DiscoverInstances:     filteropts.ParseBoolOpt(opts, "ecs:discover-instances", false),
			DiscoverImages:        filteropts.ParseBoolOpt(opts, "ecs:discover-images", false),
		},
		S3: S3DiscoveryFilters{
			BucketNames:        filteropts.ParseCsvSliceOpt(opts, "s3:bucket-names"),
			ExcludeBucketNames: filteropts.ParseCsvSliceOpt(opts, "s3:exclude:bucket-names"),
		},
		PropagateAccountTags: filteropts.ParseBoolOpt(opts, "propagate-account-tags", false),
		AccountTags:          parseMapOpt(opts, "account-tag:"),
	}

	// FIXME: DEPRECATED, remove in v15.0 vv
	// `ec2:tag:` and `ec2:exclude:tag:` were folded into the general `tag:` and
	// `exclude:tag:` filters. They still apply, but warn, so the removal lands
	// on users who have already been told rather than silently dropping a
	// filter they rely on to scope a scan.
	mergeDeprecatedTagOpt("ec2:tag:", "tag:", parseMapOpt(opts, "ec2:tag:"), d.General.Tags)
	mergeDeprecatedTagOpt("ec2:exclude:tag:", "exclude:tag:", parseMapOpt(opts, "ec2:exclude:tag:"), d.General.ExcludeTags)
	// ^^
	return d
}

// mergeDeprecatedTagOpt folds a retired `ec2:`-prefixed tag filter into its
// general replacement, warning that the option is deprecated. The replacement
// wins on conflict, so a key carrying a different value under each option gets
// a second warning naming the value being dropped.
// FIXME: DEPRECATED, remove in v15.0 vv
func mergeDeprecatedTagOpt(deprecated, replacement string, from, into map[string]string) {
	if len(from) == 0 {
		return
	}

	log.Warn().
		Str("option", deprecated).
		Str("use", replacement).
		Msg("deprecated AWS discovery filter, please switch to the replacement")

	for k, v := range from {
		if existing, exists := into[k]; exists {
			if existing != v {
				log.Warn().
					Str("option", deprecated+k).
					Str("ignored", v).
					Str("using", existing).
					Msg("filter key set by both the deprecated and the replacement option, the deprecated value is ignored")
			}
			continue
		}
		into[k] = v
	}
}

type GeneralDiscoveryFilters struct {
	Regions        []string
	ExcludeRegions []string
	// note: values can be in a CSV format, e.g. "env": "prod,staging"
	Tags map[string]string
	// note: values can be in a CSV format, e.g. "env": "prod,staging"
	ExcludeTags map[string]string
}

func (f GeneralDiscoveryFilters) HasTags() bool {
	return len(f.Tags) > 0 || len(f.ExcludeTags) > 0
}

// helper function to improve the readability of filter application
// some resources do not support server-side filtering, so we need to apply filters client-side
func (f GeneralDiscoveryFilters) IsFilteredOutByTags(resourceTags map[string]string) bool {
	return !f.MatchesIncludeTags(resourceTags) || f.MatchesExcludeTags(resourceTags)
}

func (f GeneralDiscoveryFilters) MatchesIncludeTags(resourceTags map[string]string) bool {
	if len(f.Tags) == 0 {
		return true
	}

	for k, csv := range f.Tags {
		for v := range strings.SplitSeq(csv, ",") {
			if tagValue, ok := resourceTags[k]; ok && tagValue == v {
				return true
			}
		}
	}
	return false
}

// note: if this function returns `true`, it means that the resource should be skipped
func (f GeneralDiscoveryFilters) MatchesExcludeTags(resourceTags map[string]string) bool {
	for k, csv := range f.ExcludeTags {
		for v := range strings.SplitSeq(csv, ",") {
			if tagValue, ok := resourceTags[k]; ok && tagValue == v {
				return true
			}
		}
	}
	return false
}

// when possible, we should use AWS API filters to reduce data transfer
func (f GeneralDiscoveryFilters) ToServerSideEc2Filters() []ec2types.Filter {
	filters := []ec2types.Filter{}
	for k, v := range f.Tags {
		filters = append(filters, ec2types.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", k)),
			Values: strings.Split(v, ","),
		})
	}
	return filters
}

type Ec2DiscoveryFilters struct {
	InstanceIds        []string
	ExcludeInstanceIds []string
}

// note: if this function returns `true`, it means that the resource should be skipped
func (f Ec2DiscoveryFilters) MatchesExcludeInstanceIds(instanceId *string) bool {
	return instanceId != nil && slices.Contains(f.ExcludeInstanceIds, *instanceId)
}

// Values for EcrDiscoveryFilters.Scope. An empty Scope means both.
const (
	EcrScopePrivate = "private"
	EcrScopePublic  = "public"
)

type EcrDiscoveryFilters struct {
	Tags                   []string
	ExcludeTags            []string
	PrivateRepositoryNames []string
	PublicRepositoryNames  []string
	// Scope restricts discovery to one registry visibility. Allowed values are
	// EcrScopePrivate and EcrScopePublic; an empty string means both.
	Scope string
}

func (f EcrDiscoveryFilters) IsFilteredOutByTags(imageTags []string) bool {
	return !f.MatchesIncludeTags(imageTags) || f.MatchesExcludeTags(imageTags)
}

func (f EcrDiscoveryFilters) MatchesIncludeTags(imageTags []string) bool {
	if len(f.Tags) == 0 {
		return true
	}

	for _, filterTag := range f.Tags {
		if slices.Contains(imageTags, filterTag) {
			return true
		}
	}

	return false
}

// note: if this function returns `true`, it means that the resource should be skipped
func (f EcrDiscoveryFilters) MatchesExcludeTags(imageTags []string) bool {
	for _, filterTag := range f.ExcludeTags {
		if slices.Contains(imageTags, filterTag) {
			return true
		}
	}

	return false
}

// ECRDescribeRepositoriesNameLimit is the maximum number of repository names AWS
// accepts in the repositoryNames parameter of a single DescribeRepositories request.
const ECRDescribeRepositoriesNameLimit = 100

// Splits the repository names in batches. 0 batches are returned when no names are specified.
func (f EcrDiscoveryFilters) PrivateRepositoryNameBatches() [][]string {
	return batchRepositoryNames(f.PrivateRepositoryNames)
}

// Splits the repository names in batches. 0 batches are returned when no names are specified.
func (f EcrDiscoveryFilters) PublicRepositoryNameBatches() [][]string {
	return batchRepositoryNames(f.PublicRepositoryNames)
}

func batchRepositoryNames(names []string) [][]string {
	if len(names) == 0 {
		return nil
	}
	batches := make([][]string, 0, (len(names)+ECRDescribeRepositoriesNameLimit-1)/ECRDescribeRepositoriesNameLimit)
	for batch := range slices.Chunk(names, ECRDescribeRepositoriesNameLimit) {
		batches = append(batches, batch)
	}
	return batches
}

type EcsDiscoveryFilters struct {
	OnlyRunningContainers bool
	DiscoverImages        bool
	DiscoverInstances     bool
}

type S3DiscoveryFilters struct {
	BucketNames        []string
	ExcludeBucketNames []string
}

// note: if this function returns `true`, it means that the bucket should be skipped
func (f S3DiscoveryFilters) IsFilteredOut(bucketName string) bool {
	if len(f.BucketNames) > 0 && !slices.Contains(f.BucketNames, bucketName) {
		return true
	}
	return slices.Contains(f.ExcludeBucketNames, bucketName)
}

func (f EcsDiscoveryFilters) MatchesOnlyRunningContainers(containerState string) bool {
	if !f.OnlyRunningContainers {
		return true
	}
	return containerState == "RUNNING"
}

// Given a map of options and a key prefix, return a map of key-value pairs
// where the keys start with the given prefix, with the prefix removed.
// Example:
// keyPrefix = "tag:"
// opts = {"tag:env": "prod", "tag:role": "web"}
// returns {"env": "prod", "role": "web"}
func parseMapOpt(opts map[string]string, keyPrefix string) map[string]string {
	res := map[string]string{}
	for k, v := range opts {
		if k == "" || v == "" {
			continue
		}
		if !strings.HasPrefix(k, keyPrefix) {
			continue
		}
		res[strings.TrimPrefix(k, keyPrefix)] = v
	}
	return res
}

// Given a map of options and a key, return the string value for that key.
// Returns "" if the key is missing or its value is empty.
// Example:
// key = "ecr:scope"
// opts = {"ecr:scope": "private"}
// returns "private"
func parseStringOpt(opts map[string]string, key string) string {
	return opts[key]
}
