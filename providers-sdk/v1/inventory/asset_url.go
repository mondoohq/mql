// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// # AssetUrl
//
// Assets are generally structured in a giant graph. However, we often find
// it difficult to reason with arbitrary graphs. As humans, we tend to
// group assets into hierarchical tree structures, that make it easy for us
// to put them into a box and reason about them.
//
// For example: A technology-centric view of the world would group a VM
// in a cloud environment like this:
//   /aws/accountX/ec2/instances/linux/debian/8.0
//
// Every entry in this path structure follows a strict schema. Thus "aws" above
// is the chosen path value for the key "technology". As you can see, some
// keys lead to predefined (limited) values (technology can be aws, azure, os,
// k8s, etc), while other keys can have (almost) arbitrary values (eg account).
//
// Providers create this schema and may extend this schema. Providers cannot
// create conflicting entries in this schema.
//
// Assets can belong to multiple URLs at the same time, which allows us to
// look at it from different perspectives.
//
// URLs enable fast lookup, but do not restrict in terms of the search.
// This support looking at e.g. linux instances on all kinds of environments
// and runtimes.

// AssetUrlSchema defines the structure for an AssetUrl.
type AssetUrlSchema struct {
	root *AssetUrlBranch

	// Possible keys that exist at any layer in this structure
	keys map[string][]*AssetUrlBranch
}

type KV struct {
	Key   string
	Value string
}

type AssetUrlChain []KV

func NewAssetUrlChain(segments []string) ([]KV, error) {
	res := make([]KV, len(segments))
	for i, segment := range segments {
		if len(segment) > ASSETURL_MAX_KEY_CHARS+ASSETURL_MAX_VALUE_CHARS {
			return nil, errors.New("asset url path segment is too long")
		}
		KVs := strings.Split(segment, "=")
		if len(KVs) != 2 {
			return nil, errors.New("asset url path segment must be formatted as key=value")
		}
		res[i].Key = KVs[0]
		res[i].Value = KVs[1]
	}
	return res, nil
}

const (
	ASSETURL_MAX_DEPTH       = 100
	ASSETURL_MAX_KEY_CHARS   = 100
	ASSETURL_MAX_VALUE_CHARS = 200
)

var (
	assetUrlKeyRegex   = regexp.MustCompile("^[a-z0-9_-]+$")
	assetUrlValueRegex = regexp.MustCompile("^[A-Za-z0-9_ .-]+$")
)

func validateKey(key string) error {
	if len(key) > ASSETURL_MAX_KEY_CHARS {
		return errors.New("asset url branch key is too long: " + key[0:100] + "...")
	}
	if key == "" {
		return errors.New("asset url branch key cannot be empty")
	}
	if !assetUrlKeyRegex.MatchString(key) {
		return errors.New("asset url branch key '" + key + "' must only contain valid characters: " + assetUrlKeyRegex.String())
	}
	return nil
}

func validateValue(value string) error {
	if len(value) > ASSETURL_MAX_VALUE_CHARS {
		return errors.New("asset url branch value is too long: " + value[0:100] + "...")
	}
	if value == "" {
		return errors.New("asset url branch value cannot be empty")
	}
	if value == "*" {
		return nil
	}
	if !assetUrlValueRegex.MatchString(value) {
		return errors.New("asset url branch value '" + value + "' must only contain valid characters: " + assetUrlKeyRegex.String())
	}
	return nil
}

func NewAssetUrlSchema(rootKey string) (*AssetUrlSchema, error) {
	if err := validateKey(rootKey); err != nil {
		return nil, err
	}

	return &AssetUrlSchema{
		root: &AssetUrlBranch{
			Key:    rootKey,
			Values: map[string]*AssetUrlBranch{},
			Depth:  1,
		},
	}, nil
}

func (a *AssetUrlSchema) Add(branch *AssetUrlBranch) error {
	if branch == nil {
		return errors.New("cannot attach empty asset url branch")
	}
	if len(branch.PathSegments) == 0 {
		return errors.New("don't know where to attach asset url branch")
	}

	urlChain, err := NewAssetUrlChain(branch.PathSegments)
	if err != nil {
		return err
	}

	found, lastKey, err := a.root.FindPath(urlChain)
	if err != nil {
		return errors.New("failed to add: " + err.Error())
	}

	if found == nil {
		return errors.New("failed to attach asset url branch to any existing subtree for: " + strings.Join(branch.PathSegments, "/"))
	}

	if err = branch.validate(); err != nil {
		return errors.New("failed to add url branch: " + err.Error())
	}

	branch.setDepth(found.Depth + 1)
	found.Values[lastKey] = copyBranch(branch)
	return nil
}

func copyBranch(b *AssetUrlBranch) *AssetUrlBranch {
	if b == nil {
		return nil
	}

	res := &AssetUrlBranch{
		PathSegments: make([]string, len(b.PathSegments)),
		Key:          b.Key,
		Values:       make(map[string]*AssetUrlBranch, len(b.Values)),
		Title:        b.Title,
		References:   make([]string, len(b.References)),
		Depth:        b.Depth,
	}

	copy(res.PathSegments, b.PathSegments)
	copy(res.References, b.References)

	for k, v := range b.Values {
		res.Values[k] = copyBranch(v)
	}

	return res
}

func (a *AssetUrlBranch) setDepth(i uint32) {
	a.Depth = i
	next := i + 1
	for _, v := range a.Values {
		if v != nil {
			v.setDepth(next)
		}
	}
}

func (a *AssetUrlBranch) validate() error {
	branches := []*AssetUrlBranch{a}
	i := 0
	for i < len(branches) {
		branch := branches[i]
		i++

		if len(branch.References) != 0 {
			if len(branch.Key) != 0 {
				return errors.New("asset url segment with reference cannot have a key set")
			}
			if len(branch.Values) != 0 {
				return errors.New("asset url segment with reference cannot have values set")
			}
			continue
		}

		if branch.Key != "" {
			if err := validateKey(branch.Key); err != nil {
				return err
			}
			for value, next := range branch.Values {
				if err := validateValue(value); err != nil {
					return err
				}
				if next != nil {
					branches = append(branches, next)
				}
			}
		} else {
			if len(branch.Values) != 0 {
				return errors.New("asset url segment without key must not have values set")
			}
		}

	}

	return nil
}

func (a *AssetUrlBranch) FindPath(path AssetUrlChain) (*AssetUrlBranch, string, error) {
	if len(path) > ASSETURL_MAX_DEPTH {
		return nil, "", errors.New("asset url branch path is too long")
	}

	curBranch := a
	for segmentIdx, segment := range path {
		key := segment.Key
		if key != curBranch.Key {
			return nil, "", errors.New("asset url path key is invalid (expected '" + curBranch.Key + "', got '" + key + "')")
		}

		value := segment.Value
		if err := validateValue(value); err != nil {
			return nil, "", err
		}

		// ending condition on the last element
		if segmentIdx == len(path)-1 {
			return curBranch, value, nil
		}

		if curBranch.Values == nil {
			return nil, "", errors.New("asset url search ended prematurely, no more keys in this chain")
		}

		branch, ok := curBranch.Values[value]
		if !ok {
			branch, ok = curBranch.Values["*"]
			if !ok {
				return nil, "", errors.New("cannot find asset url branch for '" + key + "=" + value + "'")
			}
		}
		if branch == nil {
			return nil, "", errors.New("ran into premature end for asset url branch '" + key + "=" + value + "'")
		}
		curBranch = branch
	}

	return curBranch, "", nil
}

func (a *AssetUrlSchema) cloneBranch(branch *AssetUrlBranch, depth uint32, isDereferenced bool) (*AssetUrlBranch, error) {
	if depth > 1000 {
		return nil, errors.New("maximum depth reached for asset url during clone (look for circular branch references)")
	}

	if len(branch.References) != 0 {
		if isDereferenced {
			return nil, errors.New("dereferenced an asset url branch with more references (reference to = '" + strings.Join(branch.References, "/") + "')")
		}

		urlChain, err := NewAssetUrlChain(branch.References)
		if err != nil {
			return nil, err
		}

		found, lastKey, err := a.root.FindPath(urlChain)
		if err != nil {
			return nil, errors.New("failed to add asset url reference: " + err.Error())
		}

		branch = found.Values[lastKey]
		return a.cloneBranch(branch, depth, true)
	}

	res := &AssetUrlBranch{
		Key:    branch.Key,
		Title:  branch.Title,
		Values: make(map[string]*AssetUrlBranch, len(branch.Values)),
		Depth:  depth,
	}

	for k, v := range branch.Values {
		if v == nil {
			res.Values[k] = nil
			continue
		}

		b, err := a.cloneBranch(v, depth+1, false)
		if err != nil {
			return nil, err
		}
		b.ParentValue = k
		b.Parent = res
		res.Values[k] = b
	}

	return res, nil
}

func (a *AssetUrlSchema) RefreshCache() error {
	a.keys = map[string][]*AssetUrlBranch{}

	branches := []*AssetUrlBranch{a.root}
	i := 0
	for i < len(branches) {
		branch := branches[i]
		i++

		if len(branch.References) != 0 {
			res, err := a.cloneBranch(branch, branch.Depth, false)
			if err != nil {
				return err
			}

			branch.Key = res.Key
			branch.Title = res.Title
			branch.Values = res.Values
		}

		a.keys[branch.Key] = append(a.keys[branch.Key], branch)

		for k, next := range branch.Values {
			if next != nil {
				next.Parent = branch
				next.ParentValue = k
				branches = append(branches, next)
			}
		}
	}

	return nil
}

func (a *AssetUrlSchema) BuildQueries(kvs []KV) []AssetUrlChain {
	var nodes []*AssetUrlBranch
	var values []string
	for i := range kvs {
		kv := kvs[i]
		nuNodes := a.keys[kv.Key]
		nodes = append(nodes, nuNodes...)
		for range nuNodes {
			values = append(values, kv.Value)
		}
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		return nodes[i].Depth < nodes[j].Depth
	})

	var res []AssetUrlChain
	for len(nodes) != 0 {
		lastIdx := len(nodes) - 1
		cur := nodes[lastIdx]
		curValue := values[lastIdx]
		nodes = nodes[:lastIdx]
		values = values[:lastIdx]

		query := buildParentQuery(cur, curValue, kvs)
		if len(query) == 0 {
			continue
		}

		res = append(res, query)
		// since this is a valid chain, let's check the list of remaining nodes
		// if anything can get eliminated
		for cur != nil {
			nodes = filterArr(nodes, cur)
			cur = cur.Parent
		}
	}
	return res
}

func filterArr[T comparable](arr []T, entry T) []T {
	for i := range arr {
		if arr[i] == entry {
			arr[i] = arr[len(arr)-1]
			return arr[:len(arr)-1]
		}
	}
	return arr
}

// filter a key-value combination and return the filtered element if any is found
func filterKV(kvs []KV, key string, value string) ([]KV, *KV) {
	found := -1
	for i := range kvs {
		if kvs[i].Key == key && (value == "*" || kvs[i].Value == value) {
			found = i
			break
		}
	}
	if found == -1 {
		return kvs, nil
	}

	last := len(kvs) - 1
	kvs[found], kvs[last] = kvs[last], kvs[found]
	return kvs[:last], &kvs[last]
}

// Build a parent query from a leaf in an asset url schema and a given value
// in the parent branch under which this leaf was located. The required KVs
// are a list of identifiers that should be contained (or supported) by the
// resulting asset URL chain.
func buildParentQuery(leaf *AssetUrlBranch, value string, requiredKVs []KV) AssetUrlChain {
	res := make([]KV, leaf.Depth)

	cur := leaf
	curValue := value
	var found *KV
	for cur != nil {
		requiredKVs, found = filterKV(requiredKVs, cur.Key, curValue)
		if found != nil {
			res[cur.Depth-1] = KV{Key: found.Key, Value: found.Value}
		} else {
			res[cur.Depth-1] = KV{Key: cur.Key, Value: curValue}
		}

		curValue = cur.ParentValue
		cur = cur.Parent
	}

	// if we have any KVs that remain on this chain, that means we haven't found
	// a valid query
	if len(requiredKVs) != 0 {
		return nil
	}

	return res
}

func (a *AssetUrlSchema) PathToAssetUrlChain(path []string) (AssetUrlChain, error) {
	cur := a.root
	res := make([]KV, len(path))
	for idx, term := range path {
		if cur == nil {
			return nil, errors.New("invalid asset url, no more definitions at depth " + strconv.Itoa(idx) + " (value: " + term + ")")
		}

		next, ok := cur.Values[term]
		if !ok {
			next, ok = cur.Values["*"]
			if !ok {
				return nil, errors.New("invalid asset url, value not found: " + cur.Key + "=" + term)
			}
		}

		res[idx] = KV{cur.Key, term}
		cur = next
	}

	return res, nil
}

func (a *AssetUrlSchema) PathTitles(path AssetUrlChain) ([]string, error) {
	found, _, err := a.root.FindPath(path)
	if err != nil {
		return nil, err
	}

	res := make([]string, len(path))
	cur := found
	for i := len(path) - 1; i >= 0; i-- {
		if cur == nil {
			return nil, errors.New("invalid asset url, no more definitions at depth " + strconv.Itoa(i))
		}

		if cur.Title != "" {
			res[i] = cur.Title
		} else {
			res[i] = cur.Key
		}
		cur = cur.Parent
	}

	return res, nil
}

// FindChild returns the child branch for the given path.
func (a *AssetUrlSchema) FindChild(path AssetUrlChain) (*AssetUrlBranch, error) {
	found, _, err := a.root.FindPath(path)
	if err != nil {
		return nil, err
	}

	if found == nil {
		return nil, errors.New("invalid asset url, path not found")
	}

	last := path[len(path)-1]
	if b, ok := found.Values[last.Value]; ok {
		return b, nil
	} else if b, ok := found.Values["*"]; ok {
		return b, nil
	}

	return nil, errors.New("invalid asset url, value not found")
}

func (a *AssetUrlSchema) RootKey() string {
	return a.root.Key
}
