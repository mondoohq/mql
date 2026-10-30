// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package types

import "maps"

import "sync"

// StringSet is a map that contains unique strings
type StringSet struct{ sync.Map }

// Store a string to the set
func (c *StringSet) Store(k string) { c.Map.Store(k, struct{}{}) }

// Delete a key from the set
func (c *StringSet) Delete(k string) { c.Map.Delete(k) }

// Exist returns true if the string exists in the set
func (c *StringSet) Exist(k string) bool {
	_, ok := c.Load(k)
	return ok
}

// Range walks the list of keys in the set and executes the function
// as long as it returns true
func (c *StringSet) Range(f func(string) bool) {
	c.Map.Range(func(key, value any) bool {
		return f(key.(string))
	})
}

// List all keys
func (c *StringSet) List() []string {
	res := []string{}
	c.Map.Range(func(key, value any) bool {
		res = append(res, key.(string))
		return true
	})
	return res
}

// StringToStrings is a map that contains a list of strings for every string stored
type StringToStrings struct{ sync.Map }

// Store a string association to the set
func (s *StringToStrings) Store(key string, value string) {
	v, ok := s.Map.Load(key)
	var list *StringSet
	if !ok {
		list = &StringSet{}
		s.Map.Store(key, list)
	} else {
		list = v.(*StringSet)
	}
	list.Store(value)
}

// Exist a key-value connection
func (s *StringToStrings) Exist(key string, value string) bool {
	v, ok := s.Map.Load(key)
	if !ok {
		return false
	}
	return v.(*StringSet).Exist(value)
}

// List all keys and their associations
func (s *StringToStrings) List() map[string][]string {
	res := make(map[string][]string)
	s.Range(func(key, value any) bool {
		res[key.(string)] = value.(*StringSet).List()
		return true
	})
	return res
}

// ListKey in the set
func (s *StringToStrings) ListKey(key string) []string {
	v, ok := s.Load(key)
	if !ok {
		return nil
	}
	return v.List()
}

// Load a key
func (s *StringToStrings) Load(key string) (*StringSet, bool) {
	v, ok := s.Map.Load(key)
	if !ok {
		return nil, false
	}
	return v.(*StringSet), true
}

// Delete a key-value connection
func (s *StringToStrings) Delete(key string, value string) {
	set, ok := s.Load(key)
	if !ok {
		return
	}

	set.Delete(value)

	empty := true
	set.Range(func(_ string) bool {
		empty = false
		return false
	})

	if empty {
		s.Map.Delete(key)
	}
}

// mapValuesToSlice returns a slice with the values of the map
func MapValuesToSlice[K comparable, V any](m map[K]V) []V {
	var slice []V
	for _, v := range m {
		slice = append(slice, v)
	}
	return slice
}

// mergeMaps merges 2 maps. If there are duplicate keys the values from m2 will override
// the values from m1.
func MergeMaps[K comparable, V any](m1 map[K]V, m2 map[K]V) map[K]V {
	maps.Copy(m1, m2)
	return m1
}
