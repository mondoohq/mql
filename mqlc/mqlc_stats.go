// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

type CompilerStats interface {
	WalkSorted(f func(resource string, field string, info FieldStat))
	WalkCode(f func(code string, stats CompilerStats))

	// calls used by mqlc compiler internally:
	SetAutoExpand(on bool)
	CallResource(name string)
	CallField(resource string, field *resources.Field)
	// returns an object to track the compilation of a specific query
	CompileQuery(query string) CompilerStats
}

type FieldStat struct {
	Time       int64
	Type       types.Type
	AutoExpand bool
}

type compilerStatsNull struct{}

// interface validation
var _ CompilerStats = compilerStatsNull{}

func (c compilerStatsNull) WalkSorted(f func(resource string, field string, info FieldStat)) {}
func (c compilerStatsNull) WalkCode(f func(code string, stats CompilerStats))                {}
func (c compilerStatsNull) SetAutoExpand(on bool)                                            {}
func (c compilerStatsNull) CallResource(name string)                                         {}
func (c compilerStatsNull) CallField(resource string, field *resources.Field)                {}
func (c compilerStatsNull) CompileQuery(query string) CompilerStats                          { return c }

type compilerStats struct {
	ResourceFields map[string]map[string]FieldStat

	// indicates that the following resource fields are done during
	// field expansion code (e.g. expand user => name + uid + home)
	isAutoExpand bool
}

// interface validation
var _ CompilerStats = &compilerStats{}

func newCompilerStats() *compilerStats {
	return &compilerStats{
		ResourceFields: map[string]map[string]FieldStat{},
	}
}

func (c *compilerStats) SetAutoExpand(on bool) {
	if c == nil {
		return
	}
	c.isAutoExpand = on
}

func (c *compilerStats) CallResource(name string) {
	if _, ok := c.ResourceFields[name]; !ok {
		c.ResourceFields[name] = map[string]FieldStat{
			"": {
				Time: time.Now().UnixNano(),
			},
		}
	}
}

func (c *compilerStats) CallField(resource string, field *resources.Field) {
	c.CallResource(resource)
	if _, ok := c.ResourceFields[resource][field.Name]; ok {
		return
	}
	c.ResourceFields[resource][field.Name] = FieldStat{
		Time:       time.Now().UnixNano(),
		Type:       types.Type(field.Type),
		AutoExpand: c.isAutoExpand,
	}
}

func (c *compilerStats) CompileQuery(query string) CompilerStats { return c }

func (c *compilerStats) WalkSorted(f func(resource string, field string, info FieldStat)) {
	sortedResources := make([]string, len(c.ResourceFields))
	i := 0
	for key := range c.ResourceFields {
		sortedResources[i] = key
		i++
	}
	sort.Slice(sortedResources, func(i, j int) bool {
		return c.ResourceFields[sortedResources[i]][""].Time < c.ResourceFields[sortedResources[j]][""].Time
	})

	for _, resource := range sortedResources {
		m := c.ResourceFields[resource]

		fields := make([]string, len(m))
		i := 0
		for name := range m {
			fields[i] = name
			i++
		}

		sort.Slice(fields, func(i, j int) bool {
			return m[fields[i]].Time < m[fields[j]].Time
		})

		for _, field := range fields {
			f(resource, field, m[field])
		}
	}
}

func (c *compilerStats) WalkCode(f func(code string, stats CompilerStats)) {}

// interface validation
var _ CompilerStats = &compilerMultiStats{}

type compilerMultiStats struct {
	stats map[string]*compilerStats
	lock  sync.Mutex

	AutoExpand bool
}

func newCompilerMultiStats() *compilerMultiStats {
	return &compilerMultiStats{
		stats: map[string]*compilerStats{},
	}
}

func (c *compilerMultiStats) WalkSorted(f func(resource string, field string, info FieldStat)) {
	c.lock.Lock()
	defer c.lock.Unlock()

	aggregate := newCompilerStats()
	for _, v := range c.stats {
		v.WalkSorted(func(resource, field string, info FieldStat) {
			aggregate.CallResource(resource)
			aggregate.ResourceFields[resource][field] = info
		})
	}

	aggregate.WalkSorted(f)
}

func (c *compilerMultiStats) WalkCode(f func(code string, stats CompilerStats)) {
	c.lock.Lock()
	defer c.lock.Unlock()

	for k, v := range c.stats {
		f(k, v)
	}
}

// The errors currently are soft only. I'm not sure if we shouldn't switch
// them to be much stricter, because this is something that should never
// happen and points to bad coding errors.

func (c *compilerMultiStats) SetAutoExpand(on bool) {
	log.Error().Msg("using uninitialized compiler multi-stats, internal error")
}

func (c *compilerMultiStats) CallResource(name string) {
	log.Error().Msg("using uninitialized compiler multi-stats, internal error")
}

func (c *compilerMultiStats) CallField(resource string, field *resources.Field) {
	log.Error().Msg("using uninitialized compiler multi-stats, internal error")
}

func (c *compilerMultiStats) CompileQuery(query string) CompilerStats {
	c.lock.Lock()
	defer c.lock.Unlock()

	existing, ok := c.stats[query]
	if ok {
		return existing
	}

	res := newCompilerStats()
	c.stats[query] = res
	return res
}
