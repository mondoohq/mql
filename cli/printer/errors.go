// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package printer

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
)

// Rendering classified errors (ADR 046 §7).
//
// A classified error leads with its kind and what the user can grant, so the
// fix reads before the target's own message. Not applicable is dimmed, like
// version skew: nothing failed, the thing asked about does not exist here.
// Every other kind stays an error.

// fieldError renders a failed value.
func (print *Printer) fieldError(err error) string {
	e := classified(err)
	if e == nil {
		return print.Error(strings.TrimSpace(err.Error()))
	}
	text := describeError(e, 0)
	// An error built without an upstream error has its kind's label as the
	// message, which describeError already wrote.
	if msg := strings.TrimSpace(err.Error()); msg != e.Kind.Label() {
		text += ": " + msg
	}
	return print.kindColor(e.Kind, text)
}

func (print *Printer) kindColor(kind llx.ErrorKind, text string) string {
	if kind == llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE {
		return print.Disabled(text)
	}
	return print.Error(text)
}

// classified returns err's classification, or nil when it has none.
func classified(err error) *llx.Error {
	var e *llx.Error
	if !errors.As(err, &e) || e.Kind == llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		return nil
	}
	return e
}

// describeError names the kind, the partition, and the permissions, e.g.
// "access denied in eu-west-1 (ec2:DescribeAddresses)". A count above one is
// written after the partition: "access denied x784 (ec2:DescribeTags)".
func describeError(e *llx.Error, count int) string {
	var res strings.Builder
	res.WriteString(e.Kind.Label())
	if e.ScopeID != "" {
		res.WriteString(" in ")
		res.WriteString(e.ScopeID)
	}
	if count > 1 {
		res.WriteString(" x")
		res.WriteString(strconv.Itoa(count))
	}
	if len(e.Permissions) != 0 {
		// Sorted, so the same grants read the same whatever order the call
		// site named them in. A copy: the error is shared.
		perms := append([]string(nil), e.Permissions...)
		sort.Strings(perms)
		res.WriteString(" (")
		res.WriteString(strings.Join(perms, ", "))
		res.WriteString(")")
	}
	return res.String()
}

// errorGroup is one line of the repeat summary: every classified error that
// shares (kind, scope, scope_id, permissions).
type errorGroup struct {
	key   string
	first *llx.Error
	count int
}

func errorGroupKey(e *llx.Error) string {
	perms := append([]string(nil), e.Permissions...)
	sort.Strings(perms)
	return e.Kind.String() + "\x00" + e.Scope.String() + "\x00" + e.ScopeID + "\x00" + strings.Join(perms, "\x00")
}

// collectErrors counts the classified errors in data and everything nested in
// it: fields of a block, entries of a list.
func collectErrors(data *llx.RawData, groups map[string]*errorGroup) {
	if data == nil {
		return
	}
	if e := classified(data.Error); e != nil {
		key := errorGroupKey(e)
		if g, ok := groups[key]; ok {
			g.count++
		} else {
			groups[key] = &errorGroup{key: key, first: e, count: 1}
		}
	}
	collectValueErrors(data.Value, groups)
}

func collectValueErrors(value any, groups map[string]*errorGroup) {
	switch v := value.(type) {
	case *llx.RawData:
		collectErrors(v, groups)
	case map[string]any:
		for _, cur := range v {
			collectValueErrors(cur, groups)
		}
	case []any:
		for _, cur := range v {
			collectValueErrors(cur, groups)
		}
	}
}

// errorSummary is one line per group of classified errors that repeats, so a
// scan that hits 784 identical denials also says it once, with the grant that
// fixes all of them. A group seen once already reads in full where it is.
func (print *Printer) errorSummary(results map[string]*llx.RawResult) []string {
	groups := map[string]*errorGroup{}
	for _, r := range results {
		if r != nil {
			collectErrors(r.Data, groups)
		}
	}

	var repeated []*errorGroup
	for _, g := range groups {
		if g.count > 1 {
			repeated = append(repeated, g)
		}
	}
	sort.Slice(repeated, func(i, j int) bool {
		if repeated[i].count != repeated[j].count {
			return repeated[i].count > repeated[j].count
		}
		return repeated[i].key < repeated[j].key
	})

	lines := make([]string, len(repeated))
	for i, g := range repeated {
		lines[i] = print.kindColor(g.first.Kind, describeError(g.first, g.count))
	}
	return lines
}

// coverageGapLines is one dimmed line per (kind, scope_id) group of the parts
// that could not be read (ADR 046 §8). The value above them is what was read;
// these say what it is missing and which grants would complete it.
func (print *Printer) coverageGapLines(results map[string]*llx.RawResult) []string {
	type group struct {
		kind    llx.ErrorKind
		scopeID string
		perms   map[string]struct{}
		// Unclassified gaps have no kind to name them, so their message does.
		msg string
	}
	groups := map[string]*group{}
	for _, r := range results {
		if r == nil || r.Data == nil {
			continue
		}
		for _, gap := range r.Data.CoverageGaps {
			key := gap.Kind.String() + "\x00" + gap.ScopeID
			g, ok := groups[key]
			if !ok {
				g = &group{kind: gap.Kind, scopeID: gap.ScopeID, perms: map[string]struct{}{}}
				if gap.Kind == llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
					g.msg = strings.TrimSpace(gap.Error())
				}
				groups[key] = g
			}
			for _, p := range gap.Permissions {
				g.perms[p] = struct{}{}
			}
		}
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	lines := make([]string, len(keys))
	for i, k := range keys {
		g := groups[k]
		perms := make([]string, 0, len(g.perms))
		for p := range g.perms {
			perms = append(perms, p)
		}
		sort.Strings(perms)
		text := "coverage gap: " + describeError(&llx.Error{Kind: g.kind, ScopeID: g.scopeID, Permissions: perms}, 0)
		if g.msg != "" && g.msg != g.kind.Label() {
			text += ": " + g.msg
		}
		lines[i] = print.Disabled(text)
	}
	return lines
}

// appendLines adds lines below a printed result.
func appendLines(body string, lines []string) string {
	if len(lines) == 0 {
		return body
	}
	var res strings.Builder
	res.WriteString(body)
	if body != "" && !strings.HasSuffix(body, "\n") {
		res.WriteByte('\n')
	}
	res.WriteString(strings.Join(lines, "\n"))
	if strings.HasSuffix(body, "\n") {
		res.WriteByte('\n')
	}
	return res.String()
}
