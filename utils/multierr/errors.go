// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package multierr

import (
	"strconv"
	"strings"
)

// withMessage and methods are taken from https://github.com/pkg/errors
// under BSD-2-Clause license

type withMessage struct {
	cause error
	msg   string
}

func (w withMessage) Error() string { return w.msg + ": " + w.cause.Error() }
func (w withMessage) Cause() error  { return w.cause }
func (w withMessage) Unwrap() error { return w.cause }

func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return withMessage{
		cause: err,
		msg:   message,
	}
}

type Errors struct {
	Errors []error
}

func (m *Errors) Add(err ...error) {
	for i := range err {
		if err[i] != nil {
			m.Errors = append(m.Errors, err[i])
		}
	}
}

func (m *Errors) Filter(f func(e error) bool) *Errors {
	res := Errors{}
	for i := range m.Errors {
		cur := m.Errors[i]
		if !f(cur) {
			res.Errors = append(res.Errors, cur)
		}
	}
	return &res
}

func (m *Errors) Error() string {
	var res strings.Builder

	n := strconv.Itoa(len(m.Errors))
	if n == "1" {
		res.WriteString("1 error occurred:\n")
	} else {
		res.WriteString(n + " errors occurred:\n")
	}

	for i := range m.Errors {
		res.WriteString("\t* ")
		res.WriteString(m.Errors[i].Error())
		res.WriteByte('\n')
	}
	return res.String()
}

// Deduplicate returns the errors with duplicates (by message) removed,
// preserving first-occurrence order. Order preservation is load-bearing:
// callers render the result into user-visible strings (score messages,
// upload failures), and rebuilding the slice from a map made the rendered
// order a per-run dice roll — the same errors produced differently-ordered
// messages on every scan.
func (m Errors) Deduplicate() error {
	if len(m.Errors) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(m.Errors))
	res := make([]error, 0, len(m.Errors))
	for i := range m.Errors {
		e := m.Errors[i]
		msg := e.Error()
		if _, ok := seen[msg]; ok {
			continue
		}
		seen[msg] = struct{}{}
		res = append(res, e)
	}
	return &Errors{Errors: res}
}

func (m *Errors) IsEmpty() bool {
	if m == nil {
		return true
	}
	return len(m.Errors) == 0
}
