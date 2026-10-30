// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package printer

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/muesli/termenv"
	"go.mondoo.com/mql/cli/theme/colors"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// Printer turns code into human-readable strings
type Printer struct {
	Primary   func(...any) string
	Secondary func(...any) string
	Yellow    func(...any) string
	Error     func(...any) string
	Warn      func(...any) string
	Disabled  func(...any) string
	Failed    func(...any) string
	Success   func(...any) string
	schema    resources.ResourcesSchema
}

// DefaultPrinter that can be used without additional configuration
var DefaultPrinter = Printer{
	Primary: func(args ...any) string {
		return termenv.String(fmt.Sprint(args...)).Foreground(colors.DefaultColorTheme.Primary).String()
	},
	Secondary: func(args ...any) string {
		return termenv.String(fmt.Sprint(args...)).Foreground(colors.DefaultColorTheme.Secondary).String()
	},
	Error: func(args ...any) string {
		return termenv.String("error: " + fmt.Sprint(args...)).Foreground(colors.DefaultColorTheme.Error).String()
	},
	Warn: func(args ...any) string {
		return termenv.String("warning: " + fmt.Sprint(args...)).Foreground(colors.DefaultColorTheme.Low).String()
	},
	Yellow: func(args ...any) string {
		return termenv.String(fmt.Sprint(args...)).Foreground(colors.DefaultColorTheme.Low).String()
	},
	Disabled: func(args ...any) string {
		return termenv.String(fmt.Sprint(args...)).Foreground(colors.DefaultColorTheme.Disabled).String()
	},
	Failed: func(args ...any) string {
		return termenv.String(fmt.Sprint(args...)).Foreground(colors.DefaultColorTheme.Critical).String()
	},
	Success: func(args ...any) string {
		return termenv.String(fmt.Sprint(args...)).Foreground(colors.DefaultColorTheme.Success).String()
	},
}

func (p *Printer) SetSchema(schema resources.ResourcesSchema) {
	p.schema = schema
}

// PlainNoColorPrinter is a printer without colors
var PlainNoColorPrinter = Printer{
	Primary:   fmt.Sprint,
	Secondary: fmt.Sprint,
	Error:     fmt.Sprint,
	Warn:      fmt.Sprint,
	Disabled:  fmt.Sprint,
	Failed:    fmt.Sprint,
}

// H1 prints a headline
func (print *Printer) H1(headline string) string {
	var res bytes.Buffer
	res.WriteString(print.Primary(headline))
	res.WriteString("\n")
	res.WriteString(print.Primary(strings.Repeat("=", len(headline))))
	res.WriteString("\n\n")
	return res.String()
}

// H2 prints a headline
func (print *Printer) H2(headline string) string {
	var res bytes.Buffer
	res.WriteString(print.Primary(headline))
	res.WriteString("\n")
	res.WriteString(print.Primary(strings.Repeat("-", len(headline))))
	res.WriteString("\n\n")
	return res.String()
}
