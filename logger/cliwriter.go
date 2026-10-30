// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logger

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/muesli/termenv"
	"go.mondoo.com/mql/cli/theme/colors"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func NewConsoleWriter(out io.Writer, compact bool) zerolog.Logger {
	w := zerolog.ConsoleWriter{Out: out}
	// zerolog's own color output implementation does not work on Windows, therefore we re-implement all
	// colored methods here
	// TODO: its unclear why but the first 3 messages are outputted wrongly on windows
	// therefore we disable the colors for the indicators for now

	if compact && runtime.GOOS != "windows" {
		w.FormatLevel = consoleFormatLevel()
	} else if compact {
		w.FormatLevel = consoleFormatLevelNoColor()
	}

	w.FormatFieldName = consoleDefaultFormatFieldName()
	w.FormatFieldValue = consoleDefaultFormatFieldValue
	w.FormatErrFieldName = consoleDefaultFormatErrFieldName()
	w.FormatErrFieldValue = consoleDefaultFormatErrFieldValue()
	w.FormatCaller = consoleDefaultFormatCaller()
	w.FormatMessage = consoleDefaultFormatMessage
	w.FormatTimestamp = func(i any) string { return "" }

	return log.Output(w)
}

func consoleDefaultFormatCaller() zerolog.Formatter {
	return func(i any) string {
		var c string
		if cc, ok := i.(string); ok {
			c = cc
		}
		if len(c) > 0 {
			cwd, err := os.Getwd()
			if err == nil {
				c = strings.TrimPrefix(c, cwd)
				c = strings.TrimPrefix(c, "/")
			}
		}
		return c
	}
}

func consoleDefaultFormatMessage(i any) string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("%s", i)
}

func consoleDefaultFormatFieldName() zerolog.Formatter {
	return func(i any) string {
		return termenv.String(fmt.Sprintf("%s=", i)).Foreground(colors.DefaultColorTheme.Primary).String()
	}
}

func consoleDefaultFormatFieldValue(i any) string {
	return fmt.Sprintf("%s", i)
}

func consoleDefaultFormatErrFieldName() zerolog.Formatter {
	return func(i any) string {
		return termenv.String(fmt.Sprintf("%s=", i)).Foreground(colors.DefaultColorTheme.Error).String()
	}
}

func consoleDefaultFormatErrFieldValue() zerolog.Formatter {
	return func(i any) string {
		return termenv.String(fmt.Sprintf("%s", i)).Foreground(colors.DefaultColorTheme.Error).String()
	}
}

// consoleFormatLevelNoColor returns a formatter that outputs the level in uppercase without any color
// this is used for compact mode and primarily for windows which has a restricted color palette and character set
// for the console
func consoleFormatLevelNoColor() zerolog.Formatter {
	return func(i any) string {
		var l string

		if ll, ok := i.(string); ok {
			switch ll {
			case "trace":
				l = "TRC"
			case "debug":
				l = "DBG"
			case "info":
				l = "-"
			case "warn":
				l = "WRN"
			case "error":
				l = "ERR"
			case "fatal":
				l = "FTL"
			case "panic":
				l = "PNC"
			default:
				l = "UNK"
			}
		} else {
			if i == nil {
				l = "UNK"
			} else {
				l = strings.ToUpper(fmt.Sprintf("%s", i))[0:3]
			}
		}

		return l
	}
}

func consoleFormatLevel() zerolog.Formatter {
	return func(i any) string {
		var l string
		var color termenv.Color

		// set no color as default
		color = termenv.NoColor{}

		if ll, ok := i.(string); ok {
			switch ll {
			case "trace":
				l = "TRC"
				color = colors.DefaultColorTheme.Secondary
			case "debug":
				l = "DBG"
				color = colors.DefaultColorTheme.Primary
			case "info":
				l = "→"
				color = colors.DefaultColorTheme.Good
			case "warn":
				l = "!"
				color = colors.DefaultColorTheme.Medium
			case "error":
				l = "x"
				color = colors.DefaultColorTheme.Error
			case "fatal":
				l = "FTL"
				color = colors.DefaultColorTheme.Error
			case "panic":
				l = "PNC"
				color = colors.DefaultColorTheme.Error
			default:
				l = "???"
			}
		} else {
			if i == nil {
				l = "???"
			} else {
				l = strings.ToUpper(fmt.Sprintf("%s", i))[0:3]
			}
		}

		return termenv.String(l).Foreground(color).String()
	}
}
