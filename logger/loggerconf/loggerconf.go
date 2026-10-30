// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package loggerconf configures the global logger from a small, declarative set
// of options (writer, level, and writer-specific settings), so logging can be
// set up identically from a single place.
//
// It lives in its own package, separate from the base logger package, so that
// importing it (and therefore the GCP/stackdriver dependency) stays opt-in.
package loggerconf

import (
	"fmt"
	"os"

	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/logger/stackdriver"
	"sigs.k8s.io/yaml"
)

// LoggingConfig declares how the global logger should be configured.
type LoggingConfig struct {
	// Writer selects the log sink: "cli" (default) or "stackdriver".
	Writer string `json:"writer,omitempty" mapstructure:"writer"`
	// Level sets the log level: error, warn, info, debug, trace.
	Level string `json:"level,omitempty" mapstructure:"level"`
	// Options carries writer-specific settings. For the "cli" writer this is
	// "format" (json|gcp-json); for "stackdriver" it is "project-id" and
	// "log-id".
	Options map[string]string `json:"options,omitempty" mapstructure:"options"`
	// Labels are static key/value labels attached to every log entry, surfaced
	// as Cloud Logging LogEntry.labels (filterable as `labels.<key>`). Applied
	// by the GCP-aware sinks: the "gcp-json" cli format and the "stackdriver"
	// writer; ignored by the plain "json" and console formats.
	Labels map[string]string `json:"labels,omitempty" mapstructure:"labels"`
}

// Load reads a LoggingConfig from a YAML or JSON file at the given path.
func Load(path string) (*LoggingConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read logging config %q: %w", path, err)
	}

	var opts LoggingConfig
	if err := yaml.Unmarshal(raw, &opts); err != nil {
		return nil, fmt.Errorf("could not parse logging config %q: %w", path, err)
	}
	return &opts, nil
}

// Configure is the single function that decides how logging happens. It applies
// the given options to the global logger and then lets the DEBUG/TRACE
// environment variables override the configured level, so that environment
// variables always win over explicit configuration.
//
// A nil opts falls back to the colorized CLI logger at info level.
func Configure(opts *LoggingConfig) error {
	if opts == nil {
		logger.CliLogger()
		logger.Set("info")
		applyEnvLevel()
		return nil
	}

	switch opts.Writer {
	case "", "cli":
		switch opts.Options["format"] {
		case "gcp-json":
			var gcpOpts []logger.GCPLogOption
			if len(opts.Labels) > 0 {
				gcpOpts = append(gcpOpts, logger.WithGCPLabels(opts.Labels))
			}
			logger.UseGCPJSONLogging(logger.LogOutputWriter, gcpOpts...)
		case "json":
			logger.UseJSONLogging(logger.LogOutputWriter)
		default:
			// matches the nil-opts default: colorized console on the
			// same buffered writer used by the json formats above.
			logger.CliLogger()
		}
	case "stackdriver":
		if opts.Options == nil {
			return fmt.Errorf("stackdriver logging requires `project-id` and `log-id` in the options block")
		}
		projectID := opts.Options["project-id"]
		if projectID == "" {
			return fmt.Errorf("stackdriver logging requires a `project-id` option")
		}
		logID := opts.Options["log-id"]
		if logID == "" {
			return fmt.Errorf("stackdriver logging requires a `log-id` option")
		}

		var sdOpts []stackdriver.Option
		if len(opts.Labels) > 0 {
			sdOpts = append(sdOpts, stackdriver.WithLabels(opts.Labels))
		}
		w, err := stackdriver.NewStackdriverWriter(projectID, logID, sdOpts...)
		if err != nil {
			return fmt.Errorf("could not initialize stackdriver logger: %w", err)
		}
		logger.SetWriter(w)
	default:
		return fmt.Errorf("unknown log writer %q", opts.Writer)
	}
	logger.Set(opts.Level)
	applyEnvLevel()
	return nil
}

// applyEnvLevel lets the DEBUG/TRACE/MONDOO_LOG_LEVEL environment variables
// override the configured level, so environment variables always win.
func applyEnvLevel() {
	if envLevel, ok := logger.GetEnvLogLevel(); ok {
		logger.Set(envLevel)
	}
}
