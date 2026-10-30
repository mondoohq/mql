// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package zerologadapter_test

import (
	"bytes"
	"testing"

	subject "go.mondoo.com/mql/logger/zerologadapter"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestNewAdapter(t *testing.T) {
	var logOutput bytes.Buffer
	logger := zerolog.New(&logOutput).Level(zerolog.DebugLevel)
	adapter := subject.New(logger)

	t.Run("Msg method logs correctly", func(t *testing.T) {
		logOutput.Reset()
		adapter.Msg("Test message", "key1", "value1", "key2", 42)

		expectedLog := `{"level":"debug","key1":"value1","key2":42,"message":"Test message"}`
		assert.JSONEq(t, expectedLog, logOutput.String())
	})

	t.Run("Error method logs correctly", func(t *testing.T) {
		logOutput.Reset()
		adapter.Error("Error occurred", "error_code", 500)

		expectedLog := `{"level":"debug","error_code":500,"message":"Error occurred"}`
		assert.JSONEq(t, expectedLog, logOutput.String())
	})

	t.Run("Info method logs correctly", func(t *testing.T) {
		logOutput.Reset()
		adapter.Info("Info message", "key", "value")

		expectedLog := `{"level":"debug","key":"value","message":"Info message"}`
		assert.JSONEq(t, expectedLog, logOutput.String())
	})

	t.Run("Debug method logs correctly", func(t *testing.T) {
		logOutput.Reset()
		adapter.Debug("Debugging issue", "context", "test")

		expectedLog := `{"level":"debug","context":"test","message":"Debugging issue"}`
		assert.JSONEq(t, expectedLog, logOutput.String())
	})

	t.Run("Warn method logs correctly", func(t *testing.T) {
		logOutput.Reset()
		adapter.Warn("Warning issued", "warning_level", "high")

		expectedLog := `{"level":"debug","warning_level":"high","message":"Warning issued"}`
		assert.JSONEq(t, expectedLog, logOutput.String())
	})

	t.Run("Handles non-string keys gracefully", func(t *testing.T) {
		logOutput.Reset()
		adapter.Info("Non-string key test", 123, "value", "key2", 42)

		expectedLog := `{"level":"debug","key2":42,"message":"Non-string key test"}`
		assert.JSONEq(t, expectedLog, logOutput.String())
	})

	t.Run("Handles odd number of key-value pairs gracefully", func(t *testing.T) {
		logOutput.Reset()
		adapter.Debug("Odd number test", "key1", "value1", "key2")

		expectedLog := `{"level":"debug","key1":"value1","message":"Odd number test"}`
		assert.JSONEq(t, expectedLog, logOutput.String())
	})

	t.Run("Empty key-value pairs", func(t *testing.T) {
		logOutput.Reset()
		adapter.Warn("Empty key-value test")

		expectedLog := `{"level":"debug","message":"Empty key-value test"}`
		assert.JSONEq(t, expectedLog, logOutput.String())
	})
}
