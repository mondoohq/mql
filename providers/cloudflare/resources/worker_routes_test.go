// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/workers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerBindingTarget(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding string
		want    string
	}{
		{name: "k2 stream", binding: `{"name":"EVENTS","type":"k2","stream":"stream-123"}`, want: "stream-123"},
		{name: "pipelines", binding: `{"name":"P","type":"pipelines","pipeline":"my-pipeline"}`, want: "my-pipeline"},
		{name: "r2 bucket", binding: `{"name":"B","type":"r2_bucket","bucket_name":"assets"}`, want: "assets"},
		{name: "d1 legacy id", binding: `{"name":"DB","type":"d1","id":"db-legacy"}`, want: "db-legacy"},
		{name: "durable object in other script", binding: `{"name":"DO","type":"durable_object_namespace","class_name":"Counter","script_name":"svc"}`, want: "svc/Counter"},
		{name: "secret text never exposes value", binding: `{"name":"S","type":"secret_text","text":"hunter2"}`, want: ""},
		{name: "unknown kind", binding: `{"name":"X","type":"something_new","stream":"s"}`, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b workers.ScriptScriptAndVersionSettingGetResponseBinding
			require.NoError(t, json.Unmarshal([]byte(tc.binding), &b))
			assert.Equal(t, tc.want, workerBindingTarget(b))
		})
	}
}
