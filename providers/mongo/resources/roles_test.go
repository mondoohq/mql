// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestSystemBucketsData(t *testing.T) {
	if v := systemBucketsData(bson.M{"db": "", "system_buckets": ""}); v.Value != "" {
		t.Errorf("every-bucket resource: got %v, want \"\"", v.Value)
	}
	if v := systemBucketsData(bson.M{"db": "app", "system_buckets": "weather"}); v.Value != "weather" {
		t.Errorf("named bucket: got %v", v.Value)
	}
	if v := systemBucketsData(bson.M{"db": "", "collection": ""}); v.Value != nil {
		t.Errorf("collection resource: got %v, want null", v.Value)
	}
}
