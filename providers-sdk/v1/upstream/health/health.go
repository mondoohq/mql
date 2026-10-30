// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package health

import (
	"context"
	"net/http"
	"time"
)

//go:generate protoc --plugin=protoc-gen-go=../../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-rangerrpc=../../../../scripts/protoc/protoc-gen-rangerrpc --plugin=protoc-gen-go-vtproto=../../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=. --go_out=. --go_opt=paths=source_relative --rangerrpc_out=. --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size health.proto

type Status struct {
	API struct {
		Endpoint  string `json:"endpoint,omitempty"`
		Status    string `json:"status,omitempty"`
		Timestamp string `json:"timestamp,omitempty"`
		Version   string `json:"version,omitempty"`
	} `json:"api"`
	Features []string `json:"features,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func CheckApiHealth(httpClient *http.Client, endpoint string) (Status, error) {
	return CheckApiHealthContext(context.Background(), httpClient, endpoint)
}

// CheckApiHealthContext behaves like CheckApiHealth but honors the provided
// context, so callers can bound the health check with a deadline or cancel it.
func CheckApiHealthContext(ctx context.Context, httpClient *http.Client, endpoint string) (Status, error) {
	status := Status{}
	status.API.Endpoint = endpoint

	sendTime := time.Now()
	healthClient, err := NewHealthClient(endpoint, httpClient)
	if err != nil {
		return status, err
	}
	healthResp, err := healthClient.Check(ctx, &HealthCheckRequest{})
	if err != nil {
		return status, err
	} else {
		status.API.Status = healthResp.Status.String()
		status.API.Timestamp = healthResp.Time
		status.API.Version = healthResp.ApiVersion

		// do time check to make it easier to detect ssl/tls issues
		receivedResponseTime := time.Now()
		roundTripDuration := receivedResponseTime.Sub(sendTime)
		if roundTripDuration > time.Second*5 {
			status.Warnings = append(status.Warnings, "detected very long round-trip times: "+roundTripDuration.String())
		}

		upstream, err := time.Parse(time.RFC3339, healthResp.Time)
		if err != nil {
			status.Warnings = append(status.Warnings, "cannot run clock skew check")
		} else {
			diff := upstream.Sub(sendTime)
			if abs(diff) > time.Second*30 {
				status.Warnings = append(status.Warnings, "possible clock skew detected: "+diff.String())
			}
		}
	}
	return status, nil
}

func abs(a time.Duration) time.Duration {
	if a >= 0 {
		return a
	}
	return -a
}
