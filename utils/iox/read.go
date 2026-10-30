// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package iox

import (
	"fmt"
	"io"
	"math"
)

// ReadAllLimit reads a response up to maxBytes. Exceeding the budget is an error,
// never a successful prefix that could make an incomplete inspection pass.
func ReadAllLimit(body io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return nil, fmt.Errorf("invalid input limit %d", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxBytes)
	}
	return data, nil
}
