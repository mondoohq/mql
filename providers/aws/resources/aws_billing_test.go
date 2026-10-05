// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBudgetArn(t *testing.T) {
	assert.Equal(t, "arn:aws:budgets::123456789012:budget/monthly-cap",
		budgetArn("aws", "123456789012", "monthly-cap"))
	assert.Equal(t, "arn:aws-us-gov:budgets::123456789012:budget/gov budget",
		budgetArn("aws-us-gov", "123456789012", "gov budget"))
}
