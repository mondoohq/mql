// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package config

import "os"

func umaskBits() os.FileMode { return 0 }
