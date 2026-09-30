// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package processes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSocketInode(t *testing.T) {
	tests := []struct {
		link      string
		wantInode int64
		wantErr   bool
	}{
		{"socket:[41866700]", 41866700, false},
		{"socket:[0]", 0, false},
		{"socket:[999999999]", 999999999, false},
		{"pipe:[12345]", -1, false},
		{"/dev/null", -1, false},
		{"", -1, false},
		{"socket:[]", 0, true},
		{"socket:[notanumber]", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.link, func(t *testing.T) {
			inode, err := ParseSocketInode(tt.link)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantInode, inode)
			}
		})
	}
}
