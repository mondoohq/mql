// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTargetPathDirAndBase(t *testing.T) {
	win := `C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release\extensions.json`
	assert.Equal(t, `C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release`, targetPathDir(win, true))
	assert.Equal(t, "abc.default-release", targetPathBase(targetPathDir(win, true), true))
	assert.Equal(t, "extensions.json", targetPathBase(win, true))

	// Two profiles holding the same file have different directories.
	other := `C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\w.work\extensions.json`
	assert.NotEqual(t, targetPathDir(win, true), targetPathDir(other, true))

	// Mixed separators, as filepath.Join on a non-Windows scanner produces.
	mixed := `C:\Users\alice/AppData/Roaming/Mozilla/Firefox/Profiles/w.work\extensions.json`
	assert.Equal(t, `C:\Users\alice/AppData/Roaming/Mozilla/Firefox/Profiles/w.work`, targetPathDir(mixed, true))
	assert.Equal(t, "w.work", targetPathBase(targetPathDir(mixed, true), true))
	assert.Equal(t, "w.work", targetPathBase(`C:\x\w.work\`, true))
	assert.Equal(t, ".", targetPathDir("extensions.json", true))

	unix := "/home/alice/.mozilla/firefox/abc.default/extensions.json"
	assert.Equal(t, "/home/alice/.mozilla/firefox/abc.default", targetPathDir(unix, false))
	assert.Equal(t, "abc.default", targetPathBase(targetPathDir(unix, false), false))

	assert.Equal(t, "C:/a/b", targetSlashPath(`C:\a\b`, true))
}
