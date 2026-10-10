// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aix"
)

// readAixStanzas reads an AIX attribute file through the file resource, so
// it works on a running system and on an image alike.
func readAixStanzas(runtime *plugin.Runtime, path string) (*aix.Stanzas, error) {
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	file := f.(*mqlFile)
	exists := file.GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if !exists.Data {
		return nil, llx.NotFound(fmt.Errorf("%s does not exist", path))
	}
	content := file.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}
	return aix.ParseStanzas(strings.NewReader(content.Data))
}
