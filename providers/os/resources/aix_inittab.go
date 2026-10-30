// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/aix"
)

const aixInittabFile = "/etc/inittab"

func (i *mqlAixInittab) id() (string, error) {
	return "aix.inittab", nil
}

func (i *mqlAixInittab) list() ([]any, error) {
	if err := requireAix(i.MqlRuntime, "aix.inittab"); err != nil {
		return nil, err
	}
	f, err := CreateResource(i.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(aixInittabFile),
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
		return nil, llx.NotFound(fmt.Errorf("%s does not exist", aixInittabFile))
	}
	content := file.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}

	entries, err := aix.ParseInittab(strings.NewReader(content.Data))
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(entries))
	for _, e := range entries {
		r, err := CreateResource(i.MqlRuntime, "aix.inittab.entry", map[string]*llx.RawData{
			"__id":      llx.StringData("aix.inittab.entry/" + e.ID),
			"id":        llx.StringData(e.ID),
			"runLevels": llx.StringData(e.RunLevels),
			"action":    llx.StringData(e.Action),
			"command":   llx.StringData(e.Command),
			"active":    llx.BoolData(e.Action != "off"),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
