// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"encoding/json"
	"io"
)

type GetItem struct {
	Name              string      `json:"Name"`
	Length            int64       `json:"Length"`
	DirectoryName     string      `json:"DirectoryName"`
	IsReadOnly        bool        `json:"IsReadOnly"`
	Exists            bool        `json:"Exists"`
	FullName          string      `json:"FullName"`
	Extension         string      `json:"Extension"`
	CreationTime      string      `json:"CreationTime"`
	CreationTimeUtc   string      `json:"CreationTimeUtc"`
	LastAccessTime    string      `json:"LastAccessTime"`
	LastAccessTimeUtc string      `json:"LastAccessTimeUtc"`
	LastWriteTime     string      `json:"LastWriteTime"`
	LastWriteTimeUtc  string      `json:"LastWriteTimeUtc"`
	Attributes        uint32      `json:"Attributes"`
	Mode              string      `json:"Mode"`
	BaseName          string      `json:"BaseName"`
	LinkType          string      `json:"LinkType"`
	VersionInfo       VersionInfo `json:"VersionInfo"`
}

type VersionInfo struct {
	IsDebug           bool           `json:"IsDebug"`
	IsPatched         bool           `json:"IsPatched"`
	IsPreRelease      bool           `json:"IsPreRelease"`
	IsPrivateBuild    bool           `json:"IsPrivateBuild"`
	IsSpecialBuild    bool           `json:"IsSpecialBuild"`
	FileVersionRaw    VersionInfoRaw `json:"FileVersionRaw"`
	ProductVersionRaw VersionInfoRaw `json:"ProductVersionRaw"`
}

type VersionInfoRaw struct {
	Major         int `json:"Major"`
	Minor         int `json:"Minor"`
	Build         int `json:"Build"`
	Revision      int `json:"Revision"`
	MajorRevision int `json:"MajorRevision"`
	MinorRevision int `json:"MinorRevision"`
}

func ParseGetItem(r io.Reader) (*GetItem, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var item GetItem
	err = json.Unmarshal(data, &item)
	if err != nil {
		return nil, err
	}

	return &item, nil
}
