// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

// isJSONArray reports whether a payload is a JSON array, ignoring leading
// whitespace. The list decoders use it to keep the real array error instead of
// retrying as an object and reporting a misleading one.
func isJSONArray(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// RepoType is the Hub API path segment for a kind of repository. The scan
// endpoint is served under all three.
type RepoType string

const (
	RepoTypeModel   RepoType = "models"
	RepoTypeDataset RepoType = "datasets"
	RepoTypeSpace   RepoType = "spaces"
)

// RepoScan is the response of GET /api/{repoType}/{owner}/{repo}/scan: the
// Hub's antivirus and pickle-import verdict over the files in a repository.
type RepoScan struct {
	// ScansDone reports whether the Hub has finished scanning the repository.
	// A freshly created or recently updated repository reports false together
	// with an empty FilesWithIssues, so an empty list is only evidence of a
	// clean repository when ScansDone is true.
	ScansDone bool `json:"scansDone"`
	// FilesWithIssues holds one entry per flagged file. Clean files are not
	// reported, so this list is empty for a repository with no findings.
	FilesWithIssues []ScanFileIssue `json:"filesWithIssues"`
}

// ScanFileIssue is one file the Hub's security scan flagged.
type ScanFileIssue struct {
	// Path locates the file relative to the repository root.
	Path string `json:"path"`
	// Level is the severity the scan assigned, such as "caution" or "unsafe".
	Level string `json:"level"`
}
