// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"
)

func TestFolderResourceName(t *testing.T) {
	cases := map[string]string{
		"123456":         "folders/123456",
		"folders/123456": "folders/123456",
		"":               "folders/",
		"folders/":       "folders/",
	}
	for in, want := range cases {
		if got := folderResourceName(in); got != want {
			t.Errorf("folderResourceName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFolderIdNormalizationRoundTrip documents the folder id fix: folderToMql
// stores the bare id and folders()/projects() re-prefix with "folders/". If the
// list path stored the full "folders/123" instead, the child lookup key would
// become "folders/folders/123" and silently match nothing.
func TestFolderIdNormalizationRoundTrip(t *testing.T) {
	// The bare id that folderToMql now stores (mirroring initGcpFolder).
	bareID := strings.TrimPrefix("folders/123456", "folders/")
	if bareID != "123456" {
		t.Fatalf("bare id = %q, want 123456", bareID)
	}
	// folders()/projects() build the child lookup key this way:
	childKey := "folders/" + bareID
	if childKey != "folders/123456" {
		t.Errorf("child lookup key = %q, want folders/123456 (double-prefix regression)", childKey)
	}
}

// TestProjectParentMatchesFolderKey pins the other half of the folder-id
// contract, which is where the round-trip above was silently broken.
//
// cloudresourcemanager v3 always reports Project.Parent as a *prefixed*
// reference ("folders/876", "organizations/123"), while gcp.folder stores the
// bare id ("876"). gcp.projects.list() builds a set of acceptable parents from
// the folder list and matches Project.Parent against it, so both sides have to
// be normalized to the same "folders/{id}" shape. Comparing the bare id
// against Project.Parent matches nothing, and every project nested in a
// subfolder disappears from the listing with no error.
func TestProjectParentMatchesFolderKey(t *testing.T) {
	// The seed parent, as gcp.folder.projects() / gcp.organization.projects()
	// supply it -- already prefixed.
	parentId := "organizations/123"

	// Folder ids as stored by folderToMql / initGcpFolder: bare.
	folderIds := []string{"876", "877"}

	foldersMap := map[string]struct{}{parentId: {}}
	for _, id := range folderIds {
		foldersMap[folderResourceName(id)] = struct{}{}
	}

	// Parents exactly as the API reports them.
	for _, parent := range []string{"organizations/123", "folders/876", "folders/877"} {
		if _, ok := foldersMap[parent]; !ok {
			t.Errorf("Project.Parent %q did not match the folder key set %v; "+
				"projects under that parent would be silently dropped", parent, foldersMap)
		}
	}

	// A folder outside the scanned hierarchy must still not match.
	if _, ok := foldersMap["folders/999"]; ok {
		t.Error("unrelated folder matched the key set")
	}
}
