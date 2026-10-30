// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

// binaryFileTypes are the extensions of executable and package files. The list
// is the GitHub provider's, so a binary file check means the same on both.
var binaryFileTypes = map[string]bool{
	"crx":    true,
	"deb":    true,
	"dex":    true,
	"dey":    true,
	"elf":    true,
	"o":      true,
	"so":     true,
	"iso":    true,
	"class":  true,
	"jar":    true,
	"bundle": true,
	"dylib":  true,
	"lib":    true,
	"msi":    true,
	"dll":    true,
	"drv":    true,
	"efi":    true,
	"exe":    true,
	"ocx":    true,
	"pyc":    true,
	"pyo":    true,
	"par":    true,
	"rpm":    true,
	"whl":    true,
}

// securityFilePaths are the places a security policy is looked for, in order,
// in lower case.
var securityFilePaths = []string{"/security.md", "/docs/security.md", "/.github/security.md"}

// mqlAzuredevopsFileInternal names the repository of a file, whose tree and
// content are read through it.
type mqlAzuredevopsFileInternal struct {
	projectName string
	repoID      string
}

// fileType names the kind of a tree entry the way the GitHub provider does.
func fileType(it connection.Item) string {
	switch strings.ToLower(it.GitObjectType) {
	case "blob":
		return "file"
	case "tree":
		return "dir"
	case "commit":
		return "submodule"
	}
	if it.IsFolder {
		return "dir"
	}
	return strings.ToLower(it.GitObjectType)
}

// isBinaryFile reports a file whose extension, in any letter case, names a
// known binary type.
func isBinaryFile(typ, filePath string) bool {
	if typ != "file" {
		return false
	}
	return binaryFileTypes[strings.ToLower(strings.TrimPrefix(path.Ext(filePath), "."))]
}

// isPipelineFile reports a YAML file that holds an Azure Pipelines definition by
// convention: azure-pipelines.yml or .yaml at any depth, or any YAML file under
// a .azure-pipelines or .azuredevops folder at the root.
func isPipelineFile(it connection.Item) bool {
	if !it.IsBlob() {
		return false
	}
	lower := strings.ToLower(it.Path)
	ext := path.Ext(lower)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	if strings.TrimSuffix(path.Base(lower), ext) == "azure-pipelines" {
		return true
	}
	return strings.HasPrefix(lower, "/.azure-pipelines/") || strings.HasPrefix(lower, "/.azuredevops/")
}

// childrenOf is the entries directly inside dir. The tree lists its root as
// "/", which is never a child.
func childrenOf(items []connection.Item, dir string) []connection.Item {
	var out []connection.Item
	for _, it := range items {
		if it.Path != "/" && path.Dir(it.Path) == dir {
			out = append(out, it)
		}
	}
	return out
}

func newFile(runtime *plugin.Runtime, project, repoID string, it connection.Item) (*mqlAzuredevopsFile, error) {
	typ := fileType(it)
	res, err := CreateResource(runtime, "azuredevops.file", map[string]*llx.RawData{
		"__id":     llx.StringData("azuredevops.file/" + repoID + it.Path),
		"path":     llx.StringData(it.Path),
		"name":     llx.StringData(path.Base(it.Path)),
		"type":     llx.StringData(typ),
		"sha":      llx.StringData(it.ObjectID),
		"isBinary": llx.BoolData(isBinaryFile(typ, it.Path)),
		"exists":   llx.BoolData(true),
	})
	if err != nil {
		return nil, err
	}
	f := res.(*mqlAzuredevopsFile)
	f.projectName = project
	f.repoID = repoID
	return f, nil
}

// missingFile is the answer of a lookup that found nothing: an entry with the
// expected path whose exists is false.
func missingFile(runtime *plugin.Runtime, project, repoID, filePath string) (*mqlAzuredevopsFile, error) {
	res, err := CreateResource(runtime, "azuredevops.file", map[string]*llx.RawData{
		"__id":     llx.StringData("azuredevops.file/missing/" + repoID + filePath),
		"path":     llx.StringData(filePath),
		"name":     llx.StringData(path.Base(filePath)),
		"type":     llx.StringData(""),
		"sha":      llx.StringData(""),
		"isBinary": llx.BoolData(false),
		"exists":   llx.BoolData(false),
	})
	if err != nil {
		return nil, err
	}
	f := res.(*mqlAzuredevopsFile)
	f.projectName = project
	f.repoID = repoID
	return f, nil
}

func newFiles(runtime *plugin.Runtime, project, repoID string, items []connection.Item) ([]any, error) {
	out := make([]any, 0, len(items))
	for _, it := range items {
		f, err := newFile(runtime, project, repoID, it)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// tree is the default branch tree of the repository, shared by every file
// lookup. A repository with no commits has an empty tree, known without a
// request.
func (r *mqlAzuredevopsRepository) tree() ([]connection.Item, error) {
	if r.IsEmpty.Data {
		return nil, nil
	}
	items, err := connectionOf(r.MqlRuntime).Client().Tree(apiContext(), r.ProjectName.Data, r.Id.Data)
	if connection.IsEmptyRepoError(err) {
		return nil, nil
	}
	return items, err
}

func (r *mqlAzuredevopsRepository) files() ([]any, error) {
	items, err := r.tree()
	if err != nil {
		return nil, classifyForbidden(err)
	}
	return newFiles(r.MqlRuntime, r.ProjectName.Data, r.Id.Data, childrenOf(items, "/"))
}

func (r *mqlAzuredevopsRepository) allFiles() ([]any, error) {
	items, err := r.tree()
	if err != nil {
		return nil, classifyForbidden(err)
	}
	all := make([]connection.Item, 0, len(items))
	for _, it := range items {
		if it.Path != "/" {
			all = append(all, it)
		}
	}
	return newFiles(r.MqlRuntime, r.ProjectName.Data, r.Id.Data, all)
}

func (r *mqlAzuredevopsRepository) securityFile() (*mqlAzuredevopsFile, error) {
	items, err := r.tree()
	if err != nil {
		return nil, classifyForbidden(err)
	}
	for _, want := range securityFilePaths {
		for _, it := range items {
			if it.IsBlob() && strings.EqualFold(it.Path, want) {
				return newFile(r.MqlRuntime, r.ProjectName.Data, r.Id.Data, it)
			}
		}
	}
	return missingFile(r.MqlRuntime, r.ProjectName.Data, r.Id.Data, "/SECURITY.md")
}

func (r *mqlAzuredevopsRepository) pipelineFiles() ([]any, error) {
	items, err := r.tree()
	if err != nil {
		return nil, classifyForbidden(err)
	}
	var found []connection.Item
	for _, it := range items {
		if isPipelineFile(it) {
			found = append(found, it)
		}
	}
	return newFiles(r.MqlRuntime, r.ProjectName.Data, r.Id.Data, found)
}

func (f *mqlAzuredevopsFile) files() ([]any, error) {
	if f.Type.Data != "dir" {
		return []any{}, nil
	}
	items, err := connectionOf(f.MqlRuntime).Client().Tree(apiContext(), f.projectName, f.repoID)
	if err != nil {
		return nil, classifyForbidden(err)
	}
	return newFiles(f.MqlRuntime, f.projectName, f.repoID, childrenOf(items, f.Path.Data))
}

func (f *mqlAzuredevopsFile) content() (string, error) {
	if !f.Exists.Data || f.Type.Data != "file" {
		f.Content.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	item, err := connectionOf(f.MqlRuntime).Client().ItemContent(apiContext(), f.projectName, f.repoID, f.Path.Data)
	if err != nil {
		return "", classifyForbidden(err)
	}
	return item.Content, nil
}
