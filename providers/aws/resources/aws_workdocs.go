// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	"github.com/aws/aws-sdk-go-v2/service/workdocs"
	workdocstypes "github.com/aws/aws-sdk-go-v2/service/workdocs/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

type mqlAwsWorkdocsInternal struct {
	rootContentsOnce sync.Once
	rootFolders      []any
	rootDocuments    []any
	rootContentsErr  error
}

type mqlAwsWorkdocsFolderInternal struct {
	cacheParentFolderId string
	cacheCreatorId      string
}

type mqlAwsWorkdocsDocumentInternal struct {
	cacheParentFolderId string
	cacheCreatorId      string
}

func (a *mqlAwsWorkdocs) id() (string, error) {
	return "aws.workdocs", nil
}

func (a *mqlAwsWorkdocsUser) id() (string, error) {
	return a.Region.Data + "/" + a.Id.Data, nil
}

func (a *mqlAwsWorkdocsFolder) id() (string, error) {
	return "aws.workdocs.folder/" + a.Region.Data + "/" + a.Id.Data, nil
}

func (a *mqlAwsWorkdocsDocument) id() (string, error) {
	return "aws.workdocs.document/" + a.Region.Data + "/" + a.Id.Data, nil
}

func (a *mqlAwsWorkdocs) users() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getUsers(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result == nil {
			continue
		}
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsWorkdocs) getUsers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			ctx := context.Background()
			res := []any{}

			// DescribeUsers is scoped to one WorkDocs organization, and under
			// SigV4 the API requires it: without an organizationId (or explicit
			// userIds) it answers ValidationException. A WorkDocs organization
			// is a registered Directory Service directory, so the directory ids
			// in this region are the organizations to enumerate.
			orgIds, err := workdocsOrganizationIds(ctx, conn, region)
			if err != nil {
				return nil, err
			}
			if len(orgIds) == 0 {
				return res, nil
			}

			svc := conn.WorkDocs(region)
			for _, orgId := range orgIds {
				params := &workdocs.DescribeUsersInput{
					OrganizationId: aws.String(orgId),
					Fields:         aws.String("STORAGE_METADATA"),
					Include:        workdocstypes.UserFilterTypeAll,
				}
				paginator := workdocs.NewDescribeUsersPaginator(svc, params)
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil {
						// The SDK declares WorkDocs regionalized with a
						// {region} endpoint template but ships endpoints for
						// only a handful of regions, so elsewhere the
						// synthesized host does not resolve. That is not a
						// failure to read the account, it means there is
						// nothing here.
						if IsServiceNotAvailableInRegionError(err) {
							log.Debug().Str("region", region).Msg("AWS WorkDocs is not available in region")
							return res, nil
						}
						// A denial is a fact about one organization, not about
						// the region: a policy can scope WorkDocs access to
						// some directories and not others. Move on to the next
						// organization rather than dropping the users already
						// read from the ones that did answer.
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Str("organizationId", orgId).
								Msg("error accessing WorkDocs organization")
							break
						}
						// A directory that is not registered with WorkDocs is
						// not an error, it simply hosts no WorkDocs users.
						if isBadRequestError(err) || isResourceNotFoundError(err) {
							log.Debug().Str("region", region).Str("organizationId", orgId).
								Msg("directory is not a WorkDocs organization")
							break
						}
						return nil, err
					}
					for _, user := range page.Users {
						var storageAllocatedInBytes int64
						var storageUtilizedInBytes int64
						var storageType string
						if user.Storage != nil {
							if user.Storage.StorageUtilizedInBytes != nil {
								storageUtilizedInBytes = *user.Storage.StorageUtilizedInBytes
							}
							if user.Storage.StorageRule != nil {
								if user.Storage.StorageRule.StorageAllocatedInBytes != nil {
									storageAllocatedInBytes = *user.Storage.StorageRule.StorageAllocatedInBytes
								}
								storageType = string(user.Storage.StorageRule.StorageType)
							}
						}

						mqlUser, err := CreateResource(a.MqlRuntime, "aws.workdocs.user",
							map[string]*llx.RawData{
								"id":                      llx.StringDataPtr(user.Id),
								"username":                llx.StringDataPtr(user.Username),
								"emailAddress":            llx.StringDataPtr(user.EmailAddress),
								"givenName":               llx.StringDataPtr(user.GivenName),
								"surname":                 llx.StringDataPtr(user.Surname),
								"status":                  llx.StringData(string(user.Status)),
								"userType":                llx.StringData(string(user.Type)),
								"createdTimestamp":        llx.TimeDataPtr(user.CreatedTimestamp),
								"modifiedTimestamp":       llx.TimeDataPtr(user.ModifiedTimestamp),
								"timeZoneId":              llx.StringDataPtr(user.TimeZoneId),
								"locale":                  llx.StringData(string(user.Locale)),
								"organizationId":          llx.StringDataPtr(user.OrganizationId),
								"storageAllocatedInBytes": llx.IntData(storageAllocatedInBytes),
								"storageUtilizedInBytes":  llx.IntData(storageUtilizedInBytes),
								"storageType":             llx.StringData(storageType),
								"recycleBinFolderId":      llx.StringDataPtr(user.RecycleBinFolderId),
								"rootFolderId":            llx.StringDataPtr(user.RootFolderId),
								"region":                  llx.StringData(region),
							},
						)
						if err != nil {
							return nil, err
						}
						res = append(res, mqlUser)
					}
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// workdocsOrganizationIds lists the WorkDocs organizations in a region.
//
// A WorkDocs organization is an AWS Directory Service directory that has been
// registered with WorkDocs, and its organization id is the directory id. The
// WorkDocs API itself offers no way to enumerate them, so the directories are
// the candidate set; the ones that are not registered simply return no users.
func workdocsOrganizationIds(ctx context.Context, conn *connection.AwsConnection, region string) ([]string, error) {
	svc := conn.DirectoryService(region)
	ids := []string{}

	paginator := directoryservice.NewDescribeDirectoriesPaginator(svc, &directoryservice.DescribeDirectoriesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
				log.Debug().Str("region", region).Msg("cannot list directories to resolve WorkDocs organizations")
				return nil, nil
			}
			return nil, err
		}
		for _, dir := range page.DirectoryDescriptions {
			if id := convert.ToValue(dir.DirectoryId); id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// rootFolder fetches the user's root folder via GetFolder. The folder id alone
// isn't enough to locate the resource (the WorkDocs API is regional), so the
// region is taken from the parent user.
func (a *mqlAwsWorkdocsUser) rootFolder() (*mqlAwsWorkdocsFolder, error) {
	if !a.RootFolderId.IsSet() || a.RootFolderId.Data == "" {
		a.RootFolder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return fetchWorkdocsFolder(a.MqlRuntime, a.Region.Data, a.OrganizationId.Data, a.RootFolderId.Data)
}

// recycleBinFolder fetches the user's recycle bin folder via GetFolder.
func (a *mqlAwsWorkdocsUser) recycleBinFolder() (*mqlAwsWorkdocsFolder, error) {
	if !a.RecycleBinFolderId.IsSet() || a.RecycleBinFolderId.Data == "" {
		a.RecycleBinFolder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return fetchWorkdocsFolder(a.MqlRuntime, a.Region.Data, a.OrganizationId.Data, a.RecycleBinFolderId.Data)
}

// fetchWorkdocsFolder calls GetFolder and converts the result to an mql folder.
// On access denied it returns a shell with only id/region/organizationId set so
// callers can still see the reference.
func fetchWorkdocsFolder(runtime *plugin.Runtime, region, organizationId, folderId string) (*mqlAwsWorkdocsFolder, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.WorkDocs(region)
	out, err := svc.GetFolder(context.Background(), &workdocs.GetFolderInput{
		FolderId: aws.String(folderId),
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return newWorkdocsFolderShell(runtime, region, organizationId, folderId)
		}
		return nil, err
	}
	if out == nil || out.Metadata == nil {
		return newWorkdocsFolderShell(runtime, region, organizationId, folderId)
	}
	return newMqlAwsWorkdocsFolder(runtime, region, organizationId, out.Metadata)
}

// newWorkdocsFolderShell creates a folder resource with only the id/region/
// organizationId populated. It's used as a fallback when GetFolder is denied,
// so the caller still sees something queryable instead of a hard error.
func newWorkdocsFolderShell(runtime *plugin.Runtime, region, organizationId, folderId string) (*mqlAwsWorkdocsFolder, error) {
	resource, err := CreateResource(runtime, "aws.workdocs.folder", map[string]*llx.RawData{
		"id":                llx.StringData(folderId),
		"name":              llx.StringData(""),
		"creatorId":         llx.StringData(""),
		"createdTimestamp":  llx.NilData,
		"modifiedTimestamp": llx.NilData,
		"resourceState":     llx.StringData(""),
		"latestVersionSize": llx.IntData(0),
		"size":              llx.IntData(0),
		"signature":         llx.StringData(""),
		"labels":            llx.ArrayData([]any{}, "string"),
		"region":            llx.StringData(region),
		"organizationId":    llx.StringData(organizationId),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsWorkdocsFolder), nil
}

// newMqlAwsWorkdocsFolder converts a workdocs FolderMetadata into a populated
// mqlAwsWorkdocsFolder, including the cached parentFolderId/creatorId used by
// the typed parentFolder()/creator() accessors.
func newMqlAwsWorkdocsFolder(runtime *plugin.Runtime, region, organizationId string, fm *workdocstypes.FolderMetadata) (*mqlAwsWorkdocsFolder, error) {
	if fm == nil {
		return nil, nil
	}
	labels := make([]any, 0, len(fm.Labels))
	for _, l := range fm.Labels {
		labels = append(labels, l)
	}
	var latestVersionSize int64
	if fm.LatestVersionSize != nil {
		latestVersionSize = *fm.LatestVersionSize
	}
	var size int64
	if fm.Size != nil {
		size = *fm.Size
	}
	args := map[string]*llx.RawData{
		"id":                llx.StringDataPtr(fm.Id),
		"name":              llx.StringDataPtr(fm.Name),
		"creatorId":         llx.StringDataPtr(fm.CreatorId),
		"createdTimestamp":  llx.TimeDataPtr(fm.CreatedTimestamp),
		"modifiedTimestamp": llx.TimeDataPtr(fm.ModifiedTimestamp),
		"resourceState":     llx.StringData(string(fm.ResourceState)),
		"latestVersionSize": llx.IntData(latestVersionSize),
		"size":              llx.IntData(size),
		"signature":         llx.StringDataPtr(fm.Signature),
		"labels":            llx.ArrayData(labels, "string"),
		"region":            llx.StringData(region),
		"organizationId":    llx.StringData(organizationId),
	}
	resource, err := CreateResource(runtime, "aws.workdocs.folder", args)
	if err != nil {
		return nil, err
	}
	mqlFolder := resource.(*mqlAwsWorkdocsFolder)
	if fm.ParentFolderId != nil {
		mqlFolder.cacheParentFolderId = *fm.ParentFolderId
	}
	if fm.CreatorId != nil {
		mqlFolder.cacheCreatorId = *fm.CreatorId
	}
	return mqlFolder, nil
}

// newMqlAwsWorkdocsDocument converts a workdocs DocumentMetadata into a
// populated mqlAwsWorkdocsDocument.
func newMqlAwsWorkdocsDocument(runtime *plugin.Runtime, region, organizationId string, dm *workdocstypes.DocumentMetadata) (*mqlAwsWorkdocsDocument, error) {
	if dm == nil {
		return nil, nil
	}
	labels := make([]any, 0, len(dm.Labels))
	for _, l := range dm.Labels {
		labels = append(labels, l)
	}
	latestVersion, err := documentVersionToDict(dm.LatestVersionMetadata)
	if err != nil {
		return nil, err
	}
	args := map[string]*llx.RawData{
		"id":                    llx.StringDataPtr(dm.Id),
		"creatorId":             llx.StringDataPtr(dm.CreatorId),
		"createdTimestamp":      llx.TimeDataPtr(dm.CreatedTimestamp),
		"modifiedTimestamp":     llx.TimeDataPtr(dm.ModifiedTimestamp),
		"resourceState":         llx.StringData(string(dm.ResourceState)),
		"latestVersionMetadata": llx.DictData(latestVersion),
		"labels":                llx.ArrayData(labels, "string"),
		"region":                llx.StringData(region),
		"organizationId":        llx.StringData(organizationId),
	}
	resource, err := CreateResource(runtime, "aws.workdocs.document", args)
	if err != nil {
		return nil, err
	}
	mqlDoc := resource.(*mqlAwsWorkdocsDocument)
	if dm.ParentFolderId != nil {
		mqlDoc.cacheParentFolderId = *dm.ParentFolderId
	}
	if dm.CreatorId != nil {
		mqlDoc.cacheCreatorId = *dm.CreatorId
	}
	return mqlDoc, nil
}

// documentVersionToDict turns a DocumentVersionMetadata into a dict so it can
// be stored as a single-field []dict — the latest-version metadata is small,
// heterogeneous, and not worth promoting to a typed sub-resource (no clear ID,
// no nested typed refs).
func documentVersionToDict(dvm *workdocstypes.DocumentVersionMetadata) (any, error) {
	if dvm == nil {
		return nil, nil
	}
	out := map[string]any{}
	if dvm.Id != nil {
		out["id"] = *dvm.Id
	}
	if dvm.Name != nil {
		out["name"] = *dvm.Name
	}
	if dvm.ContentType != nil {
		out["contentType"] = *dvm.ContentType
	}
	if dvm.Size != nil {
		out["size"] = *dvm.Size
	}
	if dvm.Signature != nil {
		out["signature"] = *dvm.Signature
	}
	out["status"] = string(dvm.Status)
	if dvm.CreatedTimestamp != nil {
		out["createdTimestamp"] = dvm.CreatedTimestamp.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if dvm.ModifiedTimestamp != nil {
		out["modifiedTimestamp"] = dvm.ModifiedTimestamp.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if dvm.ContentCreatedTimestamp != nil {
		out["contentCreatedTimestamp"] = dvm.ContentCreatedTimestamp.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if dvm.ContentModifiedTimestamp != nil {
		out["contentModifiedTimestamp"] = dvm.ContentModifiedTimestamp.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if dvm.CreatorId != nil {
		out["creatorId"] = *dvm.CreatorId
	}
	if len(dvm.Source) > 0 {
		source, err := convert.JsonToDict(dvm.Source)
		if err != nil {
			return nil, err
		}
		out["source"] = source
	}
	return out, nil
}

// folders walks one level below each user's root folder and returns the
// subfolders found there. The traversal is intentionally bounded — recursing
// into the full WorkDocs tree would be unbounded and isn't worth modeling here.
func (a *mqlAwsWorkdocs) folders() ([]any, error) {
	folders, _, err := a.collectRootFolderContents()
	if err != nil {
		return nil, err
	}
	return folders, nil
}

// documents walks one level below each user's root folder and returns the
// documents found there. Same bounded-traversal rationale as folders().
func (a *mqlAwsWorkdocs) documents() ([]any, error) {
	_, documents, err := a.collectRootFolderContents()
	if err != nil {
		return nil, err
	}
	return documents, nil
}

// collectRootFolderContents walks every WorkDocs user's root folder and
// returns the immediate folder and document children. Discovery stops at one
// level — deeper subtrees are out of scope for this iteration. The traversal
// is guarded by sync.Once so folders() and documents() share a single pass
// instead of independently paginating DescribeFolderContents for every user.
func (a *mqlAwsWorkdocs) collectRootFolderContents() ([]any, []any, error) {
	a.rootContentsOnce.Do(func() {
		a.rootFolders, a.rootDocuments, a.rootContentsErr = a.fetchRootFolderContents()
	})
	return a.rootFolders, a.rootDocuments, a.rootContentsErr
}

// fetchRootFolderContents performs the actual traversal. Callers should go
// through collectRootFolderContents so the result is cached.
func (a *mqlAwsWorkdocs) fetchRootFolderContents() ([]any, []any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	users := a.GetUsers()
	if users.Error != nil {
		return nil, nil, users.Error
	}
	usersAny := users.Data

	type rootKey struct {
		region         string
		organizationId string
		rootFolderId   string
	}
	seen := map[rootKey]bool{}
	roots := []rootKey{}
	for _, u := range usersAny {
		mqlUser, ok := u.(*mqlAwsWorkdocsUser)
		if !ok {
			continue
		}
		if !mqlUser.RootFolderId.IsSet() || mqlUser.RootFolderId.Data == "" {
			continue
		}
		key := rootKey{
			region:         mqlUser.Region.Data,
			organizationId: mqlUser.OrganizationId.Data,
			rootFolderId:   mqlUser.RootFolderId.Data,
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		roots = append(roots, key)
	}

	folders := []any{}
	documents := []any{}
	ctx := context.Background()
	for _, r := range roots {
		svc := conn.WorkDocs(r.region)
		paginator := workdocs.NewDescribeFolderContentsPaginator(svc, &workdocs.DescribeFolderContentsInput{
			FolderId: aws.String(r.rootFolderId),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", r.region).Str("folderId", r.rootFolderId).Msg("access denied listing WorkDocs root folder contents")
					break
				}
				if isBadRequestError(err) {
					log.Warn().Str("region", r.region).Msg("AWS WorkDocs not enabled in region")
					break
				}
				return nil, nil, err
			}
			for i := range page.Folders {
				fm := page.Folders[i]
				mqlFolder, err := newMqlAwsWorkdocsFolder(a.MqlRuntime, r.region, r.organizationId, &fm)
				if err != nil {
					return nil, nil, err
				}
				if mqlFolder != nil {
					folders = append(folders, mqlFolder)
				}
			}
			for i := range page.Documents {
				dm := page.Documents[i]
				mqlDoc, err := newMqlAwsWorkdocsDocument(a.MqlRuntime, r.region, r.organizationId, &dm)
				if err != nil {
					return nil, nil, err
				}
				if mqlDoc != nil {
					documents = append(documents, mqlDoc)
				}
			}
		}
	}
	return folders, documents, nil
}

// parentFolder returns the typed parent folder reference. The folder isn't
// listed in the bounded discovery walk, so we fetch it on demand via GetFolder.
func (a *mqlAwsWorkdocsFolder) parentFolder() (*mqlAwsWorkdocsFolder, error) {
	parentId := a.cacheParentFolderId
	if parentId == "" {
		a.ParentFolder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return fetchWorkdocsFolder(a.MqlRuntime, a.Region.Data, a.OrganizationId.Data, parentId)
}

// creator returns the typed creator user reference. We look it up by id from
// the already-fetched users() listing instead of issuing per-folder GetUser
// calls — there's no list of users keyed by id available cheaply otherwise.
func (a *mqlAwsWorkdocsFolder) creator() (*mqlAwsWorkdocsUser, error) {
	creatorId := a.cacheCreatorId
	if creatorId == "" && a.CreatorId.IsSet() {
		creatorId = a.CreatorId.Data
	}
	if creatorId == "" {
		a.Creator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	user, err := findWorkdocsUserById(a.MqlRuntime, creatorId)
	if err != nil {
		return nil, err
	}
	if user == nil {
		a.Creator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

// parentFolder returns the typed parent folder reference for a document.
func (a *mqlAwsWorkdocsDocument) parentFolder() (*mqlAwsWorkdocsFolder, error) {
	parentId := a.cacheParentFolderId
	if parentId == "" {
		a.ParentFolder.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return fetchWorkdocsFolder(a.MqlRuntime, a.Region.Data, a.OrganizationId.Data, parentId)
}

// creator returns the typed creator user reference for a document.
func (a *mqlAwsWorkdocsDocument) creator() (*mqlAwsWorkdocsUser, error) {
	creatorId := a.cacheCreatorId
	if creatorId == "" && a.CreatorId.IsSet() {
		creatorId = a.CreatorId.Data
	}
	if creatorId == "" {
		a.Creator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	user, err := findWorkdocsUserById(a.MqlRuntime, creatorId)
	if err != nil {
		return nil, err
	}
	if user == nil {
		a.Creator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

// findWorkdocsUserById looks the user up by id from the already-listed
// aws.workdocs.users() collection. If no match is found the returned user is
// marked as null on the caller's side.
func findWorkdocsUserById(runtime *plugin.Runtime, userId string) (*mqlAwsWorkdocsUser, error) {
	wdResource, err := CreateResource(runtime, "aws.workdocs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	wd := wdResource.(*mqlAwsWorkdocs)
	users := wd.GetUsers()
	if users.Error != nil {
		return nil, users.Error
	}
	for _, u := range users.Data {
		mqlUser, ok := u.(*mqlAwsWorkdocsUser)
		if !ok {
			continue
		}
		if mqlUser.Id.Data == userId {
			return mqlUser, nil
		}
	}
	return nil, nil
}
