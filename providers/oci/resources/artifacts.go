// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// The registry side of the image policy.
//
// oci.oke.cluster.isImagePolicyEnabled already ships, and on its own it says
// only that a cluster checks signatures before admitting an image. Whether any
// image in the tenancy can satisfy that check is a question about the
// registry: which repositories are pullable without credentials, whether a
// published tag can be moved to different content, and which images carry a
// signature made with a key the policy names.

func (o *mqlOciArtifacts) id() (string, error) {
	return "oci.artifacts", nil
}

type mqlOciArtifactsInternal struct {
	// The tenancy's container registry configuration, read once and shared by
	// the two fields that report parts of it.
	configuration ociRetryLazy[*artifacts.ContainerConfiguration]
}

// containerConfiguration reads the tenancy-wide registry settings.
//
// The call is compartment-scoped in the API but the answer is not: the
// registry namespace and the create-on-push setting belong to the tenancy, so
// this asks the root once rather than fanning out.
func (o *mqlOciArtifacts) containerConfiguration() (*artifacts.ContainerConfiguration, error) {
	return o.configuration.get(func() (*artifacts.ContainerConfiguration, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		region, err := conn.ConfiguredRegion()
		if err != nil {
			return nil, err
		}
		svc, err := conn.ArtifactsClient(region)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetContainerConfiguration(context.Background(), artifacts.GetContainerConfigurationRequest{
			CompartmentId: new(conn.TenantID()),
		})
		if err != nil {
			return nil, err
		}
		return &resp.ContainerConfiguration, nil
	})
}

func (o *mqlOciArtifacts) registryNamespace() (string, error) {
	config, err := o.containerConfiguration()
	if err != nil {
		return "", err
	}
	return stringValue(config.Namespace), nil
}

func (o *mqlOciArtifacts) isRepositoryCreatedOnFirstPush() (bool, error) {
	config, err := o.containerConfiguration()
	if err != nil {
		return false, err
	}
	// False rather than null when the API omits it: the question is whether a
	// push can bring a repository into existence, and an absent setting means
	// it cannot.
	return boolValue(config.IsRepositoryCreatedOnFirstPush), nil
}

// ----- container repositories -----

type mqlOciArtifactsContainerRepositoryInternal struct {
	cacheCompartmentID string
	cacheRegion        string
	detail             ociRetryLazy[*artifacts.ContainerRepository]
}

func (o *mqlOciArtifacts) containerRepositories() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.ArtifactsClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]artifacts.ContainerRepositorySummary, *string, error) {
				resp, err := svc.ListContainerRepositories(ctx, artifacts.ListContainerRepositoriesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.ContainerRepositoryCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				repository := items[i]

				mqlRepository, err := CreateResource(o.MqlRuntime, "oci.artifacts.containerRepository", map[string]*llx.RawData{
					"id":                llx.StringDataPtr(repository.Id),
					"name":              llx.StringDataPtr(repository.DisplayName),
					"namespace":         llx.StringDataPtr(repository.Namespace),
					"isPublic":          llx.BoolDataPtr(repository.IsPublic),
					"imageCount":        ociOptionalInt(repository.ImageCount),
					"layerCount":        ociOptionalInt(repository.LayerCount),
					"layersSizeInBytes": llx.IntDataPtr(repository.LayersSizeInBytes),
					"billableSizeInGBs": llx.IntDataPtr(repository.BillableSizeInGBs),
					"state":             llx.StringData(string(repository.LifecycleState)),
					"created":           sdkTimeData(repository.TimeCreated),
					"freeformTags":      llx.MapData(strMapToAny(repository.FreeformTags), types.String),
					"definedTags":       llx.MapData(definedTagsToAny(repository.DefinedTags), types.Any),
					"systemTags":        llx.MapData(definedTagsToAny(repository.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlRepository.(*mqlOciArtifactsContainerRepository)
				typed.cacheCompartmentID = stringValue(repository.CompartmentId)
				typed.cacheRegion = region
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciArtifactsContainerRepository) id() (string, error) {
	return "oci.artifacts.containerRepository/" + o.Id.Data, nil
}

func (o *mqlOciArtifactsContainerRepository) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// fetchDetail reads the repository's full record.
//
// isImmutable is the reason this exists. The listing reports whether a
// repository is public but not whether a published tag can be moved to
// different content, and that second control is what decides whether an image
// verified once is the image that runs next.
func (o *mqlOciArtifactsContainerRepository) fetchDetail() (*artifacts.ContainerRepository, error) {
	return o.detail.get(func() (*artifacts.ContainerRepository, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.ArtifactsClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetContainerRepository(context.Background(), artifacts.GetContainerRepositoryRequest{
			RepositoryId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.ContainerRepository, nil
	})
}

func (o *mqlOciArtifactsContainerRepository) isImmutable() (bool, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return false, err
	}
	// False rather than null: a repository that does not report immutability
	// does not enforce it, and a null here would make
	// `isImmutable == false` skip exactly the repositories it should match.
	return boolValue(detail.IsImmutable), nil
}

func (o *mqlOciArtifactsContainerRepository) createdBy() (string, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return "", err
	}
	return stringValue(detail.CreatedBy), nil
}

func (o *mqlOciArtifactsContainerRepository) timeLastPushed() (*time.Time, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail.TimeLastPushed == nil {
		o.TimeLastPushed.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return &detail.TimeLastPushed.Time, nil
}

// images returns the images stored in this repository.
//
// Selected out of the tenancy-wide image listing rather than fetched per
// repository: that listing is fetched once and shared through the runtime
// cache, so a sweep over every repository costs one call instead of one per
// repository.
func (o *mqlOciArtifactsContainerRepository) images() ([]any, error) {
	images, err := ociArtifactsCollection(o.MqlRuntime, func(r *mqlOciArtifacts) *plugin.TValue[[]any] {
		return r.GetContainerImages()
	})
	if err != nil {
		return nil, err
	}

	return ociArtifactsSelectByOwner(images, o.Id.Data, ociArtifactsImageRepositoryID), nil
}

// ociArtifactsSelectByOwner picks the members of a registry collection that
// belong to one owner, preserving the collection's order.
//
// The owner id is read through a callback rather than compared inline because
// getting the wrong field would not fail: matching an image's own id against a
// repository id yields an empty list, and matching the wrong id field of the
// right type yields every member for every owner. Both read as data.
func ociArtifactsSelectByOwner(items []any, ownerID string, ownerOf func(any) (string, bool)) []any {
	res := []any{}
	if ownerID == "" {
		return res
	}
	for _, item := range items {
		owner, ok := ownerOf(item)
		if !ok {
			continue
		}
		if owner == ownerID {
			res = append(res, item)
		}
	}
	return res
}

// ociArtifactsImageRepositoryID reports the repository an image belongs to.
func ociArtifactsImageRepositoryID(item any) (string, bool) {
	image, ok := item.(*mqlOciArtifactsContainerImage)
	if !ok {
		return "", false
	}
	return image.cacheRepositoryID, true
}

// ociArtifactsSignatureImageID reports the image a signature covers.
func ociArtifactsSignatureImageID(item any) (string, bool) {
	signature, ok := item.(*mqlOciArtifactsContainerImageSignature)
	if !ok {
		return "", false
	}
	return signature.cacheImageID, true
}

// ociArtifactsCollection returns one of the registry's tenancy-wide
// collections, fetched once and shared.
func ociArtifactsCollection(runtime *plugin.Runtime, list func(*mqlOciArtifacts) *plugin.TValue[[]any]) ([]any, error) {
	obj, err := CreateResource(runtime, "oci.artifacts", nil)
	if err != nil {
		return nil, err
	}
	items := list(obj.(*mqlOciArtifacts))
	if items.Error != nil {
		return nil, items.Error
	}
	return items.Data, nil
}

// ----- container images -----

type mqlOciArtifactsContainerImageInternal struct {
	cacheCompartmentID string
	cacheRepositoryID  string
	cacheRegion        string
	detail             ociRetryLazy[*artifacts.ContainerImage]
}

func (o *mqlOciArtifacts) containerImages() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.ArtifactsClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]artifacts.ContainerImageSummary, *string, error) {
				resp, err := svc.ListContainerImages(ctx, artifacts.ListContainerImagesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.ContainerImageCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				image := items[i]

				mqlImage, err := CreateResource(o.MqlRuntime, "oci.artifacts.containerImage", map[string]*llx.RawData{
					"id":             llx.StringDataPtr(image.Id),
					"name":           llx.StringDataPtr(image.DisplayName),
					"digest":         llx.StringDataPtr(image.Digest),
					"version":        llx.StringDataPtr(image.Version),
					"repositoryName": llx.StringDataPtr(image.RepositoryName),
					"state":          llx.StringData(string(image.LifecycleState)),
					"created":        sdkTimeData(image.TimeCreated),
					"freeformTags":   llx.MapData(strMapToAny(image.FreeformTags), types.String),
					"definedTags":    llx.MapData(definedTagsToAny(image.DefinedTags), types.Any),
					"systemTags":     llx.MapData(definedTagsToAny(image.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlImage.(*mqlOciArtifactsContainerImage)
				typed.cacheCompartmentID = stringValue(image.CompartmentId)
				typed.cacheRepositoryID = stringValue(image.RepositoryId)
				typed.cacheRegion = region
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciArtifactsContainerImage) id() (string, error) {
	return "oci.artifacts.containerImage/" + o.Id.Data, nil
}

func (o *mqlOciArtifactsContainerImage) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciArtifactsContainerImage) repository() (*mqlOciArtifactsContainerRepository, error) {
	return resolveRef(o.MqlRuntime, "oci.artifacts.containerRepository",
		ocidOrEmpty(o.cacheRepositoryID), &o.Repository)
}

// signatures returns the signatures covering this image.
//
// Selected out of the tenancy-wide signature listing for the same reason the
// repository's images are: the audit this exists for asks about every image at
// once, and a per-image call would turn that into one request per image.
func (o *mqlOciArtifactsContainerImage) signatures() ([]any, error) {
	signatures, err := ociArtifactsCollection(o.MqlRuntime, func(r *mqlOciArtifacts) *plugin.TValue[[]any] {
		return r.GetContainerImageSignatures()
	})
	if err != nil {
		return nil, err
	}

	return ociArtifactsSelectByOwner(signatures, o.Id.Data, ociArtifactsSignatureImageID), nil
}

func (o *mqlOciArtifactsContainerImage) fetchDetail() (*artifacts.ContainerImage, error) {
	return o.detail.get(func() (*artifacts.ContainerImage, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.ArtifactsClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetContainerImage(context.Background(), artifacts.GetContainerImageRequest{
			ImageId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.ContainerImage, nil
	})
}

// versions returns the tags currently resolving to this digest.
//
// The listing reports one tag per entry; the image itself may carry several,
// and which tags point at a digest is how a tag named in a deployment is
// traced to the content it pulls.
func (o *mqlOciArtifactsContainerImage) versions() ([]any, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(detail.Versions)
}

func (o *mqlOciArtifactsContainerImage) createdBy() (string, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return "", err
	}
	return stringValue(detail.CreatedBy), nil
}

func (o *mqlOciArtifactsContainerImage) pullCount() (int64, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.PullCount == nil {
		o.PullCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *detail.PullCount, nil
}

func (o *mqlOciArtifactsContainerImage) timeLastPulled() (*time.Time, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail.TimeLastPulled == nil {
		o.TimeLastPulled.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return &detail.TimeLastPulled.Time, nil
}

func (o *mqlOciArtifactsContainerImage) layersSizeInBytes() (int64, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.LayersSizeInBytes == nil {
		o.LayersSizeInBytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *detail.LayersSizeInBytes, nil
}

// ----- container image signatures -----

type mqlOciArtifactsContainerImageSignatureInternal struct {
	cacheCompartmentID string
	cacheImageID       string
	cacheKmsKeyID      string
}

func (o *mqlOciArtifacts) containerImageSignatures() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.ArtifactsClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]artifacts.ContainerImageSignatureSummary, *string, error) {
				resp, err := svc.ListContainerImageSignatures(ctx, artifacts.ListContainerImageSignaturesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.ContainerImageSignatureCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				signature := items[i]

				mqlSignature, err := CreateResource(o.MqlRuntime, "oci.artifacts.containerImageSignature", map[string]*llx.RawData{
					"id":               llx.StringDataPtr(signature.Id),
					"name":             llx.StringDataPtr(signature.DisplayName),
					"kmsKeyVersionId":  llx.StringDataPtr(signature.KmsKeyVersionId),
					"signingAlgorithm": llx.StringData(string(signature.SigningAlgorithm)),
					"message":          llx.StringDataPtr(signature.Message),
					"signature":        llx.StringDataPtr(signature.Signature),
					"state":            llx.StringData(string(signature.LifecycleState)),
					"created":          sdkTimeData(signature.TimeCreated),
					"freeformTags":     llx.MapData(strMapToAny(signature.FreeformTags), types.String),
					"definedTags":      llx.MapData(definedTagsToAny(signature.DefinedTags), types.Any),
					"systemTags":       llx.MapData(definedTagsToAny(signature.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlSignature.(*mqlOciArtifactsContainerImageSignature)
				typed.cacheCompartmentID = stringValue(signature.CompartmentId)
				typed.cacheImageID = stringValue(signature.ImageId)
				typed.cacheKmsKeyID = stringValue(signature.KmsKeyId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciArtifactsContainerImageSignature) id() (string, error) {
	return "oci.artifacts.containerImageSignature/" + o.Id.Data, nil
}

func (o *mqlOciArtifactsContainerImageSignature) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciArtifactsContainerImageSignature) image() (*mqlOciArtifactsContainerImage, error) {
	return resolveRef(o.MqlRuntime, "oci.artifacts.containerImage",
		ocidOrEmpty(o.cacheImageID), &o.Image)
}

func (o *mqlOciArtifactsContainerImageSignature) kmsKey() (*mqlOciKmsKey, error) {
	return resolveOciKmsKey(o.MqlRuntime, ocidOrEmpty(o.cacheKmsKeyID), &o.KmsKey)
}

// ----- generic artifact repositories -----

type mqlOciArtifactsRepositoryInternal struct {
	cacheCompartmentID string
	cacheRegion        string
}

func (o *mqlOciArtifacts) repositories() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.ArtifactsClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]artifacts.RepositorySummary, *string, error) {
				resp, err := svc.ListRepositories(ctx, artifacts.ListRepositoriesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.RepositoryCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				fields, err := ociArtifactRepositoryFields(items[i])
				if err != nil {
					return nil, err
				}

				mqlRepository, err := CreateResource(o.MqlRuntime, "oci.artifacts.repository", fields)
				if err != nil {
					return nil, err
				}
				typed := mqlRepository.(*mqlOciArtifactsRepository)
				typed.cacheCompartmentID = stringValue(items[i].GetCompartmentId())
				typed.cacheRegion = region
				res = append(res, typed)
			}
			return res, nil
		})
}

// ociArtifactRepositoryFields flattens one member of the RepositorySummary
// union into resource fields.
//
// GENERIC is the only member the service offers today. An unrecognised one is
// an error rather than a skip: dropping a repository would leave its artifacts
// unreachable and the tenancy looking like it stores less than it does.
func ociArtifactRepositoryFields(summary artifacts.RepositorySummary) (map[string]*llx.RawData, error) {
	generic, ok := summary.(artifacts.GenericRepositorySummary)
	if !ok {
		return nil, fmt.Errorf("oci.artifacts.repository: unhandled repository type %T", summary)
	}

	return map[string]*llx.RawData{
		"id":             llx.StringDataPtr(generic.Id),
		"name":           llx.StringDataPtr(generic.DisplayName),
		"description":    llx.StringDataPtr(generic.Description),
		"repositoryType": llx.StringData(string(artifacts.RepositoryRepositoryTypeGeneric)),
		"isImmutable":    llx.BoolDataPtr(generic.IsImmutable),
		"state":          llx.StringData(string(generic.LifecycleState)),
		"created":        sdkTimeData(generic.TimeCreated),
		"freeformTags":   llx.MapData(strMapToAny(generic.FreeformTags), types.String),
		"definedTags":    llx.MapData(definedTagsToAny(generic.DefinedTags), types.Any),
	}, nil
}

func (o *mqlOciArtifactsRepository) id() (string, error) {
	return "oci.artifacts.repository/" + o.Id.Data, nil
}

func (o *mqlOciArtifactsRepository) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// artifacts lists what the repository holds.
//
// Scoped to the repository because that is what the API requires:
// ListGenericArtifacts takes a repository id as well as a compartment, so
// unlike the container side there is no tenancy-wide listing to select from.
func (o *mqlOciArtifactsRepository) artifacts() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.ArtifactsClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]artifacts.GenericArtifactSummary, *string, error) {
		resp, err := svc.ListGenericArtifacts(ctx, artifacts.ListGenericArtifactsRequest{
			CompartmentId: new(o.cacheCompartmentID),
			RepositoryId:  new(o.Id.Data),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.GenericArtifactCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		artifact := items[i]

		mqlArtifact, err := CreateResource(o.MqlRuntime, "oci.artifacts.genericArtifact", map[string]*llx.RawData{
			"id":           llx.StringDataPtr(artifact.Id),
			"name":         llx.StringDataPtr(artifact.DisplayName),
			"artifactPath": llx.StringDataPtr(artifact.ArtifactPath),
			"version":      llx.StringDataPtr(artifact.Version),
			"sha256":       llx.StringDataPtr(artifact.Sha256),
			"sizeInBytes":  llx.IntDataPtr(artifact.SizeInBytes),
			"state":        llx.StringData(string(artifact.LifecycleState)),
			"created":      sdkTimeData(artifact.TimeCreated),
			"freeformTags": llx.MapData(strMapToAny(artifact.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(artifact.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlArtifact.(*mqlOciArtifactsGenericArtifact)
		typed.cacheCompartmentID = stringValue(artifact.CompartmentId)
		typed.cacheRepositoryID = stringValue(artifact.RepositoryId)
		res = append(res, typed)
	}
	return res, nil
}

// ----- generic artifacts -----

type mqlOciArtifactsGenericArtifactInternal struct {
	cacheCompartmentID string
	cacheRepositoryID  string
}

func (o *mqlOciArtifactsGenericArtifact) id() (string, error) {
	return "oci.artifacts.genericArtifact/" + o.Id.Data, nil
}

func (o *mqlOciArtifactsGenericArtifact) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciArtifactsGenericArtifact) repository() (*mqlOciArtifactsRepository, error) {
	return resolveRef(o.MqlRuntime, "oci.artifacts.repository",
		ocidOrEmpty(o.cacheRepositoryID), &o.Repository)
}
