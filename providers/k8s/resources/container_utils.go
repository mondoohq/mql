// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	v1 "k8s.io/api/core/v1"
)

const DockerPullablePrefix = "docker-pullable://"

type ContainerImage struct {
	image         string
	resolvedImage string
	pullSecrets   []v1.Secret
	// archs are the CPU architectures of the nodes the image was seen running
	// on. It is best-effort: empty when the node or its architecture is unknown.
	archs map[string]struct{}
}

// ociDigestPattern matches a sha256 image digest as it appears after the "@"
// of a resolved image reference.
var ociDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// containerImageDigest returns the "sha256:..." digest of a resolved image
// reference such as "repo@sha256:...". Tag-only references, which is what the
// resolution falls back to for stopped pods and imagePullPolicy: Never, have no
// digest and yield false.
func containerImageDigest(resolvedImage string) (string, bool) {
	_, digest, found := strings.Cut(resolvedImage, "@")
	if !found || !ociDigestPattern.MatchString(digest) {
		return "", false
	}
	return digest, true
}

// mergeContainerImages merges src into dst. Like types.MergeMaps, src wins for
// every field, except archs: an image running on several architectures keeps
// the union of them.
func mergeContainerImages(dst, src map[string]ContainerImage) map[string]ContainerImage {
	for key, img := range src {
		if existing, ok := dst[key]; ok && len(existing.archs) > 0 {
			merged := make(map[string]struct{}, len(existing.archs)+len(img.archs))
			for arch := range existing.archs {
				merged[arch] = struct{}{}
			}
			for arch := range img.archs {
				merged[arch] = struct{}{}
			}
			img.archs = merged
		}
		dst[key] = img
	}
	return dst
}

func ResolveUniqueContainerImages(cs []v1.Container, ps []v1.Secret) map[string]ContainerImage {
	imagesSet := make(map[string]ContainerImage)
	for _, c := range cs {
		imagesSet[c.Image] = ContainerImage{image: c.Image, resolvedImage: c.Image, pullSecrets: ps}
	}
	return imagesSet
}

func ResolveUniqueContainerImagesFromStatus(cs []v1.ContainerStatus, ps []v1.Secret) map[string]ContainerImage {
	imagesSet := make(map[string]ContainerImage)
	for _, c := range cs {
		image, resolvedImage := ResolveContainerImageFromStatus(c)
		imagesSet[resolvedImage] = ContainerImage{image: image, resolvedImage: resolvedImage, pullSecrets: ps}
	}
	return imagesSet
}

func ResolveContainerImageFromStatus(containerStatus v1.ContainerStatus) (string, string) {
	image := containerStatus.Image
	resolvedImage := containerStatus.ImageID
	resolvedImage = strings.TrimPrefix(resolvedImage, DockerPullablePrefix)

	// stopped pods may not include the resolved image
	// pods with imagePullPolicy: Never do not have a proper ImageId value as it contains only the
	// sha but not the repository. If we use that value, it will cause issues later because we will
	// eventually try to pull an image by providing just the sha without a repo.
	if len(resolvedImage) == 0 || !strings.Contains(resolvedImage, "@") {
		resolvedImage = containerStatus.Image
	}

	return image, resolvedImage
}

// UniqueImagesForPod returns the unique container images for a pod. Images are compared based on their digest
// if that is available in the pod status. If there is no pod status set, the container image tag is used.
func UniqueImagesForPod(pod *v1.Pod, runtime *plugin.Runtime) map[string]ContainerImage {
	pullSecrets := make([]v1.Secret, 0, len(pod.Spec.ImagePullSecrets))
	for _, ps := range pod.Spec.ImagePullSecrets {
		s, err := GetSecret(runtime, pod.Namespace, ps.Name) // TODO: figure out if we want to do anything with the error here
		if err == nil {
			pullSecrets = append(pullSecrets, *s)
		}
	}
	return resolvePodImages(pod, pullSecrets)
}

// podImageRefs returns the sorted resolved references of the images a pod runs,
// without touching the API for pull secrets.
func podImageRefs(pod *v1.Pod) []string {
	images := resolvePodImages(pod, nil)
	refs := make([]string, 0, len(images))
	for ref := range images {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

// resolvePodImages is UniqueImagesForPod without the pull-secret lookups: the
// same status-first, spec-fallback resolution, keyed by resolved reference.
func resolvePodImages(pod *v1.Pod, pullSecrets []v1.Secret) map[string]ContainerImage {
	imagesSet := make(map[string]ContainerImage)

	// it is best to read the image from the container status since it is resolved
	// and more accurate, for static file scan we also need to fall-back to pure spec
	// since the status will not be set
	imagesSet = types.MergeMaps(imagesSet, ResolveUniqueContainerImagesFromStatus(pod.Status.InitContainerStatuses, pullSecrets))

	// fall-back to spec
	if len(pod.Spec.InitContainers) > 0 && len(pod.Status.InitContainerStatuses) == 0 {
		imagesSet = types.MergeMaps(imagesSet, ResolveUniqueContainerImages(pod.Spec.InitContainers, pullSecrets))
	}

	imagesSet = types.MergeMaps(imagesSet, ResolveUniqueContainerImagesFromStatus(pod.Status.ContainerStatuses, pullSecrets))

	// fall-back to spec
	if len(pod.Spec.Containers) > 0 && len(pod.Status.ContainerStatuses) == 0 {
		imagesSet = types.MergeMaps(imagesSet, ResolveUniqueContainerImages(pod.Spec.Containers, pullSecrets))
	}
	return imagesSet
}

func GetSecret(runtime *plugin.Runtime, namespace, name string) (*v1.Secret, error) {
	s, err := NewResource(runtime, "k8s.secret", map[string]*llx.RawData{
		"namespace": llx.StringData(namespace),
		"name":      llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}

	return s.(*mqlK8sSecret).obj, nil
}
