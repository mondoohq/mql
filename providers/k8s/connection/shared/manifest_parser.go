// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
)

type ManifestParser struct {
	Objects            []runtime.Object
	namespace          string
	selectedResourceID string
}

func NewManifestParser(manifest []byte, namespace, selectedResourceID string) (ManifestParser, error) {
	objs, err := load(manifest)
	if err != nil {
		return ManifestParser{}, errors.Wrap(err, "could not query resource objects")
	}
	log.Debug().Msgf("found %d resource objects", len(objs))
	return ManifestParser{
		Objects:            objs,
		namespace:          namespace,
		selectedResourceID: selectedResourceID,
	}, nil
}

func (t *ManifestParser) SupportedResourceTypes() (*resources.ApiResourceIndex, error) {
	return resources.NewApiResourceIndex(), nil
}

func (t *ManifestParser) Namespace(name string) (*v1.Namespace, error) {
	nss, err := t.Namespaces()
	if err != nil {
		return nil, err
	}

	for i := range nss {
		if nss[i].Name == name {
			return &nss[i], nil
		}
	}
	return nil, fmt.Errorf("namespace %s not found", name)
}

// Namespaces iterates over all file-based manifests and extracts all namespaces.
//
// Standalone Namespace objects present in the manifest are returned with their
// full metadata (labels, annotations, UID, etc.) so that namespace-level audits
// — for example Pod Security admission labels — work against manifest scans.
// Namespaces that are only referenced by another object's metadata.namespace
// (and have no Namespace object of their own) are synthesized as minimal
// Namespace objects carrying just the name.
func (t *ManifestParser) Namespaces() ([]v1.Namespace, error) {
	namespaces := map[string]v1.Namespace{}

	// First pass: collect standalone Namespace objects, which carry full metadata.
	for i := range t.Objects {
		ns, ok := t.Objects[i].(*v1.Namespace)
		if !ok {
			continue
		}
		// The universal deserializer strips TypeMeta, so set the Kind explicitly.
		ns.Kind = "Namespace"
		namespaces[ns.Name] = *ns
	}

	// Second pass: add namespaces that are only referenced by other objects'
	// metadata and don't have a Namespace object of their own.
	for i := range t.Objects {
		o, err := meta.Accessor(t.Objects[i])
		if err != nil {
			// There are types of resources that do not have meta data. Instead of
			// erroring skip them.
			continue
		}
		ns := o.GetNamespace()
		if ns == "" {
			continue
		}
		if _, ok := namespaces[ns]; ok {
			continue
		}
		namespaces[ns] = v1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace"},
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		}
	}

	nss := make([]v1.Namespace, 0, len(namespaces))
	for _, ns := range namespaces {
		nss = append(nss, ns)
	}

	return nss, nil
}

func (t *ManifestParser) resourceIndex() (*resources.ApiResourceIndex, error) {
	// find root nodes
	resList, err := resources.CachedServerResources()
	if err != nil {
		return nil, err
	}

	resTypes, err := resources.ResourceIndex(resList)
	if err != nil {
		return nil, err
	}

	// We have a static list of API resources for the manifest provider. Here we dynamically add
	// API resources for every Unstructured object we encounter.
	for _, o := range t.Objects {
		if unstr, ok := o.(*unstructured.Unstructured); ok {
			gvk := unstr.GetObjectKind().GroupVersionKind()

			// Only add the API resource if it wasn't added already.
			if _, err := resTypes.Lookup(strings.ToLower(gvk.GroupKind().String())); err != nil {
				apiRes := resources.ApiResource{
					GroupVersion: unstr.GroupVersionKind().GroupVersion(),
					Resource: metav1.APIResource{
						// The k8s API doesn't add just 's'. For kinds that end on 's' the suffix is 'es' but
						// that doesn't change anything for us. That's why only the basic logic is implemented.
						Name:         strings.ToLower(gvk.Kind) + "s",
						SingularName: strings.ToLower(gvk.Kind),
						Verbs:        []string{"list"},
						Kind:         gvk.Kind,
						Version:      gvk.Version,
						Group:        gvk.Group,
					},
				}
				resTypes.Add(apiRes)
			}
		}
	}

	return resTypes, nil
}

// Resources retrieves the cluster resources. If the connection has a global namespace set, then that's used
func (t *ManifestParser) Resources(kind string, name string, namespace string) (*ResourceResult, error) {
	// The connection namespace has precedence
	if t.namespace != "" {
		namespace = t.namespace
	}

	return t.resources(kind, name, namespace)
}

// resources retrieves the cluster resources
func (t *ManifestParser) resources(kind string, name string, namespace string) (*ResourceResult, error) {
	var ns string
	if namespace == "" {
		ns = t.namespace
	} else {
		ns = namespace
	}
	allNs := false
	if ns == "" {
		allNs = true
	}

	resTypes, err := t.resourceIndex()
	if err != nil {
		return nil, err
	}

	resType, err := resTypes.Lookup(kind)
	if err != nil {
		return nil, err
	}

	res, err := resources.FilterResource(resType, t.Objects, name, namespace)

	return &ResourceResult{
		Name:         name,
		Kind:         kind,
		ResourceType: resType,
		Resources:    res,
		Namespace:    ns,
		AllNs:        allNs,
	}, err
}

func load(manifest []byte) ([]k8sRuntime.Object, error) {
	res := []k8sRuntime.Object{}
	if len(manifest) > 0 {
		objects, err := resources.ResourcesFromManifest(bytes.NewReader(manifest))
		if err != nil {
			return nil, err
		}
		res = append(res, objects...)
	}

	resList, err := resources.CachedServerResources()
	if err != nil {
		return nil, err
	}

	resTypes, err := resources.ResourceIndex(resList)
	if err != nil {
		return nil, err
	}

	// Every unstructured object here is an object that we couldn't match to an actual type.
	// Such objects we treat as custom resources and should end up in the k8s.customresources list.
	// To do that we need to have a CRD for every kind that couldn't be matched to a type. Here we create
	// the related CRD for every type that needs it.
	addedCrds := make(map[string]struct{})
	for _, o := range res {
		if unstr, ok := o.(*unstructured.Unstructured); ok {
			gvk := unstr.GetObjectKind().GroupVersionKind()
			if _, err := resTypes.Lookup(gvk.Kind); err != nil {
				// Only add the CRD once.
				crdName := strings.ToLower(fmt.Sprintf("%s.%s", gvk.Kind, gvk.Group))
				if _, ok := addedCrds[crdName]; ok {
					continue
				}

				addedCrds[crdName] = struct{}{}
				res = append(
					res,
					&apiextensionsv1.CustomResourceDefinition{TypeMeta: metav1.TypeMeta{Kind: "CustomResourceDefinition"}, ObjectMeta: metav1.ObjectMeta{Name: crdName}})
			}
		}
	}

	return res, nil
}

func ProjectNameFromPath(file string) string {
	// if it is a local file (which may not be true)
	name := ""
	fi, err := os.Stat(file)
	if err == nil {
		if fi.IsDir() && fi.Name() != "." {
			name = "directory " + fi.Name()
		} else if fi.IsDir() {
			name = fi.Name()
		} else {
			name = filepath.Base(fi.Name())
			extension := filepath.Ext(name)
			name = strings.TrimSuffix(name, extension)
		}
	} else {
		// it is not a local file, so we try to be a bit smart
		name = path.Base(file)
		extension := path.Ext(name)
		name = strings.TrimSuffix(name, extension)
	}

	// if the path is . we read the current directory
	if name == "." {
		abspath, err := filepath.Abs(name)
		if err == nil {
			name = ProjectNameFromPath(abspath)
		}
	}

	return name
}

func LoadManifestFile(manifestFile string) ([]byte, error) {
	log.Debug().Str("filename", manifestFile).Msg("loading manifest file")
	var input io.Reader

	// return all resources from manifest
	filenames := []string{}

	fi, err := os.Stat(manifestFile)
	if err != nil {
		return nil, err
	}

	if fi.IsDir() {
		yamlDecoder := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
		filepath.WalkDir(manifestFile, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// only load yaml files for now
			if !d.IsDir() {
				ext := filepath.Ext(path)
				if ext != ".yaml" && ext != ".yml" {
					log.Debug().Str("file", path).Msg("ignore file, no .yaml or .yml ending")
					return nil
				}
				// A kustomization declares a kind, so it decodes as an
				// unstructured object and would make every Kustomize directory
				// look like a folder of manifests -- yielding a second asset
				// beside the kustomize one. It is build instructions, not a
				// manifest to apply, which is also why the forge classifiers
				// match it ahead of their YAML arm.
				switch d.Name() {
				case "kustomization.yaml", "kustomization.yml", "Kustomization":
					log.Debug().Str("file", path).Msg("ignore file, a kustomization is not a manifest")
					return nil
				}
				// check whether this is valid k8s yaml
				content, err := os.ReadFile(path)
				if err != nil {
					log.Debug().Str("file", path).Err(err).Msg("ignore file, could not read file")
					return nil
				}
				// At this point, we do not care about specific schemes, just whether the file is a valid k8s yaml
				_, _, err = yamlDecoder.Decode(content, nil, nil)
				if err != nil {
					// the err contains the file content, which is not useful in the output
					errorString := ""
					if len(err.Error()) > 40 {
						errorString = err.Error()[:40] + "..."
					} else {
						errorString = err.Error()
					}
					log.Debug().Str("file", path).Str("error", errorString).Msg("ignore file, no valid kubernetes yaml")
					return nil
				}
				log.Debug().Str("file", path).Msg("add file to manifest loading")
				filenames = append(filenames, path)
			}

			return nil
		})
	} else {
		filenames = append(filenames, manifestFile)
	}

	input, err = resources.MergeManifestFiles(filenames)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(input)
}
