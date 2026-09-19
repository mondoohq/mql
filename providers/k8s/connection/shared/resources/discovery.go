// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/disk"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // https://github.com/kubernetes/client-go/issues/242
	"k8s.io/client-go/rest"
)

func NewDiscovery(restConfig *rest.Config) (*Discovery, error) {
	// hide deprecation warnings for go api
	// see https://kubernetes.io/blog/2020/09/03/warnings/#customize-client-handling
	rest.SetDefaultWarningHandler(
		rest.NewWarningWriter(io.Discard, rest.WarningWriterOptions{}),
	)

	dynClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct dynamic client")
	}

	var cachedClient discovery.CachedDiscoveryInterface
	if os.Getenv("DEBUG") == "1" {
		cachedClient, err = disk.NewCachedDiscoveryClientForConfig(restConfig, ".cache/k8s", "", time.Hour)
		if err != nil {
			return nil, errors.Wrap(err, "failed to construct discovery client")
		}
	} else {
		dClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
		if err != nil {
			return nil, errors.Wrap(err, "failed to construct discovery client")
		}
		cachedClient = memory.NewMemCacheClient(dClient)
	}

	// Always request fresh data from the server
	cachedClient.Invalidate()
	serverVersion, err := cachedClient.ServerVersion()
	if err != nil {
		return nil, err
	}

	return &Discovery{
		discoveryClient: cachedClient,
		dynClient:       dynClient,
		ServerVersion:   serverVersion,
	}, nil
}

type Discovery struct {
	dynClient       dynamic.Interface
	discoveryClient discovery.CachedDiscoveryInterface
	ServerVersion   *version.Info
}

func (d *Discovery) SupportedResourceTypes() (*ApiResourceIndex, error) {
	log.Debug().Msg("query api resource types")
	resList, err := d.discoveryClient.ServerPreferredResources()
	if err != nil {
		if discovery.IsGroupDiscoveryFailedError(err) {
			log.Debug().Err(err).Msg("one or more kubernetes API groups fail to load")
		} else {
			return nil, errors.Wrap(err, "failed to fetch api resource types from kubernetes")
		}
	}
	log.Debug().Msgf("found %d api resource types", len(resList))

	return ResourceIndex(resList)
}

func (d *Discovery) GetAllResources(ctx context.Context, resTypes *ApiResourceIndex, ns string, allNs bool) ([]runtime.Object, error) {
	apis := resTypes.Resources()
	log.Debug().Msgf("query %d api resources concurrently", len(apis))

	var out []runtime.Object
	var mu sync.Mutex
	var wg sync.WaitGroup

	var collectErr error
	for _, api := range apis {
		wg.Add(1)
		go func(a ApiResource) {
			defer wg.Done()
			log.Debug().Msgf("query api resources: %s", a.GroupVersionResource())
			v, err := d.GetKindResources(ctx, a, ns, allNs)
			if err != nil {
				log.Debug().Msgf("query api resources error: %s, error=%v", a.GroupVersionResource(), err)
				// Keep the first failure rather than letting the last goroutine
				// to finish overwrite it, and take the lock: this shares `mu`
				// with `out` below, so an unguarded write here is a data race.
				mu.Lock()
				if collectErr == nil {
					collectErr = err
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			out = append(out, v...)
			mu.Unlock()
			log.Debug().Msgf("query api resources done: %s, found %d resources", a.GroupVersionResource(), len(v))
		}(api)
	}

	log.Debug().Msg("waiting for all queries to return")
	wg.Wait()
	log.Debug().Msgf("query api resources completed: objects=%d, error=%v", len(out), collectErr)
	return out, collectErr
}

func (d *Discovery) GetKindResources(ctx context.Context, apiRes ApiResource, ns string, allNs bool) ([]runtime.Object, error) {
	var out []runtime.Object

	var next string
	for {
		var intf dynamic.ResourceInterface
		nintf := d.dynClient.Resource(apiRes.GroupVersionResource())
		log.Debug().Msgf("query resources for %s (namespaced: %t)", apiRes.Resource.Name, apiRes.Resource.Namespaced)
		if apiRes.Resource.Namespaced && !allNs {
			intf = nintf.Namespace(ns)
		} else {
			intf = nintf
		}
		resp, err := intf.List(ctx, metav1.ListOptions{
			Limit:    250,
			Continue: next,
		})
		if err != nil {
			// A missing permission for a resource type is expected (the user's
			// RBAC may not cover every discovered kind), so swallow it and skip
			// this kind. Any other error (throttling, a transient API-server
			// failure, an expired continue token mid-pagination) must propagate
			// rather than silently truncate the result set to an empty/partial
			// list that looks like "this kind has no objects".
			if k8sErrors.IsForbidden(err) || k8sErrors.IsUnauthorized(err) {
				// On the first page this simply means "no access to this kind",
				// and we return an empty list. If it happens mid-pagination
				// (e.g. a token rotates during a long list), the results already
				// in `out` are partial, so warn that this kind may be incomplete
				// rather than silently returning a truncated set.
				if len(out) > 0 {
					log.Warn().Err(err).Msgf("lost permission mid-pagination for %v; returning %d partial results", apiRes.GroupVersionResource(), len(out))
				} else {
					log.Debug().Err(err).Msgf("no permission to fetch resources for: %v", apiRes.GroupVersionResource())
				}
				break
			}
			return out, errors.Wrapf(err, "could not fetch resources for %v", apiRes.GroupVersionResource())
		}

		out = append(out, UnstructuredListToObjectList(resp.Items)...)

		next = resp.GetContinue()
		if next == "" {
			break
		}
	}
	return out, nil
}

func contains(v []string, s string) bool {
	for _, vv := range v {
		if vv == s {
			return true
		}
	}
	return false
}
