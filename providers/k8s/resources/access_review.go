// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlK8sAccessReviewInternal struct {
	lock        sync.Mutex
	fetched     atomic.Bool
	allowedData bool
	reasonData  string
	resolveErr  error
}

// subjectAccessChecker is implemented by the live (api) connection, which can
// run a SubjectAccessReview against the cluster. Manifest connections do not
// implement it, so k8s.accessReview reports a clear error there.
type subjectAccessChecker interface {
	SubjectAccessAllowed(ctx context.Context, subject, namespace, verb, group, resource, name string) (bool, string, error)
}

func initK8sAccessReview(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	for _, f := range []string{"subject", "verb", "resource", "group", "namespace", "name"} {
		if _, ok := args[f]; !ok {
			args[f] = llx.StringData("")
		}
	}
	str := func(k string) string {
		if v, ok := args[k]; ok && v.Value != nil {
			if s, ok := v.Value.(string); ok {
				return s
			}
		}
		return ""
	}
	// Join with NUL, which cannot appear in a Kubernetes identifier, so values
	// containing "/" (or any other character) can't produce an ambiguous id.
	args["__id"] = llx.StringData(fmt.Sprintf("k8s.accessReview\x00sub=%s\x00ns=%s\x00grp=%s\x00res=%s\x00name=%s\x00verb=%s",
		str("subject"), str("namespace"), str("group"), str("resource"), str("name"), str("verb")))
	return args, nil, nil
}

// resolve runs the SubjectAccessReview once on success and caches the decision,
// so the allowed and reason fields share a single API call. A transient API
// failure is not cached: the next field access retries. The manifest-connection
// case is a permanent capability mismatch, so it is cached.
func (k *mqlK8sAccessReview) resolve() error {
	if k.fetched.Load() {
		return k.resolveErr
	}
	k.lock.Lock()
	defer k.lock.Unlock()
	if k.fetched.Load() {
		return k.resolveErr
	}

	conn, ok := k.MqlRuntime.Connection.(subjectAccessChecker)
	if !ok {
		k.resolveErr = errors.New("k8s.accessReview requires a live Kubernetes cluster connection")
		k.fetched.Store(true) // permanent — a manifest scan can never run a review
		return k.resolveErr
	}

	allowed, reason, err := conn.SubjectAccessAllowed(context.Background(),
		k.Subject.Data, k.Namespace.Data, k.Verb.Data, k.Group.Data, k.Resource.Data, k.Name.Data)
	k.resolveErr = err
	if err != nil {
		return err // transient — leave fetched unset so a later access retries
	}
	k.allowedData, k.reasonData = allowed, reason
	k.fetched.Store(true)
	return nil
}

func (k *mqlK8sAccessReview) allowed() (bool, error) {
	if err := k.resolve(); err != nil {
		return false, err
	}
	return k.allowedData, nil
}

func (k *mqlK8sAccessReview) reason() (string, error) {
	if err := k.resolve(); err != nil {
		return "", err
	}
	return k.reasonData, nil
}
