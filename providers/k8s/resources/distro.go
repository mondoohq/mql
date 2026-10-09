// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/k8s/connection/shared/distro"
)

func (k *mqlK8sDistro) id() (string, error) {
	return "k8s.distro", nil
}

func (k *mqlK8sDistro) result() (*distro.Result, error) {
	kt, err := k8sProvider(k.MqlRuntime.Connection)
	if err != nil {
		return nil, err
	}
	return kt.Distro(), nil
}

func (k *mqlK8sDistro) name() (string, error) {
	r, err := k.result()
	if err != nil {
		return "", err
	}
	return r.Name, nil
}

func (k *mqlK8sDistro) source() (string, error) {
	r, err := k.result()
	if err != nil {
		return "", err
	}
	return r.Source, nil
}

func (k *mqlK8sDistro) clusterName() (string, error) {
	r, err := k.result()
	if err != nil {
		return "", err
	}
	return r.Identity.ClusterName, nil
}

func (k *mqlK8sDistro) region() (string, error) {
	r, err := k.result()
	if err != nil {
		return "", err
	}
	return r.Identity.Region, nil
}

func (k *mqlK8sDistro) account() (string, error) {
	r, err := k.result()
	if err != nil {
		return "", err
	}
	return r.Identity.Account, nil
}

func (k *mqlK8sDistro) identitySource() (string, error) {
	r, err := k.result()
	if err != nil {
		return "", err
	}
	return r.Identity.Source, nil
}

func (k *mqlK8sDistro) evidence() (map[string]any, error) {
	r, err := k.result()
	if err != nil {
		return nil, err
	}
	return evidenceDict(r.Evidence), nil
}

func evidenceDict(ev map[string]distro.Evidence) map[string]any {
	res := make(map[string]any, len(ev))
	for probe, e := range ev {
		res[probe] = map[string]any{
			"distro": e.Distro,
			"value":  e.Value,
			"error":  e.Error,
		}
	}
	return res
}
