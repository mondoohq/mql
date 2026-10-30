// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/sshutil"
)

func (r *mqlHetznerSshKey) id() (string, error) {
	return fmt.Sprintf("hetzner.sshKey/%d", r.Id.Data), nil
}

func (h *mqlHetzner) sshKeys() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.SSHKey, *hcloud.Response, error) {
		return c.Client().SSHKey.List(ctx(), hcloud.SSHKeyListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, k := range items {
		res, err := newMqlHetznerSshKey(h.MqlRuntime, k)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerSshKey(runtime *plugin.Runtime, k *hcloud.SSHKey) (*mqlHetznerSshKey, error) {
	algorithm, bits := sshutil.ParsePublicKey(k.PublicKey)
	res, err := CreateResource(runtime, "hetzner.sshKey", map[string]*llx.RawData{
		"__id":        llx.StringData(fmt.Sprintf("hetzner.sshKey/%d", k.ID)),
		"id":          llx.IntData(k.ID),
		"name":        llx.StringData(k.Name),
		"fingerprint": llx.StringData(k.Fingerprint),
		"publicKey":   llx.StringData(k.PublicKey),
		"algorithm":   llx.StringData(algorithm),
		"bits":        llx.IntData(bits),
		"created":     llx.TimeDataPtr(timePtr(k.Created)),
		"labels":      labelData(k.Labels),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerSshKey), nil
}

func initHetznerSshKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "sshKey")
	if err != nil {
		return nil, nil, err
	}
	k, _, err := conn(runtime).Client().SSHKey.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if k == nil {
		return nil, nil, notFoundErr("sshKey", id)
	}
	res, err := newMqlHetznerSshKey(runtime, k)
	return args, res, err
}
