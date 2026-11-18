// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/codesphere/connection"
	"go.mondoo.com/mql/types"
)

func initCodesphere(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["apiUrl"]; !ok {
		args["apiUrl"] = llx.StringData(runtime.Connection.(*connection.CodesphereConnection).APIURL())
	}
	return args, nil, nil
}

func (r *mqlCodesphere) id() (string, error) {
	return "codesphere", nil
}

// getRoot returns the installation resource, which holds the cached lists
// that references resolve against.
func getRoot(runtime *plugin.Runtime) (*mqlCodesphere, error) {
	res, err := NewResource(runtime, "codesphere", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCodesphere), nil
}

func (r *mqlCodesphere) dataCenters() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().MetadataAPI.MetadataGetDatacenters(conn.Context()).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for _, dc := range list {
		o, err := CreateResource(r.MqlRuntime, "codesphere.dataCenter", map[string]*llx.RawData{
			"id":          llx.IntData(dc.Id),
			"name":        llx.StringData(dc.Name),
			"city":        llx.StringData(dc.City),
			"countryCode": llx.StringData(dc.CountryCode),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlCodesphere) workspacePlans() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().MetadataAPI.MetadataGetWorkspacePlans(conn.Context()).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for _, p := range list {
		c := p.Characteristics
		o, err := CreateResource(r.MqlRuntime, "codesphere.workspacePlan", map[string]*llx.RawData{
			"id":               llx.IntData(p.Id),
			"title":            llx.StringData(p.Title),
			"priceUsd":         llx.FloatData(float64(p.PriceUsd)),
			"deprecated":       llx.BoolData(p.Deprecated),
			"maxReplicas":      llx.IntData(p.MaxReplicas),
			"cpu":              llx.FloatData(float64(c.CPU)),
			"gpu":              llx.FloatData(float64(c.GPU)),
			"ramBytes":         llx.IntData(c.RAM),
			"ssdBytes":         llx.IntData(c.SSD),
			"tempStorageBytes": llx.IntData(c.TempStorage),
			"onDemand":         llx.BoolData(c.OnDemand),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlCodesphere) baseImages() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().MetadataAPI.MetadataGetWorkspaceBaseImages(conn.Context()).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for _, img := range list {
		o, err := CreateResource(r.MqlRuntime, "codesphere.baseImage", map[string]*llx.RawData{
			"id":             llx.StringData(img.Id),
			"name":           llx.StringData(img.Name),
			"supportedUntil": llx.TimeData(img.SupportedUntil),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlCodesphere) sshKeys() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.CodesphereConnection)
	list, resp, err := conn.API().SshAPI.SshListPublicKeys(conn.Context()).Execute()
	if err != nil {
		return nil, connection.Classify(resp, err)
	}
	res := make([]any, 0, len(list))
	for _, k := range list {
		o, err := CreateResource(r.MqlRuntime, "codesphere.sshKey", map[string]*llx.RawData{
			"title":       llx.StringData(k.Title),
			"fingerprint": llx.StringData(k.PublicKeyFingerprint),
			"publicKey":   llx.StringData(k.PublicKey),
			"createdAt":   llx.TimeData(k.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlCodesphereDataCenter) id() (string, error) {
	return strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlCodesphereWorkspacePlan) id() (string, error) {
	return strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlCodesphereBaseImage) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlCodesphereSshKey) id() (string, error) {
	return r.Fingerprint.Data, nil
}

// findDataCenter, findWorkspacePlan and findBaseImage resolve a reference
// against the installation's catalog, which is listed once and cached. The
// API has no endpoint to read a single catalog entry.
func findDataCenter(runtime *plugin.Runtime, id int64) (*mqlCodesphereDataCenter, error) {
	root, err := getRoot(runtime)
	if err != nil {
		return nil, err
	}
	list := root.GetDataCenters()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, it := range list.Data {
		if dc := it.(*mqlCodesphereDataCenter); dc.Id.Data == id {
			return dc, nil
		}
	}
	return nil, nil
}

func findWorkspacePlan(runtime *plugin.Runtime, id int64) (*mqlCodesphereWorkspacePlan, error) {
	root, err := getRoot(runtime)
	if err != nil {
		return nil, err
	}
	list := root.GetWorkspacePlans()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, it := range list.Data {
		if p := it.(*mqlCodesphereWorkspacePlan); p.Id.Data == id {
			return p, nil
		}
	}
	return nil, nil
}

func findBaseImage(runtime *plugin.Runtime, id string) (*mqlCodesphereBaseImage, error) {
	root, err := getRoot(runtime)
	if err != nil {
		return nil, err
	}
	list := root.GetBaseImages()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, it := range list.Data {
		if img := it.(*mqlCodesphereBaseImage); img.Id.Data == id {
			return img, nil
		}
	}
	return nil, nil
}

// cachedResource returns a resource already created under the given name and
// __id, so an init can skip the API call for an object a list already read.
func cachedResource(runtime *plugin.Runtime, name, id string) (plugin.Resource, bool) {
	return runtime.Resources.Get(name + "\x00" + id)
}

// floatDataPtr keeps an absent optional number null instead of zero.
func floatDataPtr(v *float32) *llx.RawData {
	if v == nil {
		return &llx.RawData{Type: types.Float}
	}
	return llx.FloatData(float64(*v))
}

// redactGitURL masks credentials embedded in a repository URL, so a credential
// in the URL shows up as a finding without leaking. A token can sit in the user
// name as well as the password (https://<token>@host/repo), so the whole user
// info is masked, in every scheme and in scp-style remotes. The one exception
// is the plain user "git" with no password, the conventional SSH user that
// carries no secret. Anything that does not parse is returned empty rather
// than risk returning a secret.
func redactGitURL(raw *string) *string {
	if raw == nil {
		return nil
	}
	s := *raw
	if !strings.Contains(s, "://") {
		m := scpRemote.FindStringSubmatch(s)
		switch {
		case m == nil:
			s = ""
		case m[1] != sshUser:
			s = redacted + s[len(m[1]):]
		}
		return &s
	}
	u, err := url.Parse(s)
	if err != nil {
		s = ""
		return &s
	}
	if u.User != nil {
		_, hasPassword := u.User.Password()
		if hasPassword || u.User.Username() != sshUser {
			u.User = url.User(redacted)
		}
	}
	s = u.String()
	return &s
}

const (
	redacted = "xxxxx"
	sshUser  = "git"
)

// scpRemote matches an scp-style SSH remote such as git@github.com:org/repo.git
// and captures its user.
var scpRemote = regexp.MustCompile(`^([^@/:\s]+)@[A-Za-z0-9.-]+:[^/]`)

// roleName maps the numeric resource group role the API returns to the name
// the Codesphere CLI prints for it. The CLI also treats -1 as admin.
func roleName(role int) string {
	switch role {
	case 0, -1:
		return "admin"
	case 1:
		return "member"
	default:
		return "unknown(" + strconv.Itoa(role) + ")"
	}
}
