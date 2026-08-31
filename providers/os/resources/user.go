// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/users"
	"go.mondoo.com/mql/utils/multierr"
)

func (x *mqlUser) id() (string, error) {
	var id string
	if len(x.Sid.Data) > 0 {
		id = x.Sid.Data
	} else {
		id = strconv.FormatInt(x.Uid.Data, 10)
	}

	return "user/" + id + "/" + x.Name.Data, nil
}

func initUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	// if user is only initialized with a name or uid, we will try to look it up
	rawName, nameOk := args["name"]
	rawUID, idOk := args["uid"]
	if !nameOk && !idOk {
		return args, nil, nil
	}

	raw, err := CreateResource(runtime, "users", nil)
	if err != nil {
		return nil, nil, errors.New("cannot get list of users: " + err.Error())
	}
	users := raw.(*mqlUsers)

	if err := users.refreshCache(nil); err != nil {
		return nil, nil, err
	}

	if nameOk {
		name, ok := rawName.Value.(string)
		if !ok {
			return nil, nil, errors.New("cannot detect user, invalid type for name (expected string)")
		}
		user, ok := users.usersByName[name]
		if !ok {
			return nil, nil, errors.New("cannot find user with name '" + name + "'")
		}
		return nil, user, nil
	}

	if idOk {
		id, ok := rawUID.Value.(int64)
		if !ok {
			return nil, nil, errors.New("cannot detect user, invalid type for name (expected int)")
		}
		user, ok := users.usersByID[id]
		if !ok {
			return nil, nil, errors.New("cannot find user with UID '" + strconv.Itoa(int(id)) + "'")
		}
		return nil, user, nil
	}

	return nil, nil, errors.New("cannot find user, no search criteria provided")
}

func (x *mqlUser) group(gid int64) (*mqlGroup, error) {
	raw, err := CreateResource(x.MqlRuntime, "groups", nil)
	if err != nil {
		return nil, errors.New("cannot get groups info for user: " + err.Error())
	}
	groups := raw.(*mqlGroups)
	return groups.findID(gid)
}

func (u *mqlUser) authorizedkeys(home string) (*mqlAuthorizedkeys, error) {
	// TODO: we may need to handle ".ssh/authorized_keys2" too
	authorizedKeysPath := path.Join(home, ".ssh", "authorized_keys")
	ak, err := NewResource(u.MqlRuntime, "authorizedkeys", map[string]*llx.RawData{
		"path": llx.StringData(authorizedKeysPath),
	})
	if err != nil {
		return nil, err
	}
	return ak.(*mqlAuthorizedkeys), nil
}

// ntuserDat resolves the on-disk per-user registry hive at <home>\NTUSER.DAT for
// Windows accounts, so resources like registrykey can read a user's HKCU even
// when the user is not logged in. Empty on non-Windows platforms or when the home
// directory is unknown.
func (u *mqlUser) ntuserDat(home string) (string, error) {
	conn, ok := u.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return "", nil
	}
	pf := conn.Asset().Platform
	if pf == nil || !pf.IsFamily("windows") {
		return "", nil
	}
	if home == "" {
		return "", nil
	}
	return strings.TrimRight(home, `\`) + `\NTUSER.DAT`, nil
}

type mqlUsersInternal struct {
	lock        sync.Mutex
	usersByID   map[int64]*mqlUser
	usersByName map[string]*mqlUser
}

func (x *mqlUsers) list() ([]any, error) {
	x.lock.Lock()
	defer x.lock.Unlock()

	// in the unlikely case that we get called twice into the same method,
	// any subsequent calls are locked until user detection finishes; at this point
	// we only need to return a non-nil error field and it will pull the data from cache
	if x.usersByID != nil {
		return nil, nil
	}

	conn := x.MqlRuntime.Connection.(shared.Connection)
	um, err := users.ResolveManager(conn)
	if err != nil {
		return nil, multierr.Wrap(err, "cannot resolve users manager")
	}
	if um == nil {
		return nil, errors.New("cannot find users manager")
	}

	users, err := um.List()
	if err != nil {
		return nil, multierr.Wrap(err, "could not retrieve users list")
	}

	var res []any
	for i := range users {
		user := users[i]
		nu, err := CreateResource(x.MqlRuntime, "user", map[string]*llx.RawData{
			"name":    llx.StringData(user.Name),
			"uid":     llx.IntData(user.Uid),
			"gid":     llx.IntData(user.Gid),
			"sid":     llx.StringData(user.Sid),
			"home":    llx.StringData(user.Home),
			"shell":   llx.StringData(user.Shell),
			"enabled": llx.BoolData(user.Enabled),
		})
		if err != nil {
			return nil, err
		}

		res = append(res, nu)
	}

	return res, x.refreshCache(res)
}

func (x *mqlUsers) refreshCache(all []any) error {
	if all == nil {
		raw := x.GetList()
		if raw.Error != nil {
			return raw.Error
		}
		all = raw.Data
	}

	x.usersByID = map[int64]*mqlUser{}
	x.usersByName = map[string]*mqlUser{}

	for i := range all {
		u := all[i].(*mqlUser)
		x.usersByID[u.Uid.Data] = u
		x.usersByName[u.Name.Data] = u
	}

	return nil
}

func (x *mqlUsers) findID(id int64) (*mqlUser, error) {
	if x := x.GetList(); x.Error != nil {
		return nil, x.Error
	}

	res, ok := x.usersByID[id]
	if !ok {
		return nil, resources.NotFoundError{Resource: "user", ID: strconv.Itoa(int(id))}
	}
	return res, nil
}

// loggedInUsers returns the set of currently logged-in usernames. The result
// is cached via the command resource so repeated calls (e.g. iterating
// users.list { loggedIn }) only execute the command once.
func loggedInUsers(runtime *plugin.Runtime, conn shared.Connection) (map[string]bool, error) {
	isWindows := false
	if pf := conn.Asset().Platform; pf != nil && pf.IsFamily("windows") {
		isWindows = true
	}

	cmdStr := "who"
	if isWindows {
		cmdStr = "query user"
	}

	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData(cmdStr),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return nil, err
	}
	if run.exitcode != 0 {
		return map[string]bool{}, nil
	}

	users := map[string]bool{}
	for i, line := range strings.Split(run.stdout, "\n") {
		// Skip header row from "query user" on Windows
		if isWindows && i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if isWindows {
			// Active session is prefixed with ">" (e.g., ">username")
			name = strings.TrimLeft(name, "> ")
		}
		if name != "" {
			users[name] = true
		}
	}
	return users, nil
}

func (u *mqlUser) loggedIn() (bool, error) {
	if u.Name.Error != nil {
		return false, u.Name.Error
	}

	conn := u.MqlRuntime.Connection.(shared.Connection)
	users, err := loggedInUsers(u.MqlRuntime, conn)
	if err != nil {
		return false, err
	}

	return users[u.Name.Data], nil
}

func (u *mqlUser) sshkeys() ([]any, error) {
	res := []any{}

	userSshPath := path.Join(u.Home.Data, ".ssh")

	conn := u.MqlRuntime.Connection.(shared.Connection)
	afutil := afero.Afero{Fs: conn.FileSystem()}

	// check if use ssh directory exists
	exists, err := afutil.Exists(userSshPath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return res, nil
	}

	filter := []string{"config"}

	// walk dir and search for all private keys
	potentialPrivateKeyFiles := []string{}
	err = afutil.Walk(userSshPath, func(path string, f os.FileInfo, err error) error {
		if f == nil || f.IsDir() {
			return nil
		}

		// eg. matches google_compute_known_hosts and known_hosts
		if strings.HasSuffix(f.Name(), ".pub") || strings.HasSuffix(f.Name(), "known_hosts") {
			return nil
		}

		for i := range filter {
			if f.Name() == filter[i] {
				return nil
			}
		}

		potentialPrivateKeyFiles = append(potentialPrivateKeyFiles, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// iterate over files and check if the content is there
	for i := range potentialPrivateKeyFiles {
		path := potentialPrivateKeyFiles[i]
		data, err := afutil.ReadFile(path)
		if err != nil {
			return nil, err
		}

		content := string(data)

		// check if content contains PRIVATE KEY
		isPrivateKey := strings.Contains(content, "PRIVATE KEY")
		// check if the key is encrypted ENCRYPTED
		isEncrypted := strings.Contains(content, "ENCRYPTED")

		if isPrivateKey {
			// NOTE: we use new instead of create so that the file resource is properly initialized
			upk, err := NewResource(u.MqlRuntime, "privatekey", map[string]*llx.RawData{
				"pem":       llx.StringData(content),
				"encrypted": llx.BoolData(isEncrypted),
				"path":      llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, upk.(*mqlPrivatekey))
		}
	}

	return res, nil
}
