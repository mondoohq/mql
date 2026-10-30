// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

type UserInfo struct {
	UserID         string `json:"userid"`
	Email          string `json:"email"`
	Enable         int    `json:"enable"`
	Expire         int64  `json:"expire"`
	Firstname      string `json:"firstname"`
	Lastname       string `json:"lastname"`
	Groups         string `json:"groups"` // comma-separated
	RealmType      string `json:"realm-type"`
	TFALockedUntil int64  `json:"tfa-locked-until"`
	Tokens         []struct {
		TokenID string `json:"tokenid"`
		Comment string `json:"comment"`
		Expire  int64  `json:"expire"`
		Privsep int    `json:"privsep"`
	} `json:"tokens"`
}

func (c *PveConnection) GetUsers() ([]UserInfo, error) {
	var users []UserInfo
	if err := c.apiGet("/access/users?full=1", &users); err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	return users, nil
}

// ---------------------------------------------------------------------------
// User tokens
// ---------------------------------------------------------------------------

type TokenInfo struct {
	TokenID string `json:"tokenid"`
	Comment string `json:"comment"`
	Expire  int64  `json:"expire"`
	Privsep int    `json:"privsep"`
}

func (c *PveConnection) GetUserTokens(userid string) ([]TokenInfo, error) {
	var tokens []TokenInfo
	path := fmt.Sprintf("/access/users/%s/token", userid)
	if err := c.apiGet(path, &tokens); err != nil {
		return nil, fmt.Errorf("failed to get tokens for user %s: %w", userid, err)
	}
	return tokens, nil
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

type RoleInfo struct {
	RoleID  string `json:"roleid"`
	Privs   string `json:"privs"` // comma-separated
	Special int    `json:"special"`
}

func (c *PveConnection) GetRoles() ([]RoleInfo, error) {
	var roles []RoleInfo
	if err := c.apiGet("/access/roles", &roles); err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	return roles, nil
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

type GroupInfo struct {
	GroupID string `json:"groupid"`
	Comment string `json:"comment"`
	Users   string `json:"users"` // comma-separated user IDs
}

func (c *PveConnection) GetGroups() ([]GroupInfo, error) {
	var groups []GroupInfo
	if err := c.apiGet("/access/groups", &groups); err != nil {
		return nil, fmt.Errorf("failed to get groups: %w", err)
	}
	// /access/groups doesn't return the users list — fetch each group for membership
	for i := range groups {
		var detail struct {
			Comment string   `json:"comment"`
			Members []string `json:"members"`
		}
		path := fmt.Sprintf("/access/groups/%s", groups[i].GroupID)
		if err := c.apiGet(path, &detail); err != nil {
			continue
		}
		if groups[i].Comment == "" {
			groups[i].Comment = detail.Comment
		}
		if len(detail.Members) > 0 {
			groups[i].Users = strings.Join(detail.Members, ",")
		}
	}
	return groups, nil
}

// ---------------------------------------------------------------------------
// ACL — access control list entries
// ---------------------------------------------------------------------------

type ACLEntry struct {
	Path      string `json:"path"`
	Type      string `json:"type"` // user, group, token
	UGID      string `json:"ugid"` // user@realm | groupId | user@realm!tokenid
	RoleID    string `json:"roleid"`
	Propagate int    `json:"propagate"`
}

func (c *PveConnection) GetACL() ([]ACLEntry, error) {
	var acl []ACLEntry
	if err := c.apiGet("/access/acl", &acl); err != nil {
		return nil, fmt.Errorf("failed to get ACL: %w", err)
	}
	return acl, nil
}

// ---------------------------------------------------------------------------
// Authentication realms
// ---------------------------------------------------------------------------

type RealmInfo struct {
	Realm   string `json:"realm"`
	Type    string `json:"type"` // pam, pve, ldap, ad, openid
	Comment string `json:"comment"`
	Default int    `json:"default"`
	TFA     string `json:"tfa"` // empty if no realm-enforced TFA
}

func (c *PveConnection) GetRealms() ([]RealmInfo, error) {
	var realms []RealmInfo
	if err := c.apiGet("/access/domains", &realms); err != nil {
		return nil, fmt.Errorf("failed to get realms: %w", err)
	}
	return realms, nil
}

func (c *PveConnection) GetRealmConfig(realm string) (map[string]any, error) {
	var cfg map[string]any
	path := fmt.Sprintf("/access/domains/%s", realm)
	if err := c.apiGet(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to get realm %s config: %w", realm, err)
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// Per-user TFA factors
// ---------------------------------------------------------------------------

type TFAEntry struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // totp, webauthn, recovery, yubico
	Description string `json:"description"`
	Created     int64  `json:"created"`
}

func (c *PveConnection) GetUserTFA(userid string) ([]TFAEntry, error) {
	var entries []TFAEntry
	path := fmt.Sprintf("/access/tfa/%s", userid)
	if err := c.apiGet(path, &entries); err != nil {
		return nil, fmt.Errorf("failed to get TFA entries for user %s: %w", userid, err)
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// Directory realm sync jobs
// ---------------------------------------------------------------------------

// RealmSyncJob is a scheduled import of users and groups from a directory
// realm into the Proxmox user database.
//
// Enabled is a pointer so that a payload which omits the key reports null
// rather than the Go zero value; Proxmox declares it a boolean but serializes
// it as the integer 1 or 0, which PveBool absorbs.
type RealmSyncJob struct {
	ID             string   `json:"id"`
	Realm          string   `json:"realm"`
	Schedule       string   `json:"schedule"`
	Comment        string   `json:"comment"`
	Enabled        *PveBool `json:"enabled"`
	RemoveVanished string   `json:"remove-vanished"`
	Scope          string   `json:"scope"`
	LastRun        int64    `json:"last-run"`
	NextRun        int64    `json:"next-run"`
}

// realmSyncIndex memoizes the job listing. Both the cluster-wide accessor and
// the per-realm reverse edge read from it, so without this a fleet of realms
// would re-list the jobs once each.
type realmSyncIndex struct {
	once     sync.Once
	jobs     []RealmSyncJob
	readable bool
	err      error
}

// GetRealmSyncJobs lists the configured realm-sync jobs. The second return
// value is false when the cluster does not serve the endpoint, so a Proxmox
// release without realm-sync jobs is not reported as a cluster that has none.
func (c *PveConnection) GetRealmSyncJobs() ([]RealmSyncJob, bool, error) {
	c.realmSync.once.Do(func() {
		var jobs []RealmSyncJob
		readable, err := c.getIfAvailable("/cluster/jobs/realm-sync", &jobs)
		c.realmSync.jobs, c.realmSync.readable, c.realmSync.err = jobs, readable, err
	})
	return c.realmSync.jobs, c.realmSync.readable, c.realmSync.err
}

// GetRealmSyncJob reads one job's full definition.
//
// The listing endpoint leaves out `enable-new`, which decides whether a user
// appearing in the directory becomes an enabled Proxmox account on the next
// sync, so that one setting needs the per-job route. Returns a nil map when
// the job is not readable.
func (c *PveConnection) GetRealmSyncJob(id string) (map[string]any, error) {
	var cfg map[string]any
	// the id comes back from the listing endpoint rather than from a user, but
	// it is escaped anyway so that a value carrying a separator cannot reshape
	// the request path
	path := "/cluster/jobs/realm-sync/" + url.PathEscape(id)
	readable, err := c.getIfAvailable(path, &cfg)
	if err != nil {
		return nil, err
	}
	if !readable {
		return nil, nil
	}
	return cfg, nil
}

// realmIndex memoizes the realm listing. Resolving the realm behind a sync job
// would otherwise re-list every realm once per job.
type realmIndex struct {
	once   sync.Once
	byName map[string]RealmInfo
	err    error
}

// LookupRealm resolves one realm by name against a single cached listing.
func (c *PveConnection) LookupRealm(realm string) (RealmInfo, bool, error) {
	c.realms.once.Do(func() {
		realms, err := c.GetRealms()
		if err != nil {
			c.realms.err = fmt.Errorf("failed to index realms: %w", err)
			return
		}
		index := make(map[string]RealmInfo, len(realms))
		for _, r := range realms {
			index[r.Realm] = r
		}
		c.realms.byName = index
	})
	if c.realms.err != nil {
		return RealmInfo{}, false, c.realms.err
	}
	r, ok := c.realms.byName[realm]
	return r, ok, nil
}
