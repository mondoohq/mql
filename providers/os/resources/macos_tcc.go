// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/glebarez/go-sqlite" // registers the "sqlite" database/sql driver
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	// tccSystemStorePath is the machine-wide TCC store. It holds the
	// high-privilege services: Full Disk Access, Screen Recording,
	// Accessibility, Input Monitoring, Developer Tools and Endpoint Security.
	tccSystemStorePath = "/Library/Application Support/com.apple.TCC/TCC.db"
	// tccUserStoreRelPath is the per-user TCC store, relative to a home
	// directory. It holds the per-user services: Camera, Microphone, Photos,
	// Contacts, Automation and the protected user folders.
	tccUserStoreRelPath = "Library/Application Support/com.apple.TCC/TCC.db"

	tccScopeSystem = "system"
	tccScopeUser   = "user"

	// tccIndirectObjectUnused is the literal TCC writes into
	// indirect_object_identifier for services that take no target.
	tccIndirectObjectUnused = "UNUSED"
)

// tccServiceNames maps the raw kTCCService identifiers onto the names macOS
// shows in System Settings. Apple adds identifiers with every release, so this
// is deliberately not exhaustive: tccServiceName passes an unrecognized
// identifier through unchanged rather than guessing at a label for it.
var tccServiceNames = map[string]string{
	"kTCCServiceAccessibility":                "Accessibility",
	"kTCCServiceAddressBook":                  "Contacts",
	"kTCCServiceAppleEvents":                  "Automation",
	"kTCCServiceAudioCapture":                 "Audio Capture",
	"kTCCServiceBluetoothAlways":              "Bluetooth",
	"kTCCServiceCalendar":                     "Calendar",
	"kTCCServiceCamera":                       "Camera",
	"kTCCServiceDeveloperTool":                "Developer Tools",
	"kTCCServiceEndpointSecurityClient":       "Endpoint Security Client",
	"kTCCServiceFileProviderDomain":           "File Provider",
	"kTCCServiceFocusStatus":                  "Focus Status",
	"kTCCServiceListenEvent":                  "Input Monitoring",
	"kTCCServiceMediaLibrary":                 "Media Library",
	"kTCCServiceMicrophone":                   "Microphone",
	"kTCCServiceMotion":                       "Motion & Fitness",
	"kTCCServicePhotos":                       "Photos",
	"kTCCServicePostEvent":                    "Send Keystrokes",
	"kTCCServiceReminders":                    "Reminders",
	"kTCCServiceScreenCapture":                "Screen Recording",
	"kTCCServiceSpeechRecognition":            "Speech Recognition",
	"kTCCServiceSystemPolicyAllFiles":         "Full Disk Access",
	"kTCCServiceSystemPolicyAppBundles":       "App Management",
	"kTCCServiceSystemPolicyAppData":          "App Data",
	"kTCCServiceSystemPolicyDesktopFolder":    "Desktop Folder",
	"kTCCServiceSystemPolicyDocumentsFolder":  "Documents Folder",
	"kTCCServiceSystemPolicyDownloadsFolder":  "Downloads Folder",
	"kTCCServiceSystemPolicyNetworkVolumes":   "Network Volumes",
	"kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes",
	"kTCCServiceSystemPolicySysAdminFiles":    "Administrative Files",
}

// tccAuthorizations maps the auth_value column onto readable states. macOS uses
// codes beyond this set (an auth_value of 5 occurs on current releases), so
// tccAuthorization reports an unrecognized code as "unknown" and the caller
// keeps the raw value.
var tccAuthorizations = map[int64]string{
	0: "denied",
	1: "unknown",
	2: "allowed",
	3: "limited",
}

// tccAuthReasons maps the auth_reason column onto readable origins. The
// distinction that matters for an audit is mdmPolicy (an administrator pushed
// the grant) against userConsent and userSet (someone clicked Allow).
var tccAuthReasons = map[int64]string{
	1:  "error",
	2:  "userConsent",
	3:  "userSet",
	4:  "systemSet",
	5:  "servicePolicy",
	6:  "mdmPolicy",
	7:  "overridePolicy",
	8:  "missingUsageString",
	9:  "promptTimeout",
	10: "preflightUnknown",
	11: "entitled",
	12: "appTypePolicy",
}

func tccServiceName(service string) string {
	if name, ok := tccServiceNames[service]; ok {
		return name
	}
	return service
}

func tccAuthorization(authValue int64) string {
	if s, ok := tccAuthorizations[authValue]; ok {
		return s
	}
	return "unknown"
}

// tccGranted reports whether the application may use the service. Both a full
// grant and a limited one permit access, so both count. An undecoded code
// reports false, which is why the raw value stays available on the resource.
func tccGranted(authValue int64) bool {
	return authValue == 2 || authValue == 3
}

func tccAuthReason(authReason int64) string {
	if s, ok := tccAuthReasons[authReason]; ok {
		return s
	}
	return "unknown"
}

func tccClientType(clientType int64) string {
	switch clientType {
	case 0:
		return "bundleId"
	case 1:
		return "path"
	default:
		return "unknown"
	}
}

// tccIndirectObject normalizes the indirect_object_identifier column. TCC
// stores the literal "UNUSED" when the service takes no target; that is an
// absence, so it is reported as an empty string.
func tccIndirectObject(v string) string {
	if v == tccIndirectObjectUnused {
		return ""
	}
	return v
}

// tccRow is one normalized row of the access table.
type tccRow struct {
	service                  string
	client                   string
	clientType               int64
	authValue                int64
	authReason               int64
	indirectObjectIdentifier string
	lastModified             int64
}

// tccAccessQuery builds the SELECT over the access table from the columns the
// database actually has. macOS Mojave and Catalina name the authorization
// column `allowed` (0 or 1) and carry no auth_reason; Big Sur and later use
// auth_value, whose range is wider, and add auth_reason. Reading the column set
// rather than assuming one keeps an image of an older system resolvable. The
// projection is always seven columns in a fixed order, with a literal standing
// in for a column the schema does not have.
func tccAccessQuery(columns map[string]struct{}) (query string, legacyAllowed bool, err error) {
	has := func(c string) bool {
		_, ok := columns[c]
		return ok
	}

	authColumn := ""
	switch {
	case has("auth_value"):
		authColumn = "auth_value"
	case has("allowed"):
		authColumn = "allowed"
		legacyAllowed = true
	default:
		return "", false, errors.New("TCC access table has neither an auth_value nor an allowed column")
	}

	if !has("service") || !has("client") || !has("client_type") {
		return "", false, errors.New("TCC access table is missing the service, client, or client_type column")
	}

	authReason := "0"
	if has("auth_reason") {
		authReason = "auth_reason"
	}
	indirect := "''"
	if has("indirect_object_identifier") {
		indirect = "indirect_object_identifier"
	}
	lastModified := "0"
	if has("last_modified") {
		lastModified = "last_modified"
	}

	return fmt.Sprintf(
		"SELECT service, client, client_type, %s, %s, %s, %s FROM access",
		authColumn, authReason, indirect, lastModified,
	), legacyAllowed, nil
}

// tccNormalizeAuthValue converts the legacy `allowed` column onto the auth_value
// scale so both schema generations produce the same authorization strings.
func tccNormalizeAuthValue(v int64, legacyAllowed bool) int64 {
	if !legacyAllowed {
		return v
	}
	if v == 1 {
		return 2 // allowed
	}
	return 0 // denied
}

// readTccStore copies a TCC store to a local temp file and reads its access
// table. The store may live on a remote connection or inside an image, so the
// bytes come through the connection filesystem rather than being opened in
// place. TCC keeps the database in journal_mode=delete, so there are no WAL
// sidecars to carry across and the read is opened immutable.
//
// A store that does not exist yields (nil, nil): a user who has never granted
// anything has no store, which is an absence rather than a failure. Any other
// read error is returned, so a store that exists but cannot be read (the usual
// case on a live system without Full Disk Access) surfaces instead of quietly
// shortening the result.
func readTccStore(afs *afero.Afero, storePath string) ([]tccRow, error) {
	data, err := afs.ReadFile(storePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read TCC store %s: %w", storePath, err)
	}

	tmp, err := os.CreateTemp("", "tcc-*.db")
	if err != nil {
		return nil, fmt.Errorf("cannot create temp file for TCC store %s: %w", storePath, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("cannot stage TCC store %s: %w", storePath, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("cannot stage TCC store %s: %w", storePath, err)
	}

	db, err := sql.Open("sqlite", "file:"+tmp.Name()+"?mode=ro&immutable=1")
	if err != nil {
		return nil, fmt.Errorf("cannot open TCC store %s: %w", storePath, err)
	}
	defer db.Close()

	columns, err := tccTableColumns(db, "access")
	if err != nil {
		return nil, fmt.Errorf("cannot read the schema of TCC store %s: %w", storePath, err)
	}
	query, legacyAllowed, err := tccAccessQuery(columns)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", storePath, err)
	}

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("cannot query TCC store %s: %w", storePath, err)
	}
	defer rows.Close()

	var out []tccRow
	for rows.Next() {
		var r tccRow
		if err := rows.Scan(&r.service, &r.client, &r.clientType, &r.authValue,
			&r.authReason, &r.indirectObjectIdentifier, &r.lastModified); err != nil {
			return nil, fmt.Errorf("cannot read a row of TCC store %s: %w", storePath, err)
		}
		r.authValue = tccNormalizeAuthValue(r.authValue, legacyAllowed)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read TCC store %s: %w", storePath, err)
	}
	return out, nil
}

// tccTableColumns returns the column names of a table.
func tccTableColumns(db *sql.DB, table string) (map[string]struct{}, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns := map[string]struct{}{}
	for rows.Next() {
		var (
			cid       int64
			name      string
			ctype     sql.NullString
			notnull   sql.NullInt64
			dfltValue sql.NullString
			pk        sql.NullInt64
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		columns[name] = struct{}{}
	}
	return columns, rows.Err()
}

func (r *mqlMacosTcc) id() (string, error) {
	return "macos.tcc", nil
}

// tccEntryID builds the cache key for one grant. The access table's own primary
// key is (service, client, client_type, indirect_object_identifier); a machine
// carries one system store and one store per user, so scope and user complete
// the identity. Without them the same application's Camera grant in two users'
// stores would collapse onto one cached entry.
func tccEntryID(scope, user string, row tccRow) string {
	return strings.Join([]string{
		scope, user, row.service, row.client,
		fmt.Sprintf("%d", row.clientType), row.indirectObjectIdentifier,
	}, "\x00")
}

func (r *mqlMacosTcc) entries() ([]any, error) {
	conn, ok := r.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("macos.tcc requires an operating system connection")
	}
	if platform := conn.Asset().Platform; platform == nil || !platform.IsFamily("darwin") {
		return nil, errors.New("macos.tcc is only supported on macOS")
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}

	var entries []any

	systemRows, err := readTccStore(afs, tccSystemStorePath)
	if err != nil {
		return nil, err
	}
	for _, row := range systemRows {
		entry, err := r.newEntry(tccScopeSystem, "", row)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	users, err := targetUserHomes(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// Sort so the result is stable regardless of the order users are listed in.
	sort.Slice(users, func(i, j int) bool { return users[i].name < users[j].name })

	for _, u := range users {
		storePath := strings.TrimSuffix(u.home, "/") + "/" + tccUserStoreRelPath
		userRows, err := readTccStore(afs, storePath)
		if err != nil {
			return nil, err
		}
		for _, row := range userRows {
			entry, err := r.newEntry(tccScopeUser, u.name, row)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func (r *mqlMacosTcc) newEntry(scope, user string, row tccRow) (plugin.Resource, error) {
	var lastModified *time.Time
	// TCC writes a unix timestamp; a store that carries no last_modified column
	// leaves this at zero, which is an absence rather than 1 January 1970.
	if row.lastModified > 0 {
		t := time.Unix(row.lastModified, 0).UTC()
		lastModified = &t
	}

	res, err := CreateResource(r.MqlRuntime, "macos.tcc.entry", map[string]*llx.RawData{
		"__id":                     llx.StringData(tccEntryID(scope, user, row)),
		"scope":                    llx.StringData(scope),
		"service":                  llx.StringData(row.service),
		"serviceName":              llx.StringData(tccServiceName(row.service)),
		"client":                   llx.StringData(row.client),
		"clientType":               llx.StringData(tccClientType(row.clientType)),
		"authorization":            llx.StringData(tccAuthorization(row.authValue)),
		"authorizationValue":       llx.IntData(row.authValue),
		"granted":                  llx.BoolData(tccGranted(row.authValue)),
		"authReason":               llx.StringData(tccAuthReason(row.authReason)),
		"authReasonValue":          llx.IntData(row.authReason),
		"indirectObjectIdentifier": llx.StringData(tccIndirectObject(row.indirectObjectIdentifier)),
		"lastModified":             llx.TimeDataPtr(lastModified),
	})
	if err != nil {
		return nil, err
	}

	entry := res.(*mqlMacosTccEntry)
	entry.cacheUserName = user
	return entry, nil
}

// mqlMacosTccEntryInternal carries the owning user's name from the creation
// context so user() can resolve it without re-reading the store.
type mqlMacosTccEntryInternal struct {
	cacheUserName string
}

// user resolves the account whose store holds this grant. System-scope grants
// belong to no user, so the field is explicitly null rather than left unset.
func (r *mqlMacosTccEntry) user() (*mqlUser, error) {
	if r.cacheUserName == "" {
		r.User.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(r.MqlRuntime, "user", map[string]*llx.RawData{
		"name": llx.StringData(r.cacheUserName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlUser), nil
}
