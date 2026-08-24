// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/jenkins/connection"
)

// id returns the connection's base URL, the stable identifier for a Jenkins
// controller. There is exactly one jenkins resource per connection.
func (r *mqlJenkins) id() (string, error) {
	return r.conn().BaseUrl(), nil
}

// url is the base URL the connection targets.
func (r *mqlJenkins) url() (string, error) {
	return r.conn().BaseUrl(), nil
}

// version is the Jenkins core version reported via the X-Jenkins response
// header during connection setup.
func (r *mqlJenkins) version() (string, error) {
	return r.conn().Client().Version, nil
}

// mode is the controller's operating mode (NORMAL or EXCLUSIVE), read from
// the root executor response gathered during connection setup.
func (r *mqlJenkins) mode() (string, error) {
	return r.conn().Client().Raw.Mode, nil
}

// quietingDown reports whether the controller is shutting down for
// maintenance, read from the root executor response gathered during
// connection setup.
func (r *mqlJenkins) quietingDown() (bool, error) {
	return r.conn().Client().Raw.QuietingDown, nil
}

// conn returns the Jenkins connection backing this runtime.
func (r *mqlJenkins) conn() *connection.JenkinsConnection {
	return r.MqlRuntime.Connection.(*connection.JenkinsConnection)
}
