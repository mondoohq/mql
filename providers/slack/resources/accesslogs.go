// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"time"

	"github.com/slack-go/slack"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/slack/connection"
)

func (s *mqlSlack) accessLogs() ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.SlackConnection)
	client := conn.Client()
	if client == nil {
		return nil, errors.New("cannot retrieve new data while using a mock connection")
	}

	var list []any
	var cursor string
	for {
		accessLogs, nextCursor, err := client.GetAccessLogs(slack.AccessLogParameters{
			Limit:  999, // use maximum, must be lower than 1000
			Cursor: cursor,
		})
		if err != nil {
			return nil, err
		}
		for i := range accessLogs {
			mqlUser, err := newMqlSlackLogin(s.MqlRuntime, accessLogs[i])
			if err != nil {
				return nil, err
			}
			list = append(list, mqlUser)
		}
		if nextCursor == "" {
			break
		}
		cursor = nextCursor
	}
	return list, nil
}

func newMqlSlackLogin(runtime *plugin.Runtime, login slack.Login) (any, error) {
	dateFirst := time.Unix(int64(login.DateFirst), 0)
	dateLast := time.Unix(int64(login.DateLast), 0)
	return CreateResource(runtime, "slack.login", map[string]*llx.RawData{
		"userID":    llx.StringData(login.UserID),
		"username":  llx.StringData(login.Username),
		"count":     llx.IntData(int64(login.Count)),
		"ip":        llx.StringData(login.IP),
		"userAgent": llx.StringData(login.UserAgent),
		"isp":       llx.StringData(login.ISP),
		"country":   llx.StringData(login.Country),
		"region":    llx.StringData(login.Region),
		"dateFirst": llx.TimeData(dateFirst),
		"dateLast":  llx.TimeData(dateLast),
	})
}

func (x *mqlSlackLogin) id() (string, error) {
	return "slack.login/user/" + x.UserID.Data + "/ip/" + x.Ip.Data + "/useragent/" + x.UserAgent.Data, nil
}
