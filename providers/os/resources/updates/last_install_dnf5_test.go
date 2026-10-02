// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `dnf5 history info --json 1..last` on the Fedora 44 sweep host, trimmed to
// a few packages per transaction: transaction 7 upgraded grub2, 6 and 1 only
// installed packages.
const dnf5HistoryFedora44 = `[
  {
    "id":7,
    "start_time":1790926160,
    "end_time":1790926164,
    "user_id":1000,
    "status":"Ok",
    "releasever":"44",
    "description":"dnf -y upgrade grub2-common grub2-pc",
    "comment":"",
    "packages":[
      {"nevra":"grub2-common-1:2.12-66.fc44.noarch","action":"Upgrade","reason":"Dependency","repository":"updates"},
      {"nevra":"grub2-pc-1:2.12-66.fc44.x86_64","action":"Upgrade","reason":"User","repository":"updates"},
      {"nevra":"grub2-common-1:2.12-64.fc44.noarch","action":"Replaced","reason":"Dependency","repository":"@System"},
      {"nevra":"grub2-pc-1:2.12-64.fc44.x86_64","action":"Replaced","reason":"User","repository":"@System"}
    ],
    "groups":[],
    "environments":[]
  },
  {
    "id":6,
    "start_time":1790925952,
    "end_time":1790925954,
    "user_id":1000,
    "status":"Ok",
    "releasever":"44",
    "description":"dnf -y install rpm-build",
    "comment":"",
    "packages":[
      {"nevra":"rpm-build-6.0.1-1.fc44.x86_64","action":"Install","reason":"User","repository":"fedora"}
    ],
    "groups":[],
    "environments":[]
  },
  {
    "id":1,
    "start_time":1790666470,
    "end_time":1790666500,
    "user_id":0,
    "status":"Ok",
    "releasever":"44",
    "description":"dnf5 --config /builddir/result/image/build.conf",
    "comment":"",
    "packages":[
      {"nevra":"glibc-2.43-3.fc44.x86_64","action":"Install","reason":"User","repository":"fedora"}
    ],
    "groups":[],
    "environments":[]
  }
]`

func TestParseDnf5History(t *testing.T) {
	t.Run("the newest vendor upgrade transaction", func(t *testing.T) {
		got, err := ParseDnf5History(strings.NewReader(dnf5HistoryFedora44),
			vendorSet("grub2-common", "grub2-pc", "rpm-build", "glibc"))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "2026-10-02T07:29:24Z", got.Time.Format(time.RFC3339))
		assert.Equal(t, LastUpdateSourceDnf5History, got.Source)
	})

	t.Run("installs are no evidence", func(t *testing.T) {
		// rpm-build and glibc are vendor packages, but only installed
		got, err := ParseDnf5History(strings.NewReader(dnf5HistoryFedora44),
			vendorSet("rpm-build", "glibc"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("third-party upgrades and failed transactions do not count", func(t *testing.T) {
		history := `[
  {"id":9,"end_time":1790990000,"status":"Ok","packages":[
    {"nevra":"docker-ce-3:28.0.1-1.fc44.x86_64","action":"Upgrade"},
    {"nevra":"docker-ce-3:28.0.0-1.fc44.x86_64","action":"Replaced"}]},
  {"id":8,"end_time":1790980000,"status":"Error","packages":[
    {"nevra":"openssl-libs-1:3.5.4-1.fc44.x86_64","action":"Upgrade"}]},
  {"id":3,"end_time":1790900000,"status":"Ok","packages":[
    {"nevra":"openssl-libs-1:3.5.3-1.fc44.x86_64","action":"Upgrade"}]},
  {"id":2,"end_time":1790800000,"status":"Ok","packages":[
    {"nevra":"openssl-libs-1:3.5.2-1.fc44.x86_64","action":"Downgrade"},
    {"nevra":"openssl-libs-1:3.5.3-1.fc44.x86_64","action":"Replaced"}]}
]`
		got, err := ParseDnf5History(strings.NewReader(history), vendorSet("openssl-libs"))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, int64(1790900000), got.Time.Unix())
	})

	t.Run("empty history", func(t *testing.T) {
		got, err := ParseDnf5History(strings.NewReader("[]\n"), vendorSet("glibc"))
		require.NoError(t, err)
		assert.Nil(t, got)

		got, err = ParseDnf5History(strings.NewReader(""), vendorSet("glibc"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("output that isn't JSON is an error", func(t *testing.T) {
		_, err := ParseDnf5History(strings.NewReader("Unknown argument \"--json\" for command \"info\".\n"), vendorSet("glibc"))
		assert.Error(t, err)
	})
}
