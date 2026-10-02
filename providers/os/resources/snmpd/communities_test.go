// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package snmpd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The access lines of the stock Ubuntu 24.04 snmpd.conf plus the sweep
// fixture, as loaded by Net-SNMP 5.9.4. snmpget and snmpset against the
// running agent gave the ground truth: public and readonly2 read, private
// writes (snmpset answers notWritable for sysLocation, not noAccess), and
// secret42 is accepted but reaches no object because view all is not
// declared.
const ubuntuSweepConfig = `view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
includeDir /etc/snmp/snmpd.conf.d
agentAddress udp:127.0.0.1:1161,tcp:127.0.0.1:1162
rwcommunity private 127.0.0.1 .1.3.6.1.2.1.1
rocommunity readonly2 127.0.0.1 -V systemonly
com2sec rwsec localhost secret42
group rwgroup v2c rwsec
access rwgroup "" any noauth exact all all none
rwuser -s usm admin3 priv -V systemonly
`

func TestCommunities(t *testing.T) {
	t.Run("com2sec through an undeclared view grants nothing", func(t *testing.T) {
		ro, rw := Communities(ubuntuSweepConfig)
		assert.Equal(t, []string{"public", "public", "readonly2"}, ro)
		assert.Equal(t, []string{"private"}, rw)
	})

	// With view all declared, snmpset with secret42 answered notWritable
	// for sysLocation, the same as rwcommunity private.
	t.Run("com2sec through a declared write view is read-write", func(t *testing.T) {
		ro, rw := Communities(ubuntuSweepConfig + "view all included .1\n")
		assert.Equal(t, []string{"public", "public", "readonly2"}, ro)
		assert.Equal(t, []string{"private", "secret42"}, rw)
	})

	t.Run("com2sec through a read view only is read-only", func(t *testing.T) {
		ro, rw := Communities(`view systemonly included .1.3.6.1.2.1.1
com2sec -Cn ctxA readsec 10.0.0.0/8 monitor
com2sec6 -Cn ctxA readsec6 fd00::/8 monitor6
group readers v1 readsec
group readers v2c readsec6
com2sec -Cn other othersec 10.0.0.0/8 otherctx
group readers v2c othersec
access readers "" any noauth exact systemonly none none
access readers ctx any noauth prefix systemonly none none
`)
		assert.Equal(t, []string{"monitor", "monitor6"}, ro)
		assert.Empty(t, rw)
	})

	t.Run("access lines a community request cannot match grant nothing", func(t *testing.T) {
		ro, rw := Communities(`view all included .1
com2sec authsec default needsauth
com2sec usmsec default usmmodel
com2sec nogroup default orphan
group authgroup v2c authsec
group usmgroup usm usmsec
access authgroup "" any auth exact all all none
access usmgroup "" any noauth exact all all none
`)
		assert.Empty(t, ro)
		assert.Empty(t, rw)
	})

	t.Run("a view with only excluded subtrees grants nothing", func(t *testing.T) {
		ro, rw := Communities(`view hidden excluded .1
com2sec sec default hiddencomm
group g v2c sec
access g "" v2c noauth exact hidden hidden none
`)
		assert.Empty(t, ro)
		assert.Empty(t, rw)
	})

	t.Run("authcommunity grants what its types list", func(t *testing.T) {
		ro, rw := Communities(`authcommunity read,write writer default
authcommunity read reader default
authcommunity log logger default
`)
		assert.Equal(t, []string{"reader"}, ro)
		assert.Equal(t, []string{"writer"}, rw)
	})

	t.Run("no communities", func(t *testing.T) {
		ro, rw := Communities("")
		assert.Empty(t, ro)
		assert.Empty(t, rw)
	})
}

func TestUserNames(t *testing.T) {
	content := `rouser authPrivUser authpriv -V systemonly
rwuser -s usm admin3 priv -V systemonly
rwuser opuser auth .1.3.6.1.2.1.1
authuser read,write -s usm ctxuser priv .1.3.6.1.2.1
rouser -s tsm tlsuser
rouser -s
`
	assert.Equal(t, []string{"authPrivUser", "tlsuser"}, UserNames(content, "rouser"))
	assert.Equal(t, []string{"admin3", "opuser"}, UserNames(content, "rwuser"))
}
