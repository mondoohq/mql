// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUfwKeyValue(t *testing.T) {
	input := `# /etc/ufw/ufw.conf
#

# Set to yes to start on boot.
ENABLED=yes

# Please use the 'ufw' command to set the loglevel.
LOGLEVEL=low
`
	result := parseUfwKeyValue(input)
	assert.Equal(t, "yes", result["ENABLED"])
	assert.Equal(t, "low", result["LOGLEVEL"])
}

func TestParseUfwKeyValueQuoted(t *testing.T) {
	input := `IPV6=yes
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="DROP"
DEFAULT_APPLICATION_POLICY="SKIP"
`
	result := parseUfwKeyValue(input)
	assert.Equal(t, "yes", result["IPV6"])
	assert.Equal(t, "DROP", result["DEFAULT_INPUT_POLICY"])
	assert.Equal(t, "ACCEPT", result["DEFAULT_OUTPUT_POLICY"])
	assert.Equal(t, "DROP", result["DEFAULT_FORWARD_POLICY"])
	assert.Equal(t, "SKIP", result["DEFAULT_APPLICATION_POLICY"])
}

func TestUfwPolicyName(t *testing.T) {
	assert.Equal(t, "deny", ufwPolicyName("DROP"))
	assert.Equal(t, "allow", ufwPolicyName("ACCEPT"))
	assert.Equal(t, "reject", ufwPolicyName("REJECT"))
	assert.Equal(t, "deny", ufwPolicyName("drop"))
	assert.Equal(t, "allow", ufwPolicyName("accept"))
	assert.Equal(t, "", ufwPolicyName(""))
}

func TestParseUfwKeyValueDisabled(t *testing.T) {
	input := `ENABLED=no
LOGLEVEL=low
`
	result := parseUfwKeyValue(input)
	assert.Equal(t, "no", result["ENABLED"])
}

func TestParseUfwTuples(t *testing.T) {
	input := `*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### deny tcp 3306 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 3306 -j DROP

### tuple ### allow any 80 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 80 -j ACCEPT
-A ufw-user-input -p udp --dport 80 -j ACCEPT

### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit
-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept

### tuple ### allow tcp 443 0.0.0.0/0 any 10.0.0.0/8 in_eth0
-A ufw-user-input -i eth0 -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT

### tuple ### reject tcp 25 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 25 -j REJECT

### tuple ### allow udp 53 0.0.0.0/0 any 0.0.0.0/0 out
-A ufw-user-output -p udp --dport 53 -j ACCEPT

### tuple ### allow_log tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-logging-input -p tcp --dport 8080 -j LOG
-A ufw-user-input -p tcp --dport 8080 -j ACCEPT

-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "
-A ufw-user-limit -j REJECT
-A ufw-user-limit-accept -j ACCEPT
COMMIT
`
	rules := parseUfwTuples(input)
	assert.Len(t, rules, 8)

	// allow tcp 22 in
	assert.Equal(t, "ALLOW", rules[0].action)
	assert.Equal(t, "tcp", rules[0].protocol)
	assert.Equal(t, "22", rules[0].port)
	assert.Equal(t, "0.0.0.0/0", rules[0].to)
	assert.Equal(t, "0.0.0.0/0", rules[0].from)
	assert.Equal(t, "IN", rules[0].direction)
	assert.Equal(t, "", rules[0].iface)

	// deny tcp 3306 in
	assert.Equal(t, "DENY", rules[1].action)
	assert.Equal(t, "tcp", rules[1].protocol)
	assert.Equal(t, "3306", rules[1].port)
	assert.Equal(t, "IN", rules[1].direction)

	// allow any 80 in
	assert.Equal(t, "ALLOW", rules[2].action)
	assert.Equal(t, "any", rules[2].protocol)
	assert.Equal(t, "80", rules[2].port)

	// limit tcp 22 in
	assert.Equal(t, "LIMIT", rules[3].action)
	assert.Equal(t, "tcp", rules[3].protocol)
	assert.Equal(t, "22", rules[3].port)

	// allow tcp 443 in_eth0
	assert.Equal(t, "ALLOW", rules[4].action)
	assert.Equal(t, "tcp", rules[4].protocol)
	assert.Equal(t, "443", rules[4].port)
	assert.Equal(t, "10.0.0.0/8", rules[4].from)
	assert.Equal(t, "IN", rules[4].direction)
	assert.Equal(t, "eth0", rules[4].iface)

	// reject tcp 25 in
	assert.Equal(t, "REJECT", rules[5].action)

	// allow udp 53 out
	assert.Equal(t, "ALLOW", rules[6].action)
	assert.Equal(t, "udp", rules[6].protocol)
	assert.Equal(t, "53", rules[6].port)
	assert.Equal(t, "OUT", rules[6].direction)

	// allow_log tcp 8080 in (log suffix stripped)
	assert.Equal(t, "ALLOW", rules[7].action)
	assert.Equal(t, "tcp", rules[7].protocol)
	assert.Equal(t, "8080", rules[7].port)
}

func TestParseUfwTuplesEmpty(t *testing.T) {
	// Real-world empty rules file from user's system
	input := `*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###
-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "
-A ufw-user-limit -j REJECT
-A ufw-user-limit-accept -j ACCEPT
COMMIT
`
	rules := parseUfwTuples(input)
	assert.Empty(t, rules)
}

func TestParseUfwTuplesWithApps(t *testing.T) {
	// Tuple with application names (dapp/sapp fields before direction)
	input := `### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 Apache%20Full - in
-A ufw-user-input -p tcp --dport 80 -j ACCEPT
`
	rules := parseUfwTuples(input)
	assert.Len(t, rules, 1)
	assert.Equal(t, "ALLOW", rules[0].action)
	assert.Equal(t, "tcp", rules[0].protocol)
	assert.Equal(t, "80", rules[0].port)
	assert.Equal(t, "IN", rules[0].direction)
}

func TestParseUfwTuplesLogAll(t *testing.T) {
	input := `### tuple ### deny_log-all tcp 9999 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 9999 -j DROP
`
	rules := parseUfwTuples(input)
	assert.Len(t, rules, 1)
	assert.Equal(t, "DENY", rules[0].action)
}

func TestParseUfwApplications(t *testing.T) {
	input := `[Nginx HTTP]
title=Web Server (Nginx, HTTP)
description=Small, but very powerful and efficient web server
ports=80/tcp

[Nginx HTTPS]
title=Web Server (Nginx, HTTPS)
description=Small, but very powerful and efficient web server
ports=443/tcp

[Nginx Full]
title=Web Server (Nginx, HTTP + HTTPS)
description=Small, but very powerful and efficient web server
ports=80,443/tcp

[Nginx QUIC]
title=Web Server (Nginx, HTTP + HTTPS + QUIC)
description=Small, but very powerful and efficient web server
ports=80,443/tcp|443/udp
`
	apps := parseUfwApplications(input)
	assert.Len(t, apps, 4)

	assert.Equal(t, "Nginx HTTP", apps[0].name)
	assert.Equal(t, "Web Server (Nginx, HTTP)", apps[0].title)
	assert.Equal(t, "Small, but very powerful and efficient web server", apps[0].description)
	assert.Equal(t, "80/tcp", apps[0].ports)

	assert.Equal(t, "Nginx HTTPS", apps[1].name)
	assert.Equal(t, "443/tcp", apps[1].ports)

	assert.Equal(t, "Nginx Full", apps[2].name)
	assert.Equal(t, "80,443/tcp", apps[2].ports)

	assert.Equal(t, "Nginx QUIC", apps[3].name)
	assert.Equal(t, "80,443/tcp|443/udp", apps[3].ports)
}

func TestParseUfwApplicationsEmpty(t *testing.T) {
	apps := parseUfwApplications("")
	assert.Empty(t, apps)
}

func TestParseUfwApplicationsWithComments(t *testing.T) {
	input := `# Custom app
[MyApp]
title=My Application
description=A custom application
ports=8080/tcp
`
	apps := parseUfwApplications(input)
	assert.Len(t, apps, 1)
	assert.Equal(t, "MyApp", apps[0].name)
	assert.Equal(t, "8080/tcp", apps[0].ports)
}

// Tuples captured from /etc/ufw/user.rules on Ubuntu 16.04 through 26.04
// after `ufw allow in on ens5 to any port 8080 proto tcp comment 'web alt'`
// and `ufw route allow in on ens5 out on lo to any port 80 proto tcp`.
func TestParseUfwTuplesCommentAndRoute(t *testing.T) {
	rules := parseUfwTuples(`### tuple ### allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in_ens5 comment=77656220616c74
### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_ens5!out_lo
### tuple ### route:deny_log tcp 3306 ::/0 any ::/0 out_lo
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in comment=73736820696e
`)
	require.Len(t, rules, 4)

	assert.Equal(t, "ALLOW", rules[0].action)
	assert.Equal(t, "IN", rules[0].direction)
	assert.Equal(t, "ens5", rules[0].iface)
	assert.Equal(t, "8080", rules[0].port)

	assert.Equal(t, "ALLOW", rules[1].action)
	assert.Equal(t, "FWD", rules[1].direction)
	assert.Equal(t, "ens5", rules[1].iface)
	assert.Equal(t, "80", rules[1].port)

	assert.Equal(t, "DENY", rules[2].action)
	assert.Equal(t, "FWD", rules[2].direction)
	assert.Equal(t, "lo", rules[2].iface)

	assert.Equal(t, "ALLOW", rules[3].action)
	assert.Equal(t, "IN", rules[3].direction)
	assert.Empty(t, rules[3].iface)
}

func TestReadUfwState(t *testing.T) {
	enabledConf := "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n"
	defaults := "DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\n"

	newFs := func(files map[string]string) afero.Afero {
		afs := afero.Afero{Fs: afero.NewMemMapFs()}
		for p, c := range files {
			require.NoError(t, afs.WriteFile(p, []byte(c), 0o644))
		}
		return afs
	}

	t.Run("installed and enabled", func(t *testing.T) {
		st, err := readUfwState(newFs(map[string]string{
			ufwConfPath: enabledConf, ufwDefaultsPath: defaults, "/usr/sbin/ufw": "#!/usr/bin/python3\n",
		}))
		require.NoError(t, err)
		assert.Equal(t, "active", st.status)
		assert.Equal(t, "deny", st.defIncoming)
		assert.Equal(t, "low", st.logging)
	})

	t.Run("removed but not purged", func(t *testing.T) {
		// dpkg -r ufw keeps the conffiles, ENABLED=yes included, and deletes the command.
		st, err := readUfwState(newFs(map[string]string{
			ufwConfPath: enabledConf, ufwDefaultsPath: defaults,
		}))
		require.NoError(t, err)
		assert.Equal(t, "not installed", st.status)
		assert.Empty(t, st.defIncoming)
	})

	t.Run("purged", func(t *testing.T) {
		st, err := readUfwState(newFs(map[string]string{}))
		require.NoError(t, err)
		assert.Equal(t, "not installed", st.status)
	})
}
