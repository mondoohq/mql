// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const polkitTestPolicy = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>The systemd Project</vendor>
  <vendor_url>https://systemd.io</vendor_url>
  <icon_name>system</icon_name>

  <action id="org.freedesktop.systemd1.manage-units">
    <description>Manage system services or other units</description>
    <description xml:lang="de">Systemdienste verwalten</description>
    <message>Authentication is required to manage system services.</message>
    <message xml:lang="de">Legitimierung ist notwendig.</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.imply">org.freedesktop.systemd1.reload-daemon</annotate>
    <annotate key="org.freedesktop.policykit.owner">unix-user:root</annotate>
  </action>

  <action id="org.example.wide-open">
    <description>Wide open action</description>
    <vendor>Example Corp</vendor>
    <defaults>
      <allow_any>yes</allow_any>
      <allow_inactive>yes</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
</policyconfig>
`

func TestParsePolkitPolicy(t *testing.T) {
	actions, err := parsePolkitPolicy(polkitTestPolicy)
	require.NoError(t, err)
	require.Len(t, actions, 2)

	systemd := actions[0]
	assert.Equal(t, "org.freedesktop.systemd1.manage-units", systemd.ID)
	assert.Equal(t, "auth_admin", systemd.AllowAny)
	assert.Equal(t, "auth_admin", systemd.AllowInactive)
	assert.Equal(t, "auth_admin_keep", systemd.AllowActive)

	// the untranslated text wins over any xml:lang variant
	assert.Equal(t, "Manage system services or other units", systemd.Description)
	assert.Equal(t, "Authentication is required to manage system services.", systemd.Message)

	// vendor metadata is inherited from the enclosing policyconfig
	assert.Equal(t, "The systemd Project", systemd.Vendor)
	assert.Equal(t, "https://systemd.io", systemd.VendorURL)
	assert.Equal(t, "system", systemd.IconName)

	assert.Equal(t, map[string]string{
		"org.freedesktop.policykit.imply": "org.freedesktop.systemd1.reload-daemon",
		"org.freedesktop.policykit.owner": "unix-user:root",
	}, systemd.Annotations)

	open := actions[1]
	assert.Equal(t, "org.example.wide-open", open.ID)
	assert.Equal(t, "yes", open.AllowAny)
	// an action-level vendor overrides the policyconfig vendor, and the url
	// still falls back
	assert.Equal(t, "Example Corp", open.Vendor)
	assert.Equal(t, "https://systemd.io", open.VendorURL)
	assert.Empty(t, open.Annotations)
}

func TestParsePolkitPolicy_MalformedXML(t *testing.T) {
	_, err := parsePolkitPolicy("<policyconfig><action id=\"a.b\">")
	require.Error(t, err)
}

func TestParsePolkitPolicy_ActionWithoutID(t *testing.T) {
	actions, err := parsePolkitPolicy(`<policyconfig>
  <action><description>no id</description></action>
  <action id="org.example.real"><description>real</description></action>
</policyconfig>`)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "org.example.real", actions[0].ID)
}

const polkitTestPkla = `# leading comment
Identity=orphan:ignored

[Allow mounting for wheel]
Identity=unix-group:wheel;unix-user:alice;
Action=org.freedesktop.udisks2.filesystem-mount;org.freedesktop.udisks2.*
ResultAny=no
ResultInactive=auth_self
ResultActive=yes

[Wide open]
Identity=unix-group:users
Action=org.freedesktop.packagekit.*
ResultAny = yes

[Third section]
Identity=unix-user:bob
Action=org.example.third
ResultActive=auth_admin
`

func TestParsePolkitPkla(t *testing.T) {
	rules := parsePolkitPkla(polkitTestPkla)
	// three sections are enough to force the backing slice to grow, which is
	// where a section captured by pointer would lose its keys
	require.Len(t, rules, 3)

	assert.Equal(t, "Allow mounting for wheel", rules[0].Name)
	assert.Equal(t, []string{"unix-group:wheel", "unix-user:alice"}, rules[0].Identities)
	assert.Equal(t, []string{
		"org.freedesktop.udisks2.filesystem-mount",
		"org.freedesktop.udisks2.*",
	}, rules[0].Actions)
	assert.Equal(t, "no", rules[0].ResultAny)
	assert.Equal(t, "auth_self", rules[0].ResultInactive)
	assert.Equal(t, "yes", rules[0].ResultActive)

	assert.Equal(t, "Wide open", rules[1].Name)
	assert.Equal(t, []string{"unix-group:users"}, rules[1].Identities)
	// whitespace around the separator is tolerated
	assert.Equal(t, "yes", rules[1].ResultAny)
	assert.Empty(t, rules[1].ResultActive)

	assert.Equal(t, "Third section", rules[2].Name)
	assert.Equal(t, []string{"unix-user:bob"}, rules[2].Identities)
	assert.Equal(t, "auth_admin", rules[2].ResultActive)
}

func TestParsePolkitPkla_Empty(t *testing.T) {
	assert.Empty(t, parsePolkitPkla(""))
	assert.Empty(t, parsePolkitPkla("# only a comment\n"))
}

const polkitTestRule = `// this file used to grant org.example.commented-out to everyone
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
    /* org.example.block-comment stays out of the results */
    if (action.id.startsWith("org.freedesktop.udisks2.")) {
        return polkit.Result.AUTH_ADMIN_KEEP;
    }
    polkit.log("see https://example.com/docs for details");
    return polkit.Result.NOT_HANDLED;
});
`

func TestPolkitRuleFactsFrom(t *testing.T) {
	facts := polkitRuleFactsFrom(polkitTestRule)

	assert.False(t, facts.AdminRule)

	// the identifier in the line comment and the one in the block comment are
	// both excluded; the prefix used with startsWith is kept
	assert.Equal(t, []string{
		"org.freedesktop.systemd1.manage-units",
		"org.freedesktop.udisks2.",
	}, facts.ActionIDs)

	assert.Equal(t, []string{"AUTH_ADMIN_KEEP", "NOT_HANDLED", "YES"}, facts.Results)
}

func TestPolkitRuleFactsFrom_AdminRule(t *testing.T) {
	facts := polkitRuleFactsFrom(`polkit.addAdminRule(function(action, subject) {
    return ["unix-group:admin"];
});
`)

	assert.True(t, facts.AdminRule)
	// an identity is not an action identifier
	assert.Empty(t, facts.ActionIDs)
	assert.Empty(t, facts.Results)
}

func TestPolkitRuleFactsFrom_CommentedResultIsNotReported(t *testing.T) {
	facts := polkitRuleFactsFrom(`polkit.addRule(function(action, subject) {
    // return polkit.Result.YES;
    return polkit.Result.NO;
});
`)

	assert.Equal(t, []string{"NO"}, facts.Results)
}

func TestPolkitRuleFactsFrom_UrlInStringIsNotAComment(t *testing.T) {
	// the "//" inside the string must not swallow the rest of the line
	facts := polkitRuleFactsFrom(`var doc = "https://example.com/x"; return polkit.Result.YES;`)

	assert.Equal(t, []string{"YES"}, facts.Results)
}

func TestPolkitRuleFactsFrom_TemplateLiteral(t *testing.T) {
	facts := polkitRuleFactsFrom("polkit.log(`org.example.tpl`); return polkit.Result.NO;")

	assert.Equal(t, []string{"org.example.tpl"}, facts.ActionIDs)
	assert.Equal(t, []string{"NO"}, facts.Results)
}

func TestPolkitRuleFactsFrom_TemplateLiteralInterpolation(t *testing.T) {
	// an interpolation is captured as part of the literal, so the call inside it
	// is not read as code; the surrounding statements still are
	facts := polkitRuleFactsFrom("polkit.log(`action: ${describe(polkit.Result.YES)}`); return polkit.Result.NO;")

	assert.Equal(t, []string{"NO"}, facts.Results)
}

func TestPolkitRuleFactsFrom_EscapedQuoteInLiteral(t *testing.T) {
	facts := polkitRuleFactsFrom(`var a = "he said \"hi\""; var b = "org.example.after";`)

	assert.Equal(t, []string{"org.example.after"}, facts.ActionIDs)
}

func TestPolkitRuleFactsFrom_UnterminatedConstructs(t *testing.T) {
	// a truncated file must not hang or panic
	assert.NotPanics(t, func() {
		polkitRuleFactsFrom(`var a = "org.example.open`)
		polkitRuleFactsFrom(`/* never closed`)
		polkitRuleFactsFrom(`// trailing`)
	})
}

func TestPolkitRuleFactsFrom_RejectsNonActionLiterals(t *testing.T) {
	facts := polkitRuleFactsFrom(`var x = ["/usr/bin/pkexec", "1.2.3", "unix-group:users", "wheel", "en_US.UTF-8"];`)

	assert.Empty(t, facts.ActionIDs)
}

func TestOrderPolkitRuleFiles(t *testing.T) {
	ordered := orderPolkitRuleFiles([][]string{
		{"/etc/polkit-1/rules.d/49-custom.rules", "/etc/polkit-1/rules.d/50-default.rules"},
		{},
		{"/usr/local/share/polkit-1/rules.d/60-local.rules"},
		{"/usr/share/polkit-1/rules.d/50-default.rules", "/usr/share/polkit-1/rules.d/70-vendor.rules"},
	})

	require.Len(t, ordered, 4)

	// lexicographic by file name, and the /etc copy of 50-default shadows the
	// one shipped under /usr/share
	assert.Equal(t, polkitRuleFile{Path: "/etc/polkit-1/rules.d/49-custom.rules", Order: 0}, ordered[0])
	assert.Equal(t, polkitRuleFile{Path: "/etc/polkit-1/rules.d/50-default.rules", Order: 1}, ordered[1])
	assert.Equal(t, polkitRuleFile{Path: "/usr/local/share/polkit-1/rules.d/60-local.rules", Order: 2}, ordered[2])
	assert.Equal(t, polkitRuleFile{Path: "/usr/share/polkit-1/rules.d/70-vendor.rules", Order: 3}, ordered[3])
}

func TestOrderPolkitRuleFiles_Empty(t *testing.T) {
	assert.Empty(t, orderPolkitRuleFiles(nil))
	assert.Empty(t, orderPolkitRuleFiles([][]string{{}, {}}))
}

func TestParsePolkitLocalAuthorityConf(t *testing.T) {
	identities := parsePolkitLocalAuthorityConf(`[Configuration]
# the last assignment wins
AdminIdentities=unix-group:wheel
AdminIdentities=unix-group:sudo;unix-user:root
`)

	assert.Equal(t, []string{"unix-group:sudo", "unix-user:root"}, identities)
}

func TestParsePolkitLocalAuthorityConf_Unset(t *testing.T) {
	assert.Nil(t, parsePolkitLocalAuthorityConf("[Configuration]\n"))
	assert.Nil(t, parsePolkitLocalAuthorityConf(""))
}

func TestParsePolkitVersion(t *testing.T) {
	tests := []struct {
		title    string
		out      string
		expected string
	}{
		{"legacy release", "pkaction version 0.105\n", "0.105"},
		{"current release", "pkaction version 124", "124"},
		{"extra output lines", "pkaction version 0.116\nsomething else\n", "0.116"},
		{"empty", "", ""},
		{"no version present", "command not found\n", ""},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			assert.Equal(t, test.expected, parsePolkitVersion(test.out))
		})
	}
}

// An excerpt of the generated /etc/polkit-1/rules.d/90-default-privs.rules on
// SLES 16 and openSUSE Leap 16: results come from a lookup table of strings
const suseDefaultPrivsRules = `/**********************************************\
*              DO NOT EDIT                     *
\**********************************************/

polkit.addRule(function(action, subject) {
	// set to true for debugging
	var debug = false;
        rules = { 
		'com.endlessm.ParentalControls.AccountInfo.ChangeAny':
			[ 'auth_admin_keep', 'auth_admin_keep', 'auth_admin_keep' ],
		'com.endlessm.ParentalControls.AccountInfo.ReadAny':
			[ 'yes', 'yes', 'yes' ],
		'com.feralinteractive.GameMode.cpu-helper':
			[ 'no', 'no', 'no' ],
		'zypp.gui.pkexec.run':
			[ 'auth_admin', 'auth_admin', 'auth_admin_keep' ],
        };
        var i = 0;
        if (rules[action.id]) {
		if (debug)
			polkit.log(action.id + " => " + rules[action.id][i]);
                return rules[action.id][i];
        } else {
		if (debug)
			polkit.log(action.id + " => no override found");
	}
});
`

func TestPolkitRuleFactsFrom_StringResults(t *testing.T) {
	facts := polkitRuleFactsFrom(suseDefaultPrivsRules)

	assert.Equal(t, []string{"AUTH_ADMIN", "AUTH_ADMIN_KEEP", "NO", "YES"}, facts.Results)
	assert.Contains(t, facts.ActionIDs, "zypp.gui.pkexec.run")
}

func TestPolkitRuleFactsFrom_StringResultMatchesExactly(t *testing.T) {
	// polkit matches result strings case-sensitively, and a word inside a
	// longer string or in a comment is not a result
	facts := polkitRuleFactsFrom(`polkit.addRule(function(action, subject) {
    // return "yes";
    polkit.log("yes, handled");
    if (action.id == "org.example.YES") { return "YES"; }
    return "not_handled";
});
`)

	assert.Empty(t, facts.Results)
}
