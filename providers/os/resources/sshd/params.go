// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshd

import (
	"strings"

	shellquote "github.com/kballard/go-shellquote"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/utils/sortx"
)

type MatchBlock struct {
	Criteria string
	// Note: we set the value type to any, but it must be a string.
	// This is done due to type limitations in go and MQL's internal processing
	Params  map[string]any
	Context Context
}

type Context struct {
	Path    string
	Range   llx.Range
	curLine int
}

func setParam(m map[string]any, key string, value string) {
	v, ok := m[key]
	if !ok {
		m[key] = value
	} else if isMultiParam[key] {
		m[key] = v.(string) + "," + value
	}
}

type MatchBlocks []*MatchBlock

var isMultiParam = map[string]bool{
	"AllowGroups":   true,
	"AllowUsers":    true,
	"DenyGroups":    true,
	"DenyUsers":     true,
	"ListenAddress": true,
	"Port":          true,
	"AcceptEnv":     true,
	"HostKey":       true,
}

func (m MatchBlocks) Flatten() map[string]any {
	if len(m) == 0 {
		return nil
	}
	if len(m) == 1 {
		return m[0].Params
	}

	// We are using the first block as a starting point for the size.
	// We can't just add the sizes of params across all blocks, because keys
	// may be used across multiple blocks. It is likely that the size will
	// have to grow, but it's the floor and a good starting point.
	res := make(map[string]any, len(m[0].Params))
	matchConditions := []string{}
	for i := range m {
		cur := m[i]

		if cur.Criteria != "" {
			matchConditions = append(matchConditions, cur.Criteria)
		}

		for k, v := range cur.Params {
			setParam(res, k, v.(string))
		}
	}

	// We are adding one flattened key for all match groups. This is
	// more to be informative and consistent, rather than useful.
	// The most useful way to access conditions is to cycle over all match blocks.
	if len(matchConditions) != 0 {
		res["Match"] = strings.Join(matchConditions, ",")
	}

	return res
}

func mergeIncludedBlocks(matchConditions map[string]*MatchBlock, blocks MatchBlocks, curBlock string) {
	for _, block := range blocks {
		if block.Criteria == "" {
			// Default block: merge into the current block
			existing := matchConditions[curBlock]
			if existing == nil {
				existing = &MatchBlock{
					Criteria: curBlock,
					Params:   map[string]any{},
					Context:  block.Context,
				}
				matchConditions[curBlock] = existing
			}
			if existing.Params == nil {
				existing.Params = map[string]any{}
			}
			for k, v := range block.Params {
				if _, ok := existing.Params[k]; !ok {
					existing.Params[k] = v
				}
			}
			continue
		}

		// Match block: always add to global map
		existing, ok := matchConditions[block.Criteria]
		if !ok {
			// Create a new Match block
			existing = &MatchBlock{
				Criteria: block.Criteria,
				Params:   map[string]any{},
				Context:  block.Context,
			}
			matchConditions[block.Criteria] = existing
		}

		if existing.Params == nil {
			existing.Params = map[string]any{}
		}

		for k, v := range block.Params {
			if _, ok := existing.Params[k]; !ok {
				existing.Params[k] = v
			}
		}
	}
}

type (
	fileContentFunc func(string) (content string, err error)
	globExpandFunc  func(string) (paths []string, err error)
)

// ParseBlocks parses a single SSH config file and returns the match blocks.
// The filePath should be the actual file path (not a glob pattern).
// For Include directives with glob patterns, use ParseBlocksWithGlob instead.
func ParseBlocks(filePath string, content string) (MatchBlocks, error) {
	curBlock := &MatchBlock{
		Criteria: "",
		Params:   map[string]any{},
		Context: Context{
			Path:    filePath,
			Range:   llx.NewRange(),
			curLine: 1,
		},
	}
	matchConditions := map[string]*MatchBlock{
		"": curBlock,
	}

	lines := strings.Split(content, "\n")
	for curLineIdx, textLine := range lines {
		l, err := ParseLine([]rune(textLine))
		if err != nil {
			return nil, err
		}

		key := l.key
		if key == "" {
			continue
		}

		// handle lower case entries and use proper ssh camel case
		if sshKey, ok := SSH_Keywords[strings.ToLower(key)]; ok {
			key = sshKey
		}

		if key == "Include" {
			// Include directives are handled by ParseBlocksWithGlob
			// This function only parses single files
			log.Warn().Str("file", filePath).Msg("Include directive found in single-file parser, use ParseBlocksWithGlob instead")
			continue
		}

		if key == "Match" {
			// wrap up context on the previous block
			curBlock.Context.Range = curBlock.Context.Range.AddLineRange(uint32(curBlock.Context.curLine), uint32(curLineIdx))
			curBlock.Context.curLine = curLineIdx

			// This key is stored in the condition of each block and can be accessed there.
			condition := l.args
			if b, ok := matchConditions[condition]; ok {
				curBlock = b
			} else {
				curBlock = &MatchBlock{
					Criteria: condition,
					Params:   map[string]any{},
					Context: Context{
						curLine: curLineIdx + 1,
						Path:    filePath,
						Range:   llx.NewRange(),
					},
				}
				matchConditions[condition] = curBlock
			}
			continue
		}

		setParam(curBlock.Params, key, l.args)
	}

	keys := sortx.Keys(matchConditions)
	res := make([]*MatchBlock, len(keys))
	i := 0
	for _, key := range keys {
		res[i] = matchConditions[key]
		i++
	}

	curBlock.Context.Range = curBlock.Context.Range.AddLineRange(uint32(curBlock.Context.curLine), uint32(len(lines)))

	return res, nil
}

// ParseBlocksWithGlob parses SSH config files, expanding glob patterns in Include directives.
// It expands globs and calls ParseBlocksWithGlobRecursive for each matched file individually,
func ParseBlocksWithGlob(rootPath string, fileContent fileContentFunc, globExpand globExpandFunc) (MatchBlocks, error) {
	// First, expand the root path if it's a glob
	paths, err := globExpand(rootPath)
	if err != nil {
		return nil, err
	}

	// If no paths matched, check if rootPath was a single file (not a glob) or return empty blocks
	if len(paths) == 0 {
		// Check if rootPath contains a glob pattern
		hasGlob := strings.Contains(rootPath, "*") || strings.Contains(rootPath, "?") || strings.Contains(rootPath, "[")
		if !hasGlob {
			_, err := fileContent(rootPath)
			if err != nil {
				return nil, err
			}
		}
		return MatchBlocks{}, nil
	}

	// Parse each file individually and collect all blocks
	// Each file maintains its own context (path, line numbers)
	var allBlocks MatchBlocks

	for i, path := range paths {
		content, err := fileContent(path)
		if err != nil {
			if i == 0 && (len(paths) == 1 || path == rootPath) {
				return nil, err
			}
			log.Warn().Err(err).Str("path", path).Msg("unable to read file")
			continue
		}

		blocks, err := ParseBlocksWithGlobRecursive(path, content, fileContent, globExpand)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("unable to parse file")
			continue
		}

		allBlocks = append(allBlocks, blocks...)
	}

	return allBlocks, nil
}

// ParseBlocksWithGlobRecursive parses a single file and recursively handles Include directives.
// splitIncludeArgs splits an Include directive's arguments into paths.
//
// sshd_config permits a path to be quoted, which is how a path containing
// spaces is written, and some distributions quote unconditionally. Flatcar
// ships exactly one effective line:
//
//	Include "/etc/ssh/sshd_config.d/*.conf"
//
// Splitting on spaces alone left the quote characters inside the pattern, so
// the glob matched nothing, the miss was swallowed by a log.Warn, and the
// entire included configuration was dropped without any error reaching the
// caller. sshd.config.ciphers then returned an empty list, which makes a
// "no weak ciphers" denylist pass vacuously.
//
// Quote-aware splitting also fixes the case quoting exists for: a path that
// contains a space is now one argument rather than two broken ones.
func splitIncludeArgs(args string) []string {
	if fields, err := shellquote.Split(args); err == nil {
		return fields
	}

	// Unbalanced quoting is malformed sshd_config. Fall back to the plain
	// split rather than dropping the directive entirely.
	return strings.Split(args, " ")
}

func ParseBlocksWithGlobRecursive(filePath string, content string, fileContent fileContentFunc, globExpand globExpandFunc) (MatchBlocks, error) {
	curBlock := &MatchBlock{
		Criteria: "",
		Params:   map[string]any{},
		Context: Context{
			Path:    filePath,
			Range:   llx.NewRange(),
			curLine: 1,
		},
	}
	matchConditions := map[string]*MatchBlock{
		"": curBlock,
	}

	lines := strings.Split(content, "\n")
	for curLineIdx, textLine := range lines {
		l, err := ParseLine([]rune(textLine))
		if err != nil {
			return nil, err
		}

		key := l.key
		if key == "" {
			continue
		}

		// handle lower case entries and use proper ssh camel case
		if sshKey, ok := SSH_Keywords[strings.ToLower(key)]; ok {
			key = sshKey
		}

		if key == "Include" {
			includePaths := splitIncludeArgs(l.args)

			for _, includePath := range includePaths {
				// Expand glob pattern if present
				expandedPaths, err := globExpand(includePath)
				if err != nil {
					log.Warn().Err(err).Str("path", includePath).Msg("unable to expand Include directive")
					continue
				}

				// Parse each matched file individually
				for _, expandedPath := range expandedPaths {
					subContent, err := fileContent(expandedPath)
					if err != nil {
						log.Warn().Err(err).Str("path", expandedPath).Msg("unable to read included file")
						continue
					}

					subBlocks, err := ParseBlocksWithGlobRecursive(expandedPath, subContent, fileContent, globExpand)
					if err != nil {
						log.Warn().Err(err).Str("path", expandedPath).Msg("unable to parse included file")
						continue
					}
					mergeIncludedBlocks(matchConditions, subBlocks, curBlock.Criteria)
				}
			}
			continue
		}

		if key == "Match" {
			// wrap up context on the previous block
			curBlock.Context.Range = curBlock.Context.Range.AddLineRange(uint32(curBlock.Context.curLine), uint32(curLineIdx))
			curBlock.Context.curLine = curLineIdx

			// This key is the only that we don't add to any params. It is stored
			// in the condition of each block and can be accessed there.
			condition := l.args
			if b, ok := matchConditions[condition]; ok {
				curBlock = b
			} else {
				curBlock = &MatchBlock{
					Criteria: condition,
					Params:   map[string]any{},
					Context: Context{
						curLine: curLineIdx + 1,
						Path:    filePath,
						Range:   llx.NewRange(),
					},
				}
				matchConditions[condition] = curBlock
			}
			continue
		}

		setParam(curBlock.Params, key, l.args)
	}

	keys := sortx.Keys(matchConditions)
	res := make([]*MatchBlock, len(keys))
	i := 0
	for _, key := range keys {
		res[i] = matchConditions[key]
		i++
	}

	curBlock.Context.Range = curBlock.Context.Range.AddLineRange(uint32(curBlock.Context.curLine), uint32(len(lines)))

	return res, nil
}

var SSH_Keywords = map[string]string{
	"acceptenv":                       "AcceptEnv",
	"addressfamily":                   "AddressFamily",
	"allowagentforwarding":            "AllowAgentForwarding",
	"allowgroups":                     "AllowGroups",
	"allowstreamlocalforwarding":      "AllowStreamLocalForwarding",
	"allowtcpforwarding":              "AllowTcpForwarding",
	"allowusers":                      "AllowUsers",
	"authenticationmethods":           "AuthenticationMethods",
	"authorizedkeyscommand":           "AuthorizedKeysCommand",
	"authorizedkeyscommanduser":       "AuthorizedKeysCommandUser",
	"authorizedkeysfile":              "AuthorizedKeysFile",
	"authorizedprincipalscommand":     "AuthorizedPrincipalsCommand",
	"authorizedprincipalscommanduser": "AuthorizedPrincipalsCommandUser",
	"authorizedprincipalsfile":        "AuthorizedPrincipalsFile",
	"banner":                          "Banner",
	"casignaturealgorithms":           "CASignatureAlgorithms",
	"challengeresponseauthentication": "ChallengeResponseAuthentication",
	"chrootdirectory":                 "ChrootDirectory",
	"ciphers":                         "Ciphers",
	"clientalivecountmax":             "ClientAliveCountMax",
	"clientaliveinterval":             "ClientAliveInterval",
	"compression":                     "Compression",
	"denygroups":                      "DenyGroups",
	"denyusers":                       "DenyUsers",
	"disableforwarding":               "DisableForwarding",
	"exposeauthinfo":                  "ExposeAuthInfo",
	"fingerprinthash":                 "FingerprintHash",
	"forcecommand":                    "ForceCommand",
	"gssapiauthentication":            "GSSAPIAuthentication",
	"gssapicleanupcredentials":        "GSSAPICleanupCredentials",
	"gssapistrictacceptorcheck":       "GSSAPIStrictAcceptorCheck",
	"gatewayports":                    "GatewayPorts",
	"hostcertificate":                 "HostCertificate",
	"hostkey":                         "HostKey",
	"hostkeyagent":                    "HostKeyAgent",
	"hostkeyalgorithms":               "HostKeyAlgorithms",
	"hostbasedacceptedkeytypes":       "HostbasedAcceptedKeyTypes",
	"hostbasedauthentication":         "HostbasedAuthentication",
	"hostbasedusesnamefrompacketonly": "HostbasedUsesNameFromPacketOnly",
	"ipqos":                           "IPQoS",
	"ignorerhosts":                    "IgnoreRhosts",
	"ignoreuserknownhosts":            "IgnoreUserKnownHosts",
	"include":                         "Include",
	"kbdinteractiveauthentication":    "KbdInteractiveAuthentication",
	"kerberosauthentication":          "KerberosAuthentication",
	"kerberosgetafstoken":             "KerberosGetAFSToken",
	"kerberosorlocalpasswd":           "KerberosOrLocalPasswd",
	"kerberosticketcleanup":           "KerberosTicketCleanup",
	"kexalgorithms":                   "KexAlgorithms",
	"listenaddress":                   "ListenAddress",
	"loglevel":                        "LogLevel",
	"logingracetime":                  "LoginGraceTime",
	"macs":                            "MACs",
	"match":                           "Match",
	"maxauthtries":                    "MaxAuthTries",
	"maxsessions":                     "MaxSessions",
	"maxstartups":                     "MaxStartups",
	"passwordauthentication":          "PasswordAuthentication",
	"permitemptypasswords":            "PermitEmptyPasswords",
	"permitlisten":                    "PermitListen",
	"permitopen":                      "PermitOpen",
	"permitrootlogin":                 "PermitRootLogin",
	"permittty":                       "PermitTTY",
	"permittunnel":                    "PermitTunnel",
	"permituserenvironment":           "PermitUserEnvironment",
	"permituserrc":                    "PermitUserRC",
	"pidfile":                         "PidFile",
	"port":                            "Port",
	"printlastlog":                    "PrintLastLog",
	"printmotd":                       "PrintMotd",
	"pubkeyacceptedkeytypes":          "PubkeyAcceptedKeyTypes",
	"pubkeyauthoptions":               "PubkeyAuthOptions",
	"pubkeyauthentication":            "PubkeyAuthentication",
	"rdomain":                         "RDomain",
	"rekeylimit":                      "RekeyLimit",
	"revokedkeys":                     "RevokedKeys",
	"securitykeyprovider":             "SecurityKeyProvider",
	"setenv":                          "SetEnv",
	"streamlocalbindmask":             "StreamLocalBindMask",
	"streamlocalbindunlink":           "StreamLocalBindUnlink",
	"strictmodes":                     "StrictModes",
	"subsystem":                       "Subsystem",
	"syslogfacility":                  "SyslogFacility",
	"tcpkeepalive":                    "TCPKeepAlive",
	"trustedusercakeys":               "TrustedUserCAKeys",
	"usedns":                          "UseDNS",
	"usepam":                          "UsePAM",
	"versionaddendum":                 "VersionAddendum",
	"x11displayoffset":                "X11DisplayOffset",
	"x11forwarding":                   "X11Forwarding",
	"x11uselocalhost":                 "X11UseLocalhost",
	"xauthlocation":                   "XAuthLocation",
}
