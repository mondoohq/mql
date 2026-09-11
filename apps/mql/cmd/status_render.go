// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"fmt"
	"go.mondoo.com/mql/cli/config"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/muesli/termenv"
	"go.mondoo.com/mql/cli/theme"
	"go.mondoo.com/mql/cli/theme/colors"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/health"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
)

// RenderOptions controls how RenderCli formats the status screen. Color is
// disabled for non-TTY output and in tests so the rendered string is
// deterministic plain text.
type RenderOptions struct {
	Color bool
	Width int
	// Binary is the name of the invoking CLI ("mql" or "cnspec"), used in the
	// command hints so the same renderer tells cnspec users to run
	// "cnspec providers update" rather than "mql ...". Callers derive it from
	// cmd.Root().Name(); an empty value falls back to "mql".
	Binary string
}

// styler applies (or, when disabled, passes through) terminal styling. When
// Color is off it returns the input verbatim, guaranteeing escape-free output
// that tests and pipes can assert on. The palette is captured at construction
// so the semantic helpers don't reach into a global mid-render.
type styler struct {
	on      bool
	profile termenv.Profile
	palette colors.Theme
	binary  string
	width   int
}

// defaultRenderColor reports whether the status screen should be rendered with
// color, based on the detected terminal profile (which already honors NO_COLOR
// and non-TTY output).
func defaultRenderColor() bool {
	return colors.Profile != termenv.Ascii
}

func newStyler(color bool, binary string, width int) styler {
	p := colors.Profile
	if !color {
		p = termenv.Ascii
	}
	if binary == "" {
		binary = "mql"
	}
	// When the width is unknown (non-TTY output, tests) fall back to a standard
	// 80-column budget so long lists still collapse rather than assuming an
	// unbounded terminal.
	if width <= 0 {
		width = 80
	}
	return styler{on: color, profile: p, palette: theme.DefaultTheme.Colors, binary: binary, width: width}
}

func (st styler) fg(c termenv.Color, s string) string {
	if !st.on {
		return s
	}
	return st.profile.String(s).Foreground(c).String()
}

func (st styler) bold(s string) string {
	if !st.on {
		return s
	}
	return st.profile.String(s).Bold().String()
}

// semantic roles mapped onto the theme palette
func (st styler) value(s string) string  { return st.bold(s) }
func (st styler) dim(s string) string    { return st.fg(st.palette.Disabled, s) }
func (st styler) ok(s string) string     { return st.fg(st.palette.Success, s) }
func (st styler) bad(s string) string    { return st.fg(st.palette.Error, s) }
func (st styler) warn(s string) string   { return st.fg(st.palette.Warn, s) }
func (st styler) cmd(s string) string    { return st.fg(st.palette.Command, s) }
func (st styler) accent(s string) string { return st.fg(st.palette.Secondary, s) }

// RenderCli renders the human-facing status screen as a string. It performs no
// I/O and reads no globals: everything it needs is on the Status value, which
// makes it directly unit-testable.
func (s Status) RenderCli(opts RenderOptions) string {
	st := newStyler(opts.Color, opts.Binary, opts.Width)
	var b strings.Builder

	s.renderHealth(&b, st)
	s.renderSystem(&b, st)
	s.renderMql(&b, st)
	s.renderPlatform(&b, st)
	s.renderProviders(&b, st)
	s.renderFooter(&b, st)

	// trim trailing whitespace from every line so framed blank rows ("│") and
	// short rows don't leave ragged trailing spaces
	lines := strings.Split(b.String(), "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(ln, " ")
	}
	return strings.Join(lines, "\n")
}

const ruleWidth = 46

// section writes an open-frame header: "── Title ─────────". There is no right
// border, which sidesteps glyph-width alignment problems entirely.
func (st styler) section(b *strings.Builder, title string) {
	fmt.Fprintf(b, "\n  %s %s %s\n", st.dim("──"), st.value(title), st.dim(strings.Repeat("─", ruleWidth)))
}

// row writes a left-ruled body line: "│  label  value".
func (st styler) row(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "  %s  %s  %s\n", st.dim("│"), st.dim(padRight(label, 9)), value)
}

// rowRaw writes a left-ruled body line without a label column, for tables and
// free-form rows under a section.
func (st styler) rowRaw(b *strings.Builder, value string) {
	fmt.Fprintf(b, "  %s  %s\n", st.dim("│"), value)
}

func (s Status) renderSystem(b *strings.Builder, st styler) {
	st.section(b, "System")

	host := st.value(s.Client.Hostname)
	if s.Client.IP != "" {
		host += " " + st.dim("· "+s.Client.IP)
	}
	st.row(b, "Host", host)

	plat := st.dim("unknown")
	if s.Client.Platform != nil {
		plat = s.Client.Platform.Name + " " + st.value(s.Client.Platform.Version) + " " + st.dim("· "+s.Client.Platform.Arch)
	}
	st.row(b, "Platform", plat)
}

func (s Status) renderMql(b *strings.Builder, st styler) {
	st.section(b, "mql")

	ver := st.value(s.Client.Version)
	if s.updateAvailable() {
		ver = st.dim(s.Client.Version) + "  " + st.accent("→") + "  " + st.warn(s.Client.LatestVersion) +
			"   " + st.warn("⚠ update recommended")
	}
	st.row(b, "Version", ver)
	st.row(b, "API", "v"+s.Client.APIVersion)

	if s.Client.ConfigFile != "" {
		st.row(b, "Config", st.value(s.Client.ConfigFile))
	} else {
		st.row(b, "Config", st.dim("defaults — no config file loaded"))
	}
	st.row(b, "Updates", s.Client.UpdatesURL)
	if s.Client.UpdateChannel != "" && s.Client.UpdateChannel != config.ChannelStable {
		st.row(b, "Channel", st.value(s.Client.UpdateChannel))
	}
}

func (s Status) renderPlatform(b *strings.Builder, st styler) {
	st.section(b, "Mondoo Platform")
	st.row(b, "Endpoint", s.Upstream.API.Endpoint)

	statusStr := st.bad(s.Upstream.API.Status)
	if s.Upstream.API.Status == "SERVING" {
		statusStr = st.ok("SERVING")
	}
	sync := st.ok("✓ in sync")
	if s.Upstream.API.Version != s.Client.APIVersion {
		// A development build reports its API version as "unstable" and is
		// expected to run against any released platform, so it never counts as
		// a mismatch. A client running a newer API version than the server is
		// likewise fine during a staged rollout (the CLI updates ahead of the
		// platform), so only flag a mismatch when the client trails the server
		// (or the versions can't be compared numerically).
		switch {
		case s.Client.APIVersion == "unstable":
			sync = st.ok("✓ dev build")
		case clientAPINewer(s.Client.APIVersion, s.Upstream.API.Version):
			sync = st.ok("✓ client ahead")
		default:
			sync = st.warn("⚠ version mismatch")
		}
	}
	st.row(b, "Status", statusStr+"   "+st.dim("API v"+s.Upstream.API.Version)+" "+sync)
	st.row(b, "Time", s.Upstream.API.Timestamp)

	// The upload endpoint is a separate host from the API above; the row is
	// omitted entirely when no ingest endpoint could be derived, so a
	// self-hosted deployment doesn't get a check it can't pass.
	if s.Ingest != nil {
		st.row(b, "Ingest", ingestRowValue(st, *s.Ingest))
	}

	if s.Client.Registered {
		st.row(b, "Client", st.value(s.Client.Mrn))
		st.row(b, "Account", st.value(s.Client.ServiceAccount))
	} else {
		st.row(b, "Client", st.bad("✗ not registered")+" "+st.dim("—")+" run "+st.cmd(st.binary+" login"))
	}

	if len(s.Upstream.Features) > 0 {
		st.row(b, "Features", st.dim(strings.Join(s.Upstream.Features, ", ")))
	}

	// surface upstream warnings (clock skew, slow round-trip, etc.) as their own
	// highlighted lines so they aren't silently dropped
	for _, w := range s.Upstream.Warnings {
		st.rowRaw(b, st.warn("⚠ "+w))
	}
}

// renderHealth renders the at-a-glance summary: one dot per dimension (Client,
// Platform, Updates) colored by state.
func (s Status) renderHealth(b *strings.Builder, st styler) {
	b.WriteString("\n")

	switch {
	case !s.Client.Registered:
		st.summaryRow(b, st.bad("●"), "Client", st.bad("not registered"), st.bad("✗ action needed"))
	case s.Client.PingPongError != nil:
		st.summaryRow(b, st.bad("●"), "Client", st.value("registered"), st.bad("✗ authentication failed"))
	default:
		st.summaryRow(b, st.ok("●"), "Client", st.value("registered"), st.ok("✓ authenticated"))
	}

	if s.platformHealthy() {
		body := "reachable " + st.dim("·") + " " + st.value("SERVING")
		// A SERVING API with a blocked upload host is not a healthy platform
		// from a scan's point of view: every scan runs and then fails to report.
		if s.ingestBlocked() {
			st.summaryRow(b, st.warn("●"), "Platform", body, st.warn("⚠ ingest unreachable"))
		} else {
			st.summaryRow(b, st.ok("●"), "Platform", body, st.ok("✓ healthy"))
		}
	} else {
		status := s.Upstream.API.Status
		if status == "" {
			status = "unreachable"
		}
		st.summaryRow(b, st.bad("●"), "Platform", st.bad(status), st.bad("✗ unreachable"))
	}

	var parts []string
	if s.updateAvailable() {
		parts = append(parts, st.binary+" "+st.dim(s.Client.Version)+" "+st.accent("→")+" "+st.warn(s.Client.LatestVersion))
	}
	if n := s.outdatedCount(); n > 0 {
		parts = append(parts, st.warn(fmt.Sprintf("%d providers outdated", n)))
	}
	if len(parts) == 0 {
		st.summaryRow(b, st.ok("●"), "Updates", st.ok("up to date"), "")
	} else {
		st.summaryRow(b, st.warn("●"), "Updates", strings.Join(parts, " "+st.dim("·")+" "), "")
	}
}

func (st styler) summaryRow(b *strings.Builder, dot, label, body, trailing string) {
	fmt.Fprintf(b, "  %s %s  %s", dot, st.value(padRight(label, 9)), body)
	if trailing != "" {
		fmt.Fprintf(b, "   %s", trailing)
	}
	b.WriteString("\n")
}

func (s Status) platformHealthy() bool { return s.Upstream.API.Status == "SERVING" }

// ingestBlocked reports whether the ingest probe ran and the endpoint did not
// answer. A nil Ingest means the check was skipped, which is not a failure.
func (s Status) ingestBlocked() bool {
	return s.Ingest != nil && !s.Ingest.Reachable
}

// ingestRowValue formats the ingest endpoint row. The HTTP status is
// deliberately not shown on the success path: the endpoint answers an
// unauthenticated probe with 404 by design, and printing "404" next to a green
// check reads as a defect rather than as the proof of reachability it is.
func ingestRowValue(st styler, ingest health.IngestStatus) string {
	if ingest.Reachable {
		return ingest.Endpoint + "   " + st.ok("✓ reachable") + " " +
			st.dim("· "+strconv.FormatInt(ingest.LatencyMs, 10)+"ms")
	}

	row := ingest.Endpoint + "   " + st.bad("✗ unreachable")
	if ingest.Reason != "" {
		row += " " + st.dim("· "+ingest.Reason)
	}
	return row
}

// ingestHostPort renders the ingest endpoint as the host:port pair an egress
// rule is written against, falling back to the raw endpoint if it cannot be
// parsed.
func ingestHostPort(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return endpoint
	}
	if port := u.Port(); port != "" {
		return u.Hostname() + ":" + port
	}
	if u.Scheme == "http" {
		return u.Hostname() + ":80"
	}
	return u.Hostname() + ":443"
}

// clientAPINewer reports whether the client's API version is strictly newer
// than the server's. Both are major-version strings (e.g. "13"); if either
// isn't a plain integer (a development "unstable" build, say), we can't prove
// the client is ahead and return false so the caller falls back to warning.
func clientAPINewer(clientVersion, serverVersion string) bool {
	client, err := strconv.Atoi(clientVersion)
	if err != nil {
		return false
	}
	server, err := strconv.Atoi(serverVersion)
	if err != nil {
		return false
	}
	return client > server
}

// updateAvailable reports whether a newer mql release exists. Builds made
// locally from source stamp a "v"-prefixed git-describe version that surfaces
// as an "unstable" API version; they update by rebuilding, so they never nag
// about released versions. Official release binaries carry a bare semver and a
// real API version, so they still get update checks.
func (s Status) updateAvailable() bool {
	if s.Client.APIVersion == "unstable" {
		return false
	}
	return s.Client.LatestVersion != "" &&
		newerAvailable(s.Client.Version, s.Client.LatestVersion)
}

// newerAvailable reports whether latest is a strictly newer release than
// current, compared semantically. The build stamps a "v"-prefixed version
// (e.g. "v13.27.0") while the release feed reports it bare ("13.27.0"), so a
// raw string compare treats identical releases as different; a semver compare
// ignores the prefix. It also means a local build ahead of the latest published
// release is not flagged as outdated. When either version can't be parsed as
// semver (a rolling dev build, say) it falls back to an exact string compare,
// preserving the previous behavior.
func newerAvailable(current, latest string) bool {
	diff, err := semver.Parser{}.Compare(current, latest)
	if err != nil {
		return current != latest
	}
	return diff < 0
}

func (s Status) outdatedCount() int {
	n := 0
	for _, p := range s.Client.Providers {
		if p.Outdated {
			n++
		}
	}
	return n
}

// registryReachable reports whether provider version data was retrieved. When
// the registry is unreachable every provider's Latest is empty, so version
// drift cannot be shown.
func (s Status) registryReachable() bool {
	if len(s.Client.Providers) == 0 {
		return true
	}
	for _, p := range s.Client.Providers {
		if p.Latest != "" {
			return true
		}
	}
	return false
}

// providerTableLimit caps how many outdated providers the drift table lists
// before collapsing the rest into a "+N more" line.
const providerTableLimit = 8

func (s Status) renderProviders(b *strings.Builder, st styler) {
	st.section(b, "Providers")

	total := len(s.Client.Providers)
	outdated := s.outdatedCount()
	current := total - outdated

	if !s.registryReachable() {
		st.rowRaw(b, st.value(strconv.Itoa(total))+" "+st.dim("installed")+"   "+
			st.warn("registry unreachable — provider versions unknown"))
		return
	}

	st.rowRaw(b, st.value(strconv.Itoa(total))+" "+st.dim("installed")+" "+st.dim("·")+" "+
		st.warn(strconv.Itoa(outdated)+" outdated")+" "+st.dim("·")+" "+
		st.ok(strconv.Itoa(current)+" current"))

	if outdated > 0 {
		st.rowRaw(b, "")
		st.rowRaw(b, st.dim(padRight("PROVIDER", 18)+padRight("INSTALLED", 11)+"LATEST"))

		shown := 0
		for _, p := range s.Client.Providers {
			if !p.Outdated {
				continue
			}
			if shown >= providerTableLimit {
				break
			}
			st.rowRaw(b, st.value(padRight(p.Name, 18))+st.dim(padRight(p.Installed, 9))+
				st.accent("→")+"  "+st.warn(p.Latest))
			shown++
		}
		if outdated > providerTableLimit {
			st.rowRaw(b, st.dim(fmt.Sprintf("+ %d more outdated", outdated-providerTableLimit))+" "+
				st.dim("·")+" "+st.cmd(st.binary+" providers list")+st.dim(" to see all"))
		}
	}

	currentNames := make([]string, 0, current)
	for _, p := range s.Client.Providers {
		if !p.Outdated {
			currentNames = append(currentNames, p.Name)
		}
	}
	if len(currentNames) > 0 {
		st.rowRaw(b, "")
		shown, extra := st.fitNames(currentNames)
		line := st.ok("✓ current") + "  " + st.dim(strings.Join(shown, ", "))
		if extra > 0 {
			line += st.dim(fmt.Sprintf(", +%d", extra))
		}
		st.rowRaw(b, line)
	}
}

// fitNames trims a comma-separated provider list to what fits on one terminal
// line, returning the names to show and how many were dropped into the "+N"
// marker. It measures visible width only (the styling escapes don't occupy
// columns) and always keeps at least the first name so the row is never empty.
func (st styler) fitNames(names []string) (shown []string, extra int) {
	// Columns consumed before the first name: the row gutter ("  │  ") plus the
	// "✓ current  " label.
	const prefix = len("  │  ") + len("✓ current  ")
	budget := st.width - prefix

	used := 0
	for i, name := range names {
		add := len(name)
		if i > 0 {
			add += len(", ")
		}
		// Reserve room for a ", +N" marker when names would remain after this one.
		marker := 0
		if remaining := len(names) - i - 1; remaining > 0 {
			marker = len(fmt.Sprintf(", +%d", remaining))
		}
		if i > 0 && used+add+marker > budget {
			return names[:i], len(names) - i
		}
		used += add
	}
	return names, 0
}

func (s Status) renderFooter(b *strings.Builder, st styler) {
	// authFailed is the "registered but the platform rejected the credential"
	// case (revoked or expired service account) — distinct from never having
	// registered at all, and remediated by re-registering with a fresh token.
	authFailed := s.Client.Registered && s.Client.PingPongError != nil
	hasError := !s.Client.Registered || s.Client.PingPongError != nil
	actionable := hasError || s.ingestBlocked() || s.updateAvailable() || s.outdatedCount() > 0

	b.WriteString("\n")
	switch {
	case !s.Client.Registered:
		fmt.Fprintf(b, "  %s %s\n", st.bad("✗ not registered"), st.dim("· exit 1 · next steps:"))
	case authFailed:
		fmt.Fprintf(b, "  %s %s\n", st.bad("✗ authentication failed"), st.dim("· exit 1 · next steps:"))
	case !actionable:
		fmt.Fprintf(b, "  %s\n\n", st.ok("✓ all systems healthy"))
		return
	default:
		fmt.Fprintf(b, "  %s\n", st.dim("next steps:"))
	}

	if !s.Client.Registered {
		st.footerStep(b, st.binary+" login", "register this client with Mondoo Platform")
	}
	if authFailed {
		st.footerStep(b, st.binary+" login --token <token>", "re-register with a fresh token from Mondoo Platform")
	}
	// No command fixes a blocked upload host, so the step names the egress rule
	// to open instead. Kept above the update hints: a client that cannot upload
	// is reporting nothing at all, which outranks being a version behind.
	if s.ingestBlocked() {
		st.footerStep(b, "allow egress to "+ingestHostPort(s.Ingest.Endpoint),
			"scan results are uploaded to this endpoint")
	}
	if s.updateAvailable() {
		st.footerStep(b, "visit "+s.Client.UpdatesURL, "upgrade "+s.Client.Version+" → "+s.Client.LatestVersion)
	}
	// With a single outdated provider, point at the targeted install; with
	// several, recommend the bulk `providers update` (no args updates them all)
	// so the user doesn't have to name each one.
	if n := s.outdatedCount(); n == 1 {
		st.footerStep(b, st.binary+" providers install <name>", fmt.Sprintf("update %d outdated providers", n))
	} else if n > 1 {
		st.footerStep(b, st.binary+" providers update", fmt.Sprintf("update %d outdated providers", n))
	}
	b.WriteString("\n")
}

func (st styler) footerStep(b *strings.Builder, command, desc string) {
	fmt.Fprintf(b, "    %s %s    %s\n", st.cmd("→"), st.cmd(padRight(command, 28)), st.dim(desc))
}

// padRight pads s with spaces to a width of n display columns. It counts runes
// rather than bytes so multi-byte content still aligns.
func padRight(s string, n int) string {
	width := utf8.RuneCountInString(s)
	if width >= n {
		return s
	}
	return s + strings.Repeat(" ", n-width)
}
