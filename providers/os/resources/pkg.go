// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"sort"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// pkgReposDirs is REPOS_DIR as libpkg defaults it: /etc/pkg/ first, then
// PREFIX/etc/pkg/repos/. Files are read in that order and a repository
// declared in more than one of them is merged across them.
var pkgReposDirs = []string{"/etc/pkg", "/usr/local/etc/pkg/repos"}

// pkgRepo is one repository after every configuration file that names it
// has been applied.
type pkgRepo struct {
	Name          string
	URL           string
	Enabled       bool
	MirrorType    string
	SignatureType string
	Fingerprints  string
	Pubkey        string
	Priority      int64
	SourceFile    *mqlFile
}

// pkgValue is one scalar as the file spelled it. Quoting is kept because
// pkg rejects a block whose priority is not an integer, and a quoted "5"
// is a string to the UCL parser rather than a number.
type pkgValue struct {
	Raw    string
	Quoted bool
}

// pkgRepoBlock is a single `name: { ... }` block. Only the keys the block
// actually sets are present: pkg inherits most unset keys from an earlier
// definition of the same repository, so presence has to be tracked apart
// from the value.
type pkgRepoBlock struct {
	Name string
	Keys map[string]pkgValue
}

type mqlPkgRepoInternal struct {
	fingerprintsPath string
	pubkeyPath       string
}

func (p *mqlPkg) id() (string, error) {
	return "pkg", nil
}

func (p *mqlPkg) repos() ([]any, error) {
	files, err := p.configFiles()
	if err != nil {
		return nil, err
	}

	repos := map[string]*pkgRepo{}
	order := []string{}
	for _, f := range files {
		content, err := fileContentOrEmpty(f)
		if err != nil {
			return nil, err
		}
		for _, block := range parsePkgRepoBlocks(content) {
			mergePkgRepoBlock(repos, &order, block, f)
		}
	}

	res := make([]any, 0, len(order))
	for _, name := range order {
		repo, err := p.newRepo(repos[name])
		if err != nil {
			return nil, err
		}
		res = append(res, repo)
	}
	return res, nil
}

// configFiles collects every file pkg would read, in the order pkg reads
// them. Order decides the outcome: a repository declared twice takes the
// later file's values, so the directories are walked in REPOS_DIR order
// and each directory's files are sorted the way libpkg's scandir sorts
// them. files.find promises no ordering of its own.
func (p *mqlPkg) configFiles() ([]*mqlFile, error) {
	var out []*mqlFile

	for _, dir := range pkgReposDirs {
		o, err := CreateResource(p.MqlRuntime, "files.find", map[string]*llx.RawData{
			"from":  llx.StringData(dir),
			"type":  llx.StringData("file"),
			"depth": llx.IntData(1),
		})
		if err != nil {
			return nil, err
		}

		list := o.(*mqlFilesFind).GetList()
		if list.Error != nil {
			// a missing directory is the normal case anywhere but FreeBSD
			continue
		}

		var found []*mqlFile
		for _, item := range list.Data {
			mf, ok := item.(*mqlFile)
			if !ok {
				continue
			}
			if !isPkgConfigFile(mf.Path.Data) {
				continue
			}
			found = append(found, mf)
		}
		sort.Slice(found, func(i, j int) bool {
			return path.Base(found[i].Path.Data) < path.Base(found[j].Path.Data)
		})
		out = append(out, found...)
	}

	return out, nil
}

// isPkgConfigFile reports whether pkg would read this file. libpkg's
// configfile() filter skips dotfiles and requires a name longer than
// ".conf" itself, so a file named exactly ".conf" is ignored where
// "a.conf" is read.
func isPkgConfigFile(p string) bool {
	base := path.Base(p)
	if strings.HasPrefix(base, ".") {
		return false
	}
	return len(base) > len(".conf") && strings.HasSuffix(base, ".conf")
}

func (p *mqlPkg) newRepo(repo *pkgRepo) (*mqlPkgRepo, error) {
	args := map[string]*llx.RawData{
		"__id":          llx.StringData(repo.Name),
		"name":          llx.StringData(repo.Name),
		"url":           llx.StringData(repo.URL),
		"enabled":       llx.BoolData(repo.Enabled),
		"mirrorType":    llx.StringData(repo.MirrorType),
		"signatureType": llx.StringData(repo.SignatureType),
		"priority":      llx.IntData(repo.Priority),
		"file":          llx.ResourceData(repo.SourceFile, "file"),
	}

	r, err := CreateResource(p.MqlRuntime, "pkg.repo", args)
	if err != nil {
		return nil, err
	}

	res := r.(*mqlPkgRepo)
	res.fingerprintsPath = repo.Fingerprints
	res.pubkeyPath = repo.Pubkey
	return res, nil
}

func (r *mqlPkgRepo) fingerprints() (*mqlFile, error) {
	if r.fingerprintsPath == "" {
		r.Fingerprints.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newFile(r.MqlRuntime, r.fingerprintsPath)
}

func (r *mqlPkgRepo) pubkey() (*mqlFile, error) {
	if r.pubkeyPath == "" {
		r.Pubkey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newFile(r.MqlRuntime, r.pubkeyPath)
}

// mergePkgRepoBlock applies one block to the repository set the way
// libpkg's add_repo does. The rules are not uniform. url, enabled,
// signature_type, fingerprints, pubkey and mirror_type are inherited from
// an earlier definition when the block leaves them out, but priority is
// not: libpkg starts every block at priority 0 and assigns it
// unconditionally, so an override that does not restate priority resets it
// to 0. An unusable value does not fall back to a default either, it drops
// the whole block, leaving the repository at its previous definition.
func mergePkgRepoBlock(repos map[string]*pkgRepo, order *[]string, block pkgRepoBlock, file *mqlFile) {
	existing := repos[block.Name]

	url, hasURL := block.Keys["url"]
	if existing == nil && !hasURL {
		// a block that neither carries a url nor overrides a repository
		// already declared is discarded, so pkg never sees it
		return
	}

	signatureType := ""
	if v, ok := block.Keys["signature_type"]; ok {
		switch strings.ToLower(v.Raw) {
		case "pubkey", "fingerprints", "none":
			signatureType = strings.ToLower(v.Raw)
		default:
			// an unknown scheme, `fingerprint` for `fingerprints` say,
			// takes the whole block with it
			return
		}
	}

	var priority int64
	if v, ok := block.Keys["priority"]; ok {
		n, err := strconv.ParseInt(strings.TrimSpace(v.Raw), 10, 64)
		if err != nil || v.Quoted {
			return
		}
		priority = n
	}

	repo := existing
	if repo == nil {
		// the defaults pkg_repo_new starts a repository at
		repo = &pkgRepo{
			Name:          block.Name,
			SignatureType: "none",
			MirrorType:    "none",
			Enabled:       true,
		}
		repos[block.Name] = repo
		*order = append(*order, block.Name)
	}

	if hasURL {
		repo.URL = url.Raw
	}
	if signatureType != "" {
		repo.SignatureType = signatureType
	}
	if v, ok := block.Keys["fingerprints"]; ok {
		repo.Fingerprints = v.Raw
	}
	if v, ok := block.Keys["pubkey"]; ok {
		repo.Pubkey = v.Raw
	}
	if v, ok := block.Keys["mirror_type"]; ok {
		switch strings.ToLower(v.Raw) {
		case "srv":
			repo.MirrorType = "srv"
		case "http":
			repo.MirrorType = "http"
		default:
			repo.MirrorType = "none"
		}
	}
	if v, ok := block.Keys["enabled"]; ok {
		repo.Enabled = pkgBool(v.Raw)
	}
	repo.Priority = priority
	repo.SourceFile = file
}

// pkgBool reads a UCL boolean. libpkg puts no type check on `enabled`, so
// the value reaches ucl_object_toboolean, where a number counts as true
// when it is not zero.
func pkgBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "no", "false", "off", "0":
		return false
	}
	return true
}

// parsePkgRepoBlocks extracts every top-level `name: { ... }` block. The
// files are UCL, but the subset FreeBSD documents and ships is a flat list
// of named objects holding scalars, so this reads that shape instead of
// carrying a full UCL parser. Nested objects, a repository's `env` among
// them, are stepped over by brace counting.
func parsePkgRepoBlocks(content string) []pkgRepoBlock {
	content = stripPkgComments(content)
	res := []pkgRepoBlock{}

	i := 0
	for i < len(content) {
		for i < len(content) && isPkgSeparator(content[i]) {
			i++
		}
		if i >= len(content) {
			break
		}

		name, next, ok := readPkgToken(content, i)
		if !ok {
			i++
			continue
		}
		i = next

		for i < len(content) && isPkgSpace(content[i]) {
			i++
		}
		if i < len(content) && (content[i] == ':' || content[i] == '=') {
			i++
			for i < len(content) && isPkgSpace(content[i]) {
				i++
			}
		}

		if i >= len(content) || content[i] != '{' {
			// not a repository block; the name token was consumed, so the
			// scan still makes progress
			continue
		}

		body, next, ok := readPkgBraceBlock(content, i)
		if !ok {
			// unterminated block: everything after it is unreadable
			break
		}
		i = next

		res = append(res, pkgRepoBlock{Name: name, Keys: parsePkgBlockKeys(body)})
	}

	return res
}

// parsePkgBlockKeys reads the scalar key/value pairs of one block body.
// Keys are lowercased because libpkg compares them case-insensitively.
func parsePkgBlockKeys(body string) map[string]pkgValue {
	keys := map[string]pkgValue{}

	i := 0
	for i < len(body) {
		for i < len(body) && isPkgSeparator(body[i]) {
			i++
		}
		if i >= len(body) {
			break
		}

		key, next, ok := readPkgToken(body, i)
		if !ok {
			i++
			continue
		}
		i = next

		for i < len(body) && isPkgSpace(body[i]) {
			i++
		}
		if i < len(body) && (body[i] == ':' || body[i] == '=') {
			i++
			for i < len(body) && isPkgSpace(body[i]) {
				i++
			}
		}
		if i >= len(body) {
			break
		}

		// step over a nested value; none of the keys read here is one
		if body[i] == '{' {
			_, next, ok := readPkgBraceBlock(body, i)
			if !ok {
				break
			}
			i = next
			continue
		}
		if body[i] == '[' {
			next, ok := skipPkgArray(body, i)
			if !ok {
				break
			}
			i = next
			continue
		}

		quoted := body[i] == '"' || body[i] == '\''
		val, next, ok := readPkgToken(body, i)
		if !ok {
			i++
			continue
		}
		i = next

		keys[strings.ToLower(key)] = pkgValue{Raw: val, Quoted: quoted}
	}

	return keys
}

// stripPkgComments removes UCL comments. Quoted strings are copied through
// untouched, so a `#` inside a url stays part of the url.
func stripPkgComments(content string) string {
	var b strings.Builder
	b.Grow(len(content))

	for i := 0; i < len(content); {
		c := content[i]
		switch {
		case c == '"' || c == '\'':
			_, next, ok := readPkgToken(content, i)
			if !ok {
				b.WriteByte(c)
				i++
				continue
			}
			b.WriteString(content[i:next])
			i = next

		case c == '#' || (c == '/' && i+1 < len(content) && content[i+1] == '/'):
			for i < len(content) && content[i] != '\n' {
				i++
			}

		case c == '/' && i+1 < len(content) && content[i+1] == '*':
			i += 2
			for i+1 < len(content) && !(content[i] == '*' && content[i+1] == '/') {
				i++
			}
			if i+1 < len(content) {
				i += 2
			} else {
				i = len(content)
			}
			// a block comment separates the tokens around it
			b.WriteByte(' ')

		default:
			b.WriteByte(c)
			i++
		}
	}

	return b.String()
}

// readPkgToken reads one quoted or bare token starting at i and returns it
// along with the index just past it.
func readPkgToken(s string, i int) (string, int, bool) {
	if i >= len(s) {
		return "", i, false
	}

	if s[i] == '"' || s[i] == '\'' {
		quote := s[i]
		i++
		var b strings.Builder
		for i < len(s) {
			if s[i] == '\\' && i+1 < len(s) {
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			if s[i] == quote {
				return b.String(), i + 1, true
			}
			b.WriteByte(s[i])
			i++
		}
		// unterminated quote: take what there is
		return b.String(), i, true
	}

	start := i
	for i < len(s) && !isPkgSpace(s[i]) && !strings.ContainsRune(":={}[],;", rune(s[i])) {
		i++
	}
	if i == start {
		return "", start, false
	}
	return s[start:i], i, true
}

// readPkgBraceBlock returns the body of the brace block starting at i,
// which must be a `{`, and the index just past its closing brace.
func readPkgBraceBlock(s string, i int) (string, int, bool) {
	start := i
	depth := 0

	for i < len(s) {
		switch s[i] {
		case '"', '\'':
			_, next, ok := readPkgToken(s, i)
			if !ok {
				i++
				continue
			}
			i = next
			continue
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start+1 : i], i + 1, true
			}
		}
		i++
	}

	return "", i, false
}

// skipPkgArray returns the index just past the array starting at i.
func skipPkgArray(s string, i int) (int, bool) {
	depth := 0

	for i < len(s) {
		switch s[i] {
		case '"', '\'':
			_, next, ok := readPkgToken(s, i)
			if !ok {
				i++
				continue
			}
			i = next
			continue
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
		i++
	}

	return i, false
}

func isPkgSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func isPkgSeparator(c byte) bool {
	return isPkgSpace(c) || c == ',' || c == ';'
}
