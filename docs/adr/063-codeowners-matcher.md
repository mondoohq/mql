# ADR 063: One CODEOWNERS matcher for GitHub and GitLab

## Status

Proposed. Decision 1 is implemented in `providers-sdk/v1/codeowners`.
Decisions 2 and 3 are not implemented yet.

## Context

The github and gitlab providers read CODEOWNERS and expose its rules:
`github.repository.codeowners` with `path`, `exists`, `content` and `rules`
(pattern, owners, line number), and `gitlab.project.codeowners` with sections,
optional sections and approvals. Each provider has its own parser
(`parseCodeowners` in `providers/github/resources/github_security.go` and in
`providers/gitlab/resources/gitlab_governance.go`). Neither answers "who owns
this path": grep found no matcher in the tree. Code scanners that attach owners
to findings need the same answer, and a matcher written in every consumer would
give different owners for the same path.

The two dialects differ in more than sections:

| | GitHub | GitLab |
|---|---|---|
| Pattern without a leading `/`, with a `/` inside (`docs/*`) | relative to the root (gitignore) | at any depth |
| Pattern naming a directory without a trailing `/` (`/apps/github`) | matches everything below | names a file only |
| Final `/**` | everything below | one level, like `*` |
| `docs/*` against `docs/a/b.md` | no match (documented) | no match |
| Which rule decides | the last matching rule | the last matching rule of each section; sections combined |
| `!pattern` | not supported | exclusion within its section; once excluded, a later rule of the section cannot include the path again |
| `[a-z]`, `\` escapes | not supported | fnmatch classes and escapes; `\ ` keeps a space in a path |
| Inline `#` comment | ends the owners | unsupported; words that are not owner references are ignored |
| Invalid line | skipped | malformed owners ignored; an unparsable section header ignored and its rules kept in the previous section |

Sources: GitHub's "About code owners" page; GitLab's "Syntax of CODEOWNERS
file" and "Advanced CODEOWNERS configuration" pages and, where those are
silent, GitLab's parser (`ee/lib/gitlab/code_owners/file.rb`,
`pattern_index.rb`, `section_parser.rb`), all read on 2026-11-26. GitHub
publishes no implementation, so the GitHub rows are what its documentation
states plus gitignore semantics, which it names as the base.

## Decision

### 1. A shared package: `providers-sdk/v1/codeowners`

```go
type Dialect int // GitHub, GitLab
type Rule struct {
	Pattern           string
	Owners            []string
	Line              int
	Section           string
	Optional          bool
	ApprovalsRequired int
	Exclusion         bool
}
type Owner struct { Name string; Rule Rule }

func Parse(content string, d Dialect) ([]Rule, error)
func MatchRules(rules []Rule, path string, d Dialect) []Rule
func Match(rules []Rule, path string, d Dialect) []Owner
func Names(owners []Owner) []string
func NewIndex(rules []Rule, d Dialect) *Index // Index.Match, Index.MatchRules
```

The package lives in the root module, so any tool that imports mql uses it
without importing a provider.

- **Each dialect follows its forge** (table above). GitLab patterns are
  normalized and matched the way GitLab's parser does it: `*` becomes `/**/*`,
  a pattern without a leading `/` gets `/**/`, a trailing `/` gets `**/*`, and
  matching is fnmatch with `FNM_PATHNAME` and `FNM_DOTMATCH`. A later GitLab
  rule with the same normalized pattern in the same section replaces the
  earlier one, as in GitLab.
- **`Parse` returns the rules the forge applies and an error listing the lines
  it reports.** For GitHub those lines are skipped (unsupported syntax, an
  owner that is not `@user`, `@org/team` or an email). For GitLab the rules
  stay, with malformed owners dropped. A caller that wants no owners from a
  file with errors checks the error; the rules still give the forge's answer.
- **`MatchRules` returns the deciding rules**, not only their owners, because
  a rule without owners still decides a path: GitHub's `/apps/github` with no
  owner leaves that directory unowned after `/apps/ @octocat`.
- **Section optionality is the section's, not the header's.** A GitLab section
  is optional only when every header of that name is `^[...]`, as GitLab
  documents; each rule carries the section's value.
- **`Index`** gives the answers of `Match` and `MatchRules` for many paths
  against one file. It tries a rule only for paths containing its last literal
  segment, or a segment ending in the literal after its last wildcard; other
  rules are always tried.

### 2. Query per path and revision

MQL resource fields take no arguments (only `init` does), so the query is a
resource with an `init`: `github.codeowners.match(owner, repository, path,
ref)` and `gitlab.codeowners.match(projectPath, path, ref)`, each with
`owners`, `file` and `ref`; the GitHub one with the deciding rule's `pattern`
and `lineNumber`, the GitLab one with `rules` (one per matched section). `ref`
defaults to the default branch; given, the file is read at that ref. A refusal
to read the file is an error, never an empty owner list.

### 3. The existing rule resources stay

`github.repository.codeowners.rules` and `gitlab.project.codeowners.rules`
keep their fields and are built by the shared parser.

### 4. No owner inference

A path no rule matches has no owners, never the repository's admins. Callers
decide a fallback and label it as one.

## Security implications

- **Threat model.** CODEOWNERS is repository content: whoever can change it
  changes the answer. Every owner is reported with the rule (pattern and line)
  that assigned it, so a consumer can show where an answer came from.
- **Data handling.** Owners are handles, team slugs and email addresses already
  in the file. Nothing is stored.
- **Authentication and authorization.** None in the package. Decision 2 reads
  the file with the provider's existing repository token.
- **Supply chain.** No new dependency; the pattern matcher is in the package.
- **Residual risk.** Where a vendor documents a pattern ambiguously, the match
  may differ from the vendor's. GitHub publishes no implementation; the
  package skips GitHub lines its documentation says do not work rather than
  guess at them. No case was checked against a live forge; the tests reproduce
  the vendors' documented examples.

## Performance implications

- **Expected impact.** `Match` is linear in the number of rules per path.
  `NewIndex` brings 20,000 paths against 5,000 rules to about 22 ms (GitHub)
  and 27 ms (GitLab) on a 4 vCPU Linux container (`BenchmarkIndexMatch`,
  synthetic file); the same GitLab file without the index takes about 475 ms
  for 1,000 paths.
- **Evidence.** Measured with the package benchmarks; the inputs are
  synthetic.
- **Scale assumptions.** CODEOWNERS files are usually under 1,000 rules;
  callers may cap them.
- **Regression budget.** None on existing queries; the package is new.

## Consequences

### Positive

- One answer to "who owns this path" in every tool that uses mql, with the
  rule that gave it.

### Negative

- The matcher must follow two vendors' pattern rules as they change, and the
  GitHub half rests on documentation rather than an implementation.

### Follow-up

- Decisions 2 and 3 in the github and gitlab providers.
- Bitbucket and Azure DevOps dialects once those providers read CODEOWNERS.

## Alternatives considered

### Match in each consumer

Rejected: divergent owners for the same path, which is the problem this
package exists to remove.

### Owners from blame

Rejected: the last author is not the owner, and blame needs the full history.

### A third-party Go CODEOWNERS library

Rejected: GitLab's sections, exclusions and pattern normalization are specific
to GitLab and would be written here in any case, and the GitHub half is small.
No library was evaluated in depth; a new dependency would also carry the supply
chain cost the package avoids.

### Return only owners, not rules

Rejected: a rule without owners decides a path as much as one with owners, and
consumers need the line to cite.
