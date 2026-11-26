# ADR 053: Shared secret identity

## Status

Proposed. The package is implemented in `providers-sdk/v1/secretid`; no
producer calls it yet.

## Context

Several producers find secrets: xgrep in repositories, and cnspec on hosts and
in cloud configuration. For the platform to see one credential as one record,
every producer must compute the same identity from the same value, with the
same canonicalization and the same keyed hash, and none of them may send the
value itself.

The identity is a keyed hash so that a low-entropy value cannot be recovered by
hashing guesses: an unkeyed SHA-256 of a short password is a dictionary lookup.
The key is held per space by the platform and served to the scanners that
upload for that space; this package does not fetch it.

Before this ADR the SDK had packages for inventory, plugins, upstream and vault
(`providers-sdk/v1/`), and no secret identity. xgrep already imports mql, so a
package in mql's root module is reachable from every producer without importing
a provider or a scanner.

## Decision

### 1. One package: `providers-sdk/v1/secretid`

```go
func Canonical(value, secretType, credentialClass string) string
func ID(k *Key, canonical string) (string, error)
func IDs(keys []*Key, canonical string) ([]string, error)
func OccurrenceID(k *Key, ruleID, path string, line int, matchedCode string) (string, error)
func LineHash(k *Key, matchedCode string) (string, error)

func NewKey(keyID string, key []byte) (*Key, error)
func (k *Key) KeyID() string
func (k *Key) Close()

func NewSet(ids ...string) *Set
func (s *Set) Contains(id string) bool
func (s *Set) ContainsAny(ids []string) bool
```

The functions that hash return an error rather than a bare string: a nil key
(`ErrNoKey`), a closed key (`ErrClosed`), an empty canonical value
(`ErrEmptyValue`) and a NUL byte in a composite field (`ErrInvalidInput`) give
no id. An empty string returned in their place could be uploaded as an id, and
an id of the empty value would merge every finding whose value was lost.

### 2. Canonicalization

`Canonical` applies, in order:

1. Strip leading and trailing ASCII whitespace.
2. Strip one matching pair of `"`, `'` or `` ` `` around the value.
3. For secret type `private-key`: remove the `-----BEGIN …-----` and
   `-----END …-----` armor markers, the literal two-character escapes `\n` and
   `\r`, and all ASCII whitespace, leaving the body. A key with LF or CRLF
   line endings, as a JSON-escaped string, or reindented, is one value.
4. For credential class `personal-data`: remove spaces and `-`; for secret type
   `iban`, upper-case ASCII letters. One number written two ways is one value.
5. Nothing else: no other case folding and no Unicode normalization. Tokens are
   case-sensitive bytes.

The armor markers are removed rather than the armor lines because in a
JSON-escaped key the marker and the body share one line joined by a literal
`\n`; removing the marker gives the same body in every form.

The secret type and credential class select steps 3 and 4 and are not hashed,
so a specific rule and a generic rule that match one value give one id.

### 3. Keyed hashes with a domain string per identifier

Every identifier is HMAC-SHA256 under the space key (32 bytes), lowercase hex,
over a domain string, a zero byte, and the fields separated by zero bytes:

| Identifier | Input | Encoded as |
|---|---|---|
| secret id | `xgrep/secret-id/v1` ‖ 0 ‖ canonical value | `v1:` + 64 hex |
| occurrence id | `xgrep/occurrence/v1` ‖ 0 ‖ rule id ‖ 0 ‖ path ‖ 0 ‖ decimal line ‖ 0 ‖ matched code | `v1:` + first 32 hex |
| keyed line hash | `xgrep/line-hash/v1` ‖ 0 ‖ first line of the matched code, trimmed | first 16 hex + `:k1` |

The domain strings make the three identifiers unrelated although they share a
key. They carry the name of the first producer for historical reasons; every
producer uses the same strings, because the strings are part of the hash.

The occurrence id's path is the path relative to the scanned root; backslash
separators become forward slashes, so a Windows scan and a Linux scan of one
file give one id. A rule id or path containing a NUL byte is refused, since
NUL separates the fields. The keyed line hash uses the same primary line as the
unkeyed SARIF line hash (first line, surrounding whitespace trimmed) and
replaces it on uploaded secret findings; its `:k1` suffix tells it apart from
the unkeyed `:1`.

### 4. Versioned, with golden vectors

The secret id and occurrence id start with the scheme version (`v1:`), so ids
of two schemes never compare equal. A change to canonicalization or hashing is
a new version, with new domain strings and a new prefix, never an edit of v1.
`TestGoldenVectors` pins v1 with vectors computed independently of the package
(Python's `hmac` module); a producer written in another language must
reproduce them.

### 5. The key lives in memory only

`NewKey(keyID, bytes)` copies the bytes the platform's key call returns and
requires exactly 32 of them and a non-empty key id. `Key` exports no bytes and
has no `String` method. Every `fmt` verb and `slog` print only
`secretid.Key(<key id>)`; the JSON, text, binary and gob serializers return an
error. `Close` zeroes the bytes, and a closed key computes nothing. A `Key` is
safe for concurrent use.

Go does not guarantee that a copy of the bytes made before `NewKey` is
overwritten; the caller zeroes its own buffer.

### 6. Rotation: one id per key

`IDs(keys, canonical)` returns one id per key in the order given. During a key
rotation window a producer passes the current key and then the previous one,
and uploads both ids, each with its key id (`KeyID`), from one
canonicalization.

### 7. Membership sets

`Set` holds secret ids for membership tests, such as a space's honeytokens.
Ids are compared exactly, version prefix included. An empty id is never a
member. `ContainsAny` takes the ids of one value under several keys.

### 8. One implementation

Every producer calls this package. A producer that cannot, such as an external
tool, uploads no id rather than an id computed another way. The package does no
I/O and no logging, and depends only on the standard library.

## Security implications

- **Threat model.** The key lets its holder test whether a guessed value is a
  given id. The package never logs, prints or serializes the key (decision 5,
  `TestKeyNeverPrinted`), and never stores a value.
- **Data handling.** Values and the key are in process memory only. Nothing is
  written.
- **Authentication and authorization.** Not applicable to a library. Which
  callers receive a space's key is the platform's decision.
- **Supply chain.** Standard library only (`crypto/hmac`, `crypto/sha256`).
- **Residual risk.** A canonicalization bug splits one credential into two
  records or merges two; the canonicalization table test and the golden
  vectors pin v1. Freed memory is not guaranteed to be overwritten by the Go
  runtime, so a core dump of a running process could hold the key.

## Performance implications

- **Expected impact.** One HMAC-SHA256 per identifier per finding, two for a
  secret id during a rotation window; the private-key step adds one regular
  expression pass over the value.
- **Evidence.** Estimate, not measured: HMAC-SHA256 over a short input costs
  on the order of a microsecond.
- **Scale assumptions.** Thousands of secret findings per scan.
- **Regression budget.** Negligible against a scan; no existing code path
  changes.

## Consequences

### Positive

- Every producer computes identical identities from identical values.
- The key cannot reach a log or an output file through this package.

### Negative

- The output is a cross-repository contract: producers upgrade together when a
  version changes, and a v2 re-keys every secret on the platform.

### Follow-up

- Producers (xgrep uploads, honeytoken matching, revalidation and revocation;
  cnspec) call the package once the platform serves the space key.
- A v2 if canonicalization needs another rule.

## Alternatives considered

### Each producer implements it

Rejected: two implementations drift and split one credential into two records,
with nothing to detect it.

### Put it in xgrep

Rejected: cnspec would import a code scanner for a hash function.

### Unkeyed SHA-256

Rejected: a low-entropy value is recovered by hashing guesses.

### Return a bare string from `ID`

Rejected: an empty string on a missing or closed key can be uploaded as an id
without anyone noticing; an error cannot.
