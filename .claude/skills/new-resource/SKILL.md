---
name: new-resource
description: Add or change a resource in an existing mql provider — schema, codegen, implementation, tests, and verification against a real target. Use when the user wants to add a resource or fields to a provider (e.g. "add a bind9 resource", "expose the tomcat connectors", "add a resource for named.conf", "model the postfix config"), or when a resource returns null, empty, or wrong values and the cause is the schema rather than the API call.
argument-hint: "<provider>/<resource> (e.g. os/bind9, aws/aws.ec2.instance)"
---

# Add a resource to an mql provider

**CLAUDE.md is the rulebook** — doc-comment format, the typed-reference gate, `CreateResource` vs `NewResource`, `.lr.versions`, the sub-resource bar. Read it and follow it. This skill is the part that rulebooks do not carry: the traps that bite *even when you know the rule*, the commands that catch them mechanically, and the verification that proves the resource against a real target rather than against your reading of it.

The Go shapes behind the rules — `CreateResource`/`NewResource`/`init`, `Internal` structs and `securityGroupIdHandler`, null singular accessors, lazy detail fetches, the `command` resource, discovery filters, pagination — are in [references/implementation-patterns.md](references/implementation-patterns.md). Open it once the shape is decided (step 2) and you start writing Go.

Work through it in order. Every step ends in something you can run.

## 1. Ground the schema in a real artifact before writing it

Never design from documentation alone. Get the real thing first:

```bash
docker run -d --name src ubuntu:24.04 sleep 3600
docker exec src sh -c 'apt-get update -qq && apt-get install -y -qq <package>'
docker exec src sh -c 'cat /etc/<config>; ls /etc/<dir>/'
```

Read the distribution's actual layout. Debian splits configuration across fragments that the entry point includes; Red Hat usually does not. A schema designed from upstream docs models a file that no distribution ships.

**Validate every fixture with the format's own tool.** `named-checkconf`, `nginx -t`, `apachectl configtest`, `sshd -T`, `postfix check`. This is not politeness — it is what stops you pinning invented syntax as expected behavior:

> `named-checkconf` rejected two hand-written bind9 fixtures ("all zones must be in views", and a `recursion`/`allow-recursion` conflict). Both would have shipped as tests asserting configurations that BIND refuses to load.

## 2. Decide the shape, then check it against the identity dimensions

Follow CLAUDE.md's sub-resource bar (clear id, or nested typed refs — otherwise flatten). Then answer one more question the rulebook does not ask:

**Along which dimensions can this thing repeat?** Write them down and build `__id` from all of them.

Configuration formats nest, and the same name legitimately appears in two scopes:

| resource | dimensions | id must carry |
|---|---|---|
| `bind9.zone` | view, class, name | all three |
| `bind9.key` | view, name | both — two views may declare the same key name |
| `nginx.conf.server` | serverName, listen | both |

A missed dimension is not a cosmetic bug. `CreateResource` returns the **cached first instance** for a repeated id, so the second declaration silently reports the first one's values:

> `bind9.keys` reported both keys as `hmac-sha256` when the internet-facing view actually used `hmac-md5`. `bind9.keys.none(algorithm == "hmac-md5")` **passed** on a server using MD5 — the failure direction that matters.

Test it directly: two entries with the same name in different scopes, and assert the ids are distinct.

### Three design decisions that decide whether the resource can be trusted

**One bad record must not blind the collection.** When a resource returns many independently-meaningful records, a single unparseable one must not take the set down with it — and skipping it silently is just as wrong, because a shorter list satisfies every assertion made about it. Skip, and expose a count:

> `java.keystore` handed a whole trust store to the certificate parser. Red Hat's store has **one** certificate out of 133 with a negative serial — legal when issued in 2003, rejected by Go now — and the store reported **nothing at all**. One twenty-year-old CA blinded every check. Skipping it and counting it in `unreadableCertificates` turned that into 132 readable certificates, 54 of them SHA-1 signed and 18 expired: all previously invisible.

Applies to any collection assembled from records that fail independently — certificates, log entries, package databases, zone records.

**Read the layout out of the artifact instead of lengthening a path list.** A daemon usually knows where its own configuration lives, and often says so in its binary:

```bash
strings /usr/local/apache2/bin/httpd | grep -E '^ -D (HTTPD_ROOT|SERVER_CONFIG_FILE)'
 -D HTTPD_ROOT="/usr/local/apache2"
 -D SERVER_CONFIG_FILE="conf/httpd.conf"
```

> `apache2.conf` tried five packaged paths and found nothing on a source build — `file.path` came back null and *every* check errored. It now reads the compiled-in values, verified identical in shape across a source build, Red Hat and Debian. Packaged paths are still tried first, so a distribution install resolves exactly as before and pays nothing.

Reading the binary rather than running `httpd -V` is the point: it works on an image or a mounted filesystem, where nothing can be executed. The same trick reads a version without a command.

**Check what the credential actually protects before assuming you need one.** A password on a file format may guard integrity rather than confidentiality:

> A JKS keystore encrypts *private keys only*. Its password protects a trailing digest, not the certificates — so a trust store is fully readable without any credential, which is what lets it be read from a container image. A PKCS#12 store is the opposite: its bags sit inside encrypted content.

### Returning a type another provider owns

A resource may return a type from another provider — `network.certificate` is the common one. It goes through the shared-resource bridge, not `CreateResource`:

```go
certs, err := runtime.CreateSharedResource("certificates", map[string]*llx.RawData{
    "pem": llx.StringData(pemBundle),
})
list, err := runtime.GetSharedData("certificates", certs.MqlID(), "list")
return list.Value.([]any), nil
```

Declared in the `.lr` as `[]network.certificate(content, path)` for a list resource, or `certificates() []network.certificate` for a field. `parse.certificates` and `os.rootCertificates` are working examples.

## 3. Traps that bite even though they are documented

Each of these is in CLAUDE.md. Each still gets walked into, because the failure looks like a bug in your Go code rather than a naming rule. Match the fingerprint:

| symptom | cause | fix |
|---|---|---|
| every field of a sub-resource reads `null`, plus `provider returned no data and no error for a field` with an empty `id=` | a field named `x` on a resource named `<parent>.x` — same dotted path, and the field loses | rename the resource, or flatten the block onto the parent |
| `is not a list type` | a list field whose path equals its element resource type | plural field over singular element resource (`zones` → `bind9.zone`) |
| `undefined: mql<Name>Internal` | an `Internal` struct added or removed after codegen | run `./mqlr generate` a second time |
| a generated accessor collides with an internal cache field | both named `directory` | prefix the cache field (`baseDir`, `cachePath`) |
| your change has no effect, and the old behaviour is still there | `make providers/install/<p>` **copies from `dist/`, it does not build** — a failed or skipped build leaves the previous binary in place and install cheerfully ships it | always `make providers/build/<p>` **then** install, and check the `dist/` mtime |
| `go test ./providers/<p>/...` fails in a worktree but passes in your main checkout | a generated mock is untracked and exists only where it was generated (`mock_volumemounter.go`) | not your change — confirm with `git ls-files --error-unmatch <file>` before investigating |
| `license-check` fails with "N file(s) would be updated with new copyright years" | header written as `// Copyright (c) Mondoo, Inc.` | the accepted form carries years: `// Copyright Mondoo, Inc. 2024, 2026` |

**The install trap is worth dwelling on**, because it fails in the most misleading way available:

> Verifying a merged parser fix, the resource still showed the old behaviour. The obvious reading was that the fix did not work, and the next step would have been reporting a phantom regression upstream. The build had silently failed and `install` had copied a pre-fix binary. What caught it was a **control in the same file** — a bare directive and a wrapped one, where the bare one resolved and the wrapped one did not — which isolated the fault to the binary rather than the code.

`strings` on the binary will not settle it: Go concatenates string literals, so even terms you know are present grep to zero. Rebuild, or use a control.

**A named init argument resolves against the resource's fields, not its init parameters.** `init(path? string)` does not make `r(path: "…")` compile. The resource has to *declare* a field of that name:

| resource | `init` | declares `path` | `r(path: "…")` | `r("…")` |
|---|---|---|---|---|
| `file` | `init(path string)` | **yes** | works | works |
| `sshd.config` | `init(path? string)` | no | `does not have a field named path` | works |

The two are otherwise the same shape, so the field is the whole difference. `os.lr` is split almost evenly — **32** resources taking a path declare the field and accept the named form, **41** do not and are positional-only — which means guessing gets it wrong about half the time. `sshd.config`, `mysql.conf`, `mariadb.conf`, `bind9`, `nginx.conf`, `apache2.conf`, `chrony.conf`, `ntp.conf`, `postgresql.conf` and every `parse.*` reach their file through `file()` and declare no `path`; `fstab`, `java.keystore`, `mount.point`, `registrykey` and most `*.packages` declare it and work either way.

It is a property of **each argument**, not of the resource. `parse.ini` declares `delimiter` and not `path`, so the two halves of one init behave differently, and mixing is allowed:

```
parse.ini("/tmp/x.ini")                      # works
parse.ini(path: "/tmp/x.ini")                # does not have a field named path
parse.ini("/tmp/x.ini", delimiter: "=")      # works: positional path, named delimiter
```

Check before writing the doc comment, and run the form you wrote:

```bash
# note the trailing space, not "{": a resource may be declared `name @defaults(...) {`
grep -A20 '^<resource> ' providers/<p>/resources/<p>.lr | grep -E '^\s+path\s+string'
```

If you want the named form on a resource that lacks the field, that is a **schema change, not a doc fix**: declare `path string`, accepting that it then duplicates `file.path`, and only where the duplicate earns its place. Five resources' comments documented a form that could not compile — the cheap correction is the positional one.

## 4. Build and test without clobbering the installed provider

`PROVIDERS_PATH` replaces the provider search path entirely, so a build under test never touches `~/.config/mondoo/providers`:

```bash
make providers/build/<provider>
mkdir -p /tmp/pd/<provider> && cp providers/<provider>/dist/<provider>* /tmp/pd/<provider>/
PROVIDERS_PATH=/tmp/pd mql run <connection> -c "<query>"
```

Two builds in two directories give you an **A/B against `main`**, which is how you show a change is additive:

```bash
PROVIDERS_PATH=/tmp/pd-main mql run docker container c -c "$Q" -j > main.json
PROVIDERS_PATH=/tmp/pd-pr   mql run docker container c -c "$Q" -j > pr.json
cmp -s main.json pr.json && echo IDENTICAL
```

Build the baseline from the **current** `origin/main`. A stale baseline attributes someone else's merged change to your PR — or hides yours.

## 5. Verify against a real target, field by field

**A resource that has never run against a live instance of the thing it models does not ship.** That is the standard, not a preference: the PR stays open until somebody has run it. Automated tests do not prove a resource, they prove the parser — and when the fixture and the implementation were both written from the same vendor documentation, they agree with each other by construction. The suite is green and the resource cannot work.

What that costs when it is skipped is measurable. One live Windows Server run, behind #10064 and #10071, contradicted the documented object model in **five** places. Every one of them was a silent failure — an empty answer or a plausible wrong value, never an error naming its cause:

| what the documentation implied | what the server actually did |
|---|---|
| a collection script is just a script | `Encode` widens it to UTF-16 and base64s it, roughly tripling it, against a command-line cap that **depends on the transport** — 8,191 characters over `cmd.exe` and WinRM, 32,767 (`CreateProcess`) over SSH to Windows `sshd`. Over the limit it is rejected before PowerShell runs, and the non-zero exit reads as *the role is not installed*. Budget ~3,000 source characters to be safe on every transport, and measure rather than assume |
| a list serializes as a JSON array | one payload carried **both** `[…]` and `{"value":[…],"Count":n}`; a plain `[]string` tag decodes the second to empty, reporting "no forwarders" on a server that has two |
| an empty value serializes as `null` | a calculated property yielding nothing serializes as `{}`, which failed the decode of the entire settings payload |
| a rights mask is a `uint32` | `FileSystemRights` is a **signed** 32-bit enum: `[uint32]` on a real ACE throws *"Value was either too large or too small"*, and a real mask arrives as a bare negative decimal |
| a plain schema field gets populated | on a resource created from a path alone they never were — every one returned `null` with *provider returned no data and no error*, while the build and the parser tests stayed green |

The same run also corrected a test expectation that was simply wrong — a fourth principal on a stock system directory that the assertion did not allow for. That test had never executed under the `-run` filter in use at the time, which is exactly how a wrong expectation survives review.

None of these is reachable by reading the code, and four of the five are invisible to a fixture, because a fixture built from the documentation reproduces the documentation.

### The two reasons people skip it, and why neither holds

**"There is no host available."** Usually there is, for a few cents. A cloud fixture — one VM, created for the run and destroyed after it — is the cheap version of this: an Azure Windows Server test host reaches a ready state in about 8 minutes, and a full create-scan-destroy round trip costs roughly $0.01 on spot capacity. That is less than the reviewer time an unverified PR consumes. Build the fixture so that teardown is verified rather than assumed — `az group delete --no-wait` exits 0 the moment the request is *accepted*, which says nothing about whether anything was deleted.

**"The provider is not released yet, and CI installs from the registry."** True, and irrelevant. CI installs from the registry; you do not. Build the provider from your branch and point it at the host:

```bash
make providers/build/<provider>
mkdir -p /tmp/pd/<provider> && cp providers/<provider>/dist/<provider>* /tmp/pd/<provider>/
PROVIDERS_PATH=/tmp/pd mql run ssh <user>@<host> -i <key> -c "<resource>.<field>"
```

The release gate governs what CI can run. It does not govern what you can run before asking for review.

Where a live target genuinely cannot be obtained — hardware nobody has, a licence nobody will buy, a service that cannot be provisioned — the PR **says so in those words**, names precisely which fields are therefore unverified, and stays unmerged. "No live host was available" belongs in the body as a blocker, not as a disclaimer to merge past.

Two states beat one. A field that reads the same before and after you change the setting is either a resource bug or a fixture that never moved the setting, and one state cannot tell those apart. Drive each field to a meaningfully different value and read it in both directions.

Once you have a target, run every new field against it and read the values, then check these four, which are where resources actually fail:

- **The absent case.** On a host without the software, the check must **fail**, never pass vacuously. `mql run docker container <plain-ubuntu> -c '<resource>.<field> == false'` should error or report false. A resource that returns null and a check that reads null as satisfied is worse than no resource.
- **Null over invented values.** A field with no value in the file reports null or a documented zero — not a default you made up. If you *do* report an effective default (BIND recursion is on when unset), say so in the field's doc comment and pick the direction that fails safe.
- **Secrets.** If the format carries key material, sweep for it: `mql run ... -j | grep -c '<the secret>'` must be 0. Then state the guarantee precisely — "this field carries no secret" is true; "the secret is not exposed" is false while `file.content` exists.
- **Composability.** `<resource>.files { permissions { ... } }` — permission and ownership checks should reach every file that contributed, not just the entry point.

**Exercise the fallback, not just the path that hides it.** A fallback added alongside a working primary source never runs in a normal test, so it ships unverified. Disable the primary deliberately:

> The `ServerRoot` fallback in `apache2.conf` would have shipped untested — the upstream image's config *declares* `ServerRoot`, so the new code never executed. Commenting it out and adding a relative `Include` showed the include resolving through the compiled-in root, where before it would have resolved against the platform default and found nothing.

**A fix's fixture must contain the shape that triggered the bug.** This is the one that most often produces a green test proving nothing:

> A parser fix for discarded `<IfModule>` blocks passed its fixture identically before and after — because the fixture wrote its settings at top level, and the Red Hat layout it was built on does not wrap its virtual host the way Debian's does. The suite could not have caught the bug and still cannot. The evidence that the fix worked came from a *stock vendor config* elsewhere: a `<Directory>` nested inside a TLS virtual host that had been invisible, taking the directory count from 7 to 8.

After fixing a parser bug, ask which fixture now contains the triggering shape. If none does, the test suite is silent about the thing you just fixed.

## 6. Before the PR

```bash
gofmt -l <changed .go files>
./mqlr generate providers/<p>/resources/<p>.lr --dist providers/<p>/resources
go build ./... && go test ./resources/...
git diff --stat providers/<p>/resources/<p>.lr.versions    # new entries at version+1
git diff -U0 -- '*.lr' | grep '^+' | grep -c "—"          # em dashes: check your lines, not the file
```

Check the diff, not the whole file: `os.lr` already carries 38 em dashes from before the rule, so grepping the file reports a problem you did not create.

Then write the PR body around what you **ran**, not what you wrote: the queries, the values they returned, and the cases that failed before the fix. A table of observed results is worth more than a description of the schema, and it is what lets a reviewer disagree with you about something real.

If a fixture carries anything credential-shaped — a generated key in a `.jks`, a password in a config — remember the secret scanner reads **every commit in the PR**, not the final diff. Removing it in a later commit does not help; the branch has to be squashed.

## 7. Reading review feedback

Check a review's premise before rewriting around it, in both directions. On this codebase both failure modes have happened on the same PR:

> A review blocked `java.keystore` on the grounds that `pkcs12.ToPEM` is deprecated and `pkcs12.DecodeChain` handles SHA-256 MACs natively, which would delete an error type entirely. On the pinned version *and* on the newest release, `DecodeChain` does not exist, `ToPEM` carries no `Deprecated:` marker, and `Decode` fails with the identical error — both route through a MAC verifier that only accepts SHA-1. Two minutes of checking against a rewrite.
>
> The same review's other finding was real, and **worse than it described**: an `__id` built from a possibly-duplicate alias did not merely return the wrong entry, it let the second entry's data overwrite the cached first one's, so one entry was reported where there were two, carrying the wrong contents.

The useful move when a suggestion is wrong but points at something real: fix what is real, show the measurement that disproves the rest, and file the underlying need as an issue recording the dead ends — so the next person does not re-spend the time. A typed error usually exists where you were tempted to match on message text; look for it before pinning a string.

## Reference implementations

- **Brace-block config with includes:** `providers/os/resources/bind9/` + `bind9.go`, or `nginx/` + `nginx.go`. Include expansion, cycle detection, partial-parse survival.
- **Key/value config:** `providers/os/resources/sshd.go`.
- **Cloud API listing:** any `providers/aws/resources/aws_*.go` — different shape, same schema rules.

## Where this skill stops

This is the **build** path: design a resource, generate it, implement it, prove it against a real target.

- Auditing resources that already shipped — nil handling, pagination truncation, `__id` collisions across a whole provider — is the **`provider-bug-review`** skill. It reads code looking for defects; this one builds and verifies. If you are asking "what is wrong with the okta provider", you want that skill, not this one.
- Proving a PR against provisioned cloud infrastructure is **`provider-verification`**.
- Bootstrapping a provider that does not exist yet is **`new-provider`**, which hands off to this skill at its Step 7.
