# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# Companion to classify-inits.awk, covering the half it cannot see.
#
#   awk -f classify-accessors.awk providers/<name>/resources/*.go | sort
#
# classify-inits.awk reads init functions. But a typed reference can also be
# resolved by the accessor itself, which builds a client and fetches inline and
# so never enters an init at all. Those are invisible to that script and cannot
# be fixed by anything done at the init level.
#
# This one reads the accessors instead: functions shaped
#
#   func (x *mqlFoo) bar() (*mqlBaz, error)
#
# i.e. returning a single resource, which is what a typed reference looks like.
# The receiver name is deliberately not pinned -- providers use a, g, k, o, r,
# m, c, p, i and more, and pinning it silently reports zero for every provider
# that picked a different letter.
#
# Output: <bucket>\t<file>:<line>\t<signature>
#
#   INLINE   reaches the API itself and never resolves through the resource
#            layer. Not reachable from init-level work. Triage by fan-in
#            before doing anything.
#   VIA-NEW  resolves through the resource layer. NewResource routes through
#            the target's init, so the init-level fixes apply; CreateResource
#            skips init, so they do not -- but either way it is not an inline
#            fetch. Read which one it is before planning work.
#   BOTH     does both -- typically a cache or list check with a fetch as the
#            fallback, which is usually correct. Read it before touching it;
#            bucketing these as VIA-NEW would hide a live fetch.
#   NO-IO    reads what it already has. Fine.
#
# A ZERO IS A RESULT TO CHECK, NOT TO TRUST. If a provider reports no INLINE and
# no VIA-NEW at all, suspect the patterns below before believing it: confirm the
# provider's accessors actually match the signature shape, and that it obtains
# clients in one of the ways detected here.
#
# TRIAGE THE INLINE ONES BY FAN-IN. They split into two kinds and only one is
# worth touching:
#
#   Owned sub-object -- a config child belonging to exactly one parent (a
#     database's audit policy, a storage account's management policy). One fetch
#     per parent is the floor and GetOrCompute already memoizes it there, so
#     nothing repeats. Leave it alone.
#
#   Shared resource -- a subnet, a public IP, a firewall policy, a disk.
#     Several resources point at it, so it is fetched once per referrer with
#     nothing deduplicating them. This is the backlog.
#
# Tell them apart by counting references to the target type:
#
#   rg -c '"<target.mql.name>"' providers/<name>/resources/*.go | grep -v _test
#
# The backlog is usually far smaller than it first looks. Once CreateResource is
# counted as resource-layer resolution (see below), INLINE drops to 13 in aws, 4
# in azure and 2 in gcp -- and most of what remains is owned sub-objects. Do not
# report the raw INLINE count as though all of it were work.

BEGIN {
    # An SDK operation always takes a context; an MQL list getter takes no
    # arguments. Requiring the context is what keeps svc.GetBackupVaults() on
    # an MQL resource from reading as an SDK call -- gcp names MQL resources
    # `svc`, aws names SDK clients `svc`.
    #
    # Connection methods that are NOT API calls -- they hand back credentials,
    # config or identity the connection already holds. Without scrubbing these,
    # the conn.<Service>( pattern that catches the aws style (conn.Ec2(region))
    # also matches conn.Token(), conn.Regions(), conn.Asset() and friends, and
    # every accessor looks like it reaches the API.
    notAPI = "Asset|Runtime|Context|Token|ClientOptions|Credentials|Config|Conf|" \
             "SubId|AccountId|OrganizationID|Regions|Region|BasePlatformId|" \
             "PlatformId|Name|Filters|Options|ID|Id|Provider|Upstream|Hash"
}

/^func \([a-z][a-zA-Z0-9]* \*mql[A-Za-z0-9]+\) [a-z][A-Za-z0-9]*\(\) \(\*mql[A-Za-z0-9]+, error\) \{/ {
    inFunc = 1
    sig = $0
    start = FNR
    body = ""
    next
}

inFunc && /^}/ {
    scrubbed = body
    gsub("conn\\.(" notAPI ")\\(", "", scrubbed)

    client = (scrubbed ~ /New[A-Za-z]*Client\(/) ||     # azure, gcp, some aws
             (scrubbed ~ /conn\.Client\(\)/) ||         # github, okta, gcp
             (scrubbed ~ /conn\.[A-Z][A-Za-z]*\(/) ||   # aws: conn.Ec2(region)
             (scrubbed ~ /svc\.[A-Z][A-Za-z]*\((ctx|context\.)/) || # aws sdk ops
             (scrubbed ~ /client\.[A-Z][A-Za-z]*\(ctx/) # gcp sdk operations
    # CreateResource counts too. It does NOT run the target's init, so
    # init-level fixes do not reach it -- but an accessor that resolves through
    # the resource layer is not fetching inline, and filing it under INLINE puts
    # already-correct code on the backlog. gcp's machineType() is the case that
    # exposed this: it resolves through the project's aggregated machine-type
    # list via CreateResource and keeps a direct Get only as a fallback for
    # custom types, yet it read as INLINE.
    newres = (scrubbed ~ /(New|Create)Resource\(/)

    if (newres && client) bucket = "BOTH"
    else if (newres)      bucket = "VIA-NEW"
    else if (client)      bucket = "INLINE"
    else                  bucket = "NO-IO"

    printf "%s\t%s:%d\t%s\n", bucket, FILENAME, start, sig
    inFunc = 0
    next
}

inFunc { body = body "\n" $0 }
