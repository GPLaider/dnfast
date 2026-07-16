# dnfast safety contract

## Supported boundary

Read-only `repo list`, `search`, `doctor`, and `plan` do not change RPMDB state. `plan` may run as
an unprivileged user when it can read the root-published snapshots and write the requested output
path. Comps `group list` and `group info` are also read-only. `repo refresh`, `apply`, `install`,
`remove`, `upgrade`, and `group install` require root because they publish system state or can
change packages. Modulemd interpretation is not implemented: absence is reported exactly and
present module metadata fails closed before module state can change. Unsupported commands fail
closed.

A valid plan is a solved proposal, not proof that a later transaction must succeed. It is bound to
the exact repository snapshots, root-published policy, RPMDB inventory, action graph, artifacts,
and trust material and expires after 300 seconds. Apply reopens retained root-owned inputs and
re-solves before enabling writes. Any stale RPMDB, metadata, plan, trust bundle, artifact, or
namespace binding aborts the operation.

## Metadata and cache integrity

Metadata refresh disables redirects, requires HTTPS sources, and, for Metalink, validates repomd
size and SHA-256 before accepting a mirror. Primary and filelists compressed/open SHA-256 and size
values from repomd are mandatory and checked before publication. When `repo_gpgcheck=true`, dnfast
also downloads `repomd.xml.asc` and verifies the detached OpenPGP signature with the repository's
root-owned key bundle at the refresh timestamp. The verified primary and signing fingerprints,
key-bundle digest, and signature digest are bound into the cache generation and planning snapshot.

An apparently unchanged refresh is not a stale-cache shortcut. Dnfast first fetches the current
repomd and requires an exact byte digest match, then reopens and rehashes the complete immutable
raw metadata and search index before reuse. Any mismatch or missing object takes the full refresh
path or fails closed. A changed repomd can never reuse the old primary or filelists payload.

Snapshots and artifacts are immutable and content addressed. Complete objects are staged on the
cache filesystem, synced, and renamed before an atomic pointer update. Readers revalidate sizes,
digests, ownership, modes, retained descriptors, and safe path shapes. Failed refresh or download
cannot publish an incomplete current generation. The cache corruption model covers partial writes
and independent corruption, not a hostile process already able to rewrite all files as the same
trusted UID. Custom cache roots must not be shared with an untrusted writer.

Implementation ceilings are 2 MiB for Metalink, 16 MiB for repomd, 512 MiB for compressed
metadata, 1 GiB for opened metadata, 32 Metalink resources, and 2,000,000 packages. Arithmetic is
overflow checked and declared oversize input fails before download or allocation.

Schema-v5 planning snapshots refer to content-addressed payloads instead of embedding base64 and
bind optional comps/module payloads plus the compact file-provides index into each repository.
Materialization is permitted only for a snapshot read from its trusted, root-owned planning store;
each blob is opened beneath that store without following an attacker-selected path and its exact
size and SHA-256 are checked. The executor stages both compressed evidence and decoded native XML
from that one validated result. Legacy schema-v3/v4 snapshots remain compatible only within their
original, narrower authenticated field set; extended fields on an older schema are rejected.

## Configuration, package, and key trust

Repository configuration is untrusted. Parsing rejects malformed sections, invalid booleans,
duplicate IDs, invalid UTF-8, unresolved variables, unsafe paths, weakened TLS/package-signature
settings, unsupported metadata-signature requests, and enabled mutation repositories without an
explicit key bundle and allowed primary certificate fingerprint. Repository file opens are
anchored and checked against symlink/inode substitution.

Package specifications reject empty values where the operation requires a selector, leading
option syntax, control characters, and duplicates. Upgrade alone permits no selector and then
means upgrade all eligible installed packages.

Metadata trust and RPM payload trust are separate. Downloaded bytes must match the primary
metadata size and SHA-256. Key bundles are hashed into the planning snapshot; configured primary
fingerprints are explicit policy. Librpm verifies the RPM signature using an isolated repository
keyring, and dnfast checks package NEVRA, architecture, vendor, and authorized signer before adding
the artifact to the transaction. Merely naming a downloaded key in repository configuration never
authorizes it.

The five-minute limit applies to prepared plans and tokens. A repository snapshot's
`valid_at_unix` records when its immutable trust evidence was published; it is not itself a
five-minute cache expiry. Older staged certificates are accepted for execution only after the
root-owned system configuration, key bundle, immutable cache objects, planning pointer, and RPMDB
binding have all been revalidated against that snapshot. A timestamp more than five minutes in
the future is always rejected.

## Execution and recovery

The resident socket directory is root-owned mode 0700, the socket is mode 0600, frames are bounded,
and `SO_PEERCRED` restricts clients to EUID 0. A stale socket is removed only when it is a
single-link root-owned socket. The sequential daemon has no general command runner. A prepared
token binds one canonical solve, RPMDB cookie, planning/trust/policy generation, expiry, daemon
nonce, and sequence; only the same connection can approve it. A token mismatch, unexpected frame,
changed current snapshot, changed RPMDB cookie, or artifact mismatch aborts before writes and does
not fall back to another execution path.

The resident solve cache is an optimization of that same proof, not a second authority. A hit
requires the identical canonical intent, repository selection, planning generation, and RPMDB
cookie and produces a newly sequence-bound prepared token. The pool omits filelists to reduce the
normal working set. Refresh streams verified filelists into a snapshot-bound compact index with
256 logical buckets stored in 16 physical shards. An absolute-path selector opens and rehashes one
physical shard, maps the path to package ordinals, and submits one native `ONE_OF` selection to the
resident primary-only pool. A missing path, empty candidate set, malformed index, or digest
mismatch fails closed; full filelists are never opened during solve. Integrity or protocol errors
never trigger a compatibility fallback.

The compatibility fallback can launch only `/usr/libexec/dnfast-executor` with a retained plan
descriptor and a fixed argument shape. Both paths require root, reject ambient path substitution,
stage inputs under root-owned directories, revalidate bound state, and ask for approval before
allowing writes. Librpm performs transaction check, ordering, and execution on one owner thread.

The daemon verifies the full RPMDB before exposing the socket, again after any external cookie
change, and on every stateful failure. A successful daemon-owned transaction must change the
cookie and must exactly match the approved post-transaction identities for every changed package
name while the write lock is still held. This incremental integrity proof replaces an otherwise
redundant full verify on the hot success path; it does not bypass TEST, artifact/signature checks,
cookie validation, exact identity validation, journaling, or failure verification. The fixed
fallback continues to perform a full post-transaction RPMDB verification.

RPM transactions cannot promise atomic rollback once payload or scriptlet execution begins.
Dnfast writes a durable journal before the real transaction, records callbacks/results, publishes
the validated inventory after success, and reconciles interrupted or failed started transactions
after daemon restart or on the next fixed-executor entry. Recovery reports observed state; it does
not claim to reverse arbitrary scriptlet side effects. Package script output is untrusted data.

# Artifact cache path authority

Artifact transaction authority is keyed by the strict lexical absolute cache path. Dot components
and repeated separators are collapsed, and parent components are resolved without crossing the
filesystem root. Non-UTF-8 and NUL-bearing paths are rejected. Symlink canonicalization is
intentionally not used because it would make the authority key depend on a replaceable namespace
lookup. A second authority key binds the anchored directory device and inode, so bind-mount and
other same-inode aliases serialize with the normalized path authority as well.
