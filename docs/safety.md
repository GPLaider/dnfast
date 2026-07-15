# dnfast safety contract

## Supported boundary

Read-only `repo list`, `search`, `doctor`, and `plan` do not change RPMDB state. `plan` may run as
an unprivileged user when it can read the root-published snapshots and write the requested output
path. `repo refresh`, `apply`, `install`, `remove`, and `upgrade` require root because they publish
system state or can change packages. Unsupported commands fail closed with exit code 2.

A valid plan is a solved proposal, not proof that a later transaction must succeed. It is bound to
the exact repository snapshots, root-published policy, RPMDB inventory, action graph, artifacts,
and trust material and expires after 300 seconds. Apply reopens retained root-owned inputs and
re-solves before enabling writes. Any stale RPMDB, metadata, plan, trust bundle, artifact, or
namespace binding aborts the operation.

## Metadata and cache integrity

Metadata refresh disables redirects, requires HTTPS sources, and, for Metalink, validates repomd
size and SHA-256 before accepting a mirror. Primary and filelists compressed/open SHA-256 and size
values from repomd are mandatory and checked before publication. These transport and digest checks
do not by themselves prove publisher authenticity: dnfast does not currently verify an OpenPGP
signature over repomd. Repositories with `repo_gpgcheck=true` are rejected instead of silently
weakening that request.

Snapshots and artifacts are immutable and content addressed. Complete objects are staged on the
cache filesystem, synced, and renamed before an atomic pointer update. Readers revalidate sizes,
digests, ownership, modes, retained descriptors, and safe path shapes. Failed refresh or download
cannot publish an incomplete current generation. The cache corruption model covers partial writes
and independent corruption, not a hostile process already able to rewrite all files as the same
trusted UID. Custom cache roots must not be shared with an untrusted writer.

Implementation ceilings are 2 MiB for Metalink, 16 MiB for repomd, 512 MiB for compressed
metadata, 1 GiB for opened metadata, 32 Metalink resources, and 2,000,000 packages. Arithmetic is
overflow checked and declared oversize input fails before download or allocation.

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

## Execution and recovery

The CLI can launch only `/usr/libexec/dnfast-executor` with a retained plan descriptor and a fixed
argument shape. The executor requires root, rejects ambient path substitution, stages inputs under
root-owned directories, revalidates the RPMDB and native solve, and asks for approval before
allowing writes. Librpm performs transaction check, ordering, execution, and RPMDB verification on
one owner thread.

RPM transactions cannot promise atomic rollback once payload or scriptlet execution begins.
Dnfast writes a durable journal before the real transaction, records callbacks/results, verifies
RPMDB, republishes inventory after success, and reconciles interrupted or failed started
transactions on the next executor entry. Recovery reports observed state; it does not claim to
reverse arbitrary scriptlet side effects. Package script output is untrusted data.

# Artifact cache path authority

Artifact transaction authority is keyed by the strict lexical absolute cache path. Dot components
and repeated separators are collapsed, and parent components are resolved without crossing the
filesystem root. Non-UTF-8 and NUL-bearing paths are rejected. Symlink canonicalization is
intentionally not used because it would make the authority key depend on a replaceable namespace
lookup. A second authority key binds the anchored directory device and inode, so bind-mount and
other same-inode aliases serialize with the normalized path authority as well.
