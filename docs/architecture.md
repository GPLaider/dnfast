# dnfast architecture

## Implemented package pipeline

The public mutation path is an independent libsolv/librpm pipeline:

```text
argv -> checked TransactionIntent
  -> strict dnf.conf and .repo policy
  -> bounded HTTPS metadata refresh
  -> checksum-addressed immutable rpm-md snapshots
  -> root-published repository + RPMDB planning snapshot
  -> resident libsolv pool and one explained solve
  -> same-connection approval token bound to solve + RPMDB cookie + generation
  -> RPM payload download bound to primary metadata digest and size
  -> repository fingerprint policy + direct librpm signature verification
  -> retained descriptors and final write-lock cookie revalidation
  -> direct librpm TEST + RUN, selected identity check, journal, reconciliation
```

No product path invokes DNF or DNF5. The normal root mutation path connects to the root-only
`/run/dnfast/dnfastd.sock`; when that socket is genuinely unavailable the CLI can exec only the
fixed `/usr/libexec/dnfast-executor`. Neither executor surface has a general command-runner
interface. Architecture detection may query the system `rpm` command, but package selection and
transaction execution use the native libraries directly.

`dnfast-core` owns package intent and canonical integrity types. `dnfast-repo` treats repository
configuration as untrusted input. `dnfast-metadata`, `dnfast-cache`, and `dnfast-refresh` own
bounded transport, checksum verification, immutable publication, and generation consistency.
`dnfast-planning` publishes one root-owned snapshot binding configuration, repository generations,
trust material, solver policy, and RPMDB inventory. `dnfast-native-sys` and `dnfast-native` isolate
the libsolv/librpm ABI. `dnfast-solver` converts the native transaction to a complete, explained,
canonical plan. `dnfast-executor` owns both the resident protocol and fixed fallback, revalidates
and applies only the approved solve, and `dnfast-state` owns durable transaction journals and
post-start reconciliation.

## Metadata and cache model

Repository files are read in deterministic path order. URL expansion requires known variables;
unknown values fail. Refresh tries configured base URLs in order, then Metalink. Redirects are
disabled and every source must use HTTPS. Metalink can authenticate the repomd size and SHA-256;
repomd then authenticates compressed/open primary and filelists records. A mirror retry restarts
the entire generation, so metadata from generations never mixes.

Snapshots are addressed by the exact repomd SHA-256. Complete objects are staged and synced before
an atomic current-pointer update. Search revalidates the immutable manifest and primary digest but
does not decompress and reparse all primary XML for every query. System cache and planning roots
are `/var/cache/dnfast` and `/var/lib/dnfast/planning`.

Current limits are 2 MiB for Metalink, 16 MiB for repomd, 512 MiB for compressed metadata,
1 GiB for opened metadata, 32 Metalink resources, and 2,000,000 packages. Declared sizes above
implementation-owned limits fail before allocation or download.

## Solver and transaction model

Libsolv owns dependency resolution and emits the transaction and causal decisions. Dnfast stores
policy such as weak dependencies, best-candidate behavior, protected packages, install-only
limits, vendor changes, repository priority, and cost as typed plan inputs. Both forward weak
requirements and reverse Supplements/Enhances decisions are represented in the plan graph.
An empty upgrade request means update all eligible installed packages; empty install/remove
requests remain invalid.

Librpm owns package signature verification, transaction checks and ordering, payload changes,
scriptlets, triggers, plugins, and RPMDB writes. Native libsolv/librpm objects remain on one owner
thread. `dnfastd` performs a full RPMDB verification before accepting connections. It keeps one
pool for the exact current planning generation and RPMDB cookie, and refreshes the installed repo
incrementally after its own successful transaction. An external cookie change invalidates the
pool and requires another full RPMDB verification before reuse.

Prepare returns the solved actions and a SHA-256 token binding the daemon nonce, monotonic
sequence, canonical plan digest, RPMDB cookie, metadata/trust/policy digests, and expiry. Approval
must arrive on the same connection with a constant-time token match. Before writes the daemon
rechecks the current snapshot generation and obtains the RPMDB write lock with the approved
cookie. Root-owned artifact descriptors are rehashed and their signature, signer, NEVRA,
architecture, vendor, size, and repository binding are checked before librpm sees them.

On the normal successful resident path, the post-RUN cookie must change and only names in the
approved action set are queried under the still-held write lock. Their exact post-transaction
name/EVRA/vendor identities must match the approved result, including retained same-name
instances. The RPM name index is counted separately so “zero matches after removal” cannot mask an
iterator/index failure. The rest of the inventory is inherited only from the cookie-bound
pre-transaction snapshot. Daemon startup, external cookie changes, and all stateful failure paths
still run full RPMDB verification; failures also perform a full uncached inventory reconciliation.
The fixed fallback retains full post-transaction RPMDB verification.

RPM transactions are not atomically rollbackable after scriptlets or payload changes start.
Cancellation before execution is an abort; failure after execution starts is recorded and followed
by RPMDB/inventory reconciliation, not described as rollback.

## Compatibility and concurrency

RPM and rpm-md compatibility do not imply DNF5 behavioral compatibility. DNF5 also owns policy,
install reasons, groups, history, plugins, locks, and private state beyond RPMDB. Dnfast therefore
describes itself as an independent package manager with an explicitly smaller command surface.

Network and decompression may run concurrently through bounded queues. One repomd generation is
immutable; solver state has one owner; the librpm execution boundary is single-threaded and root
privilege is limited to refresh, planning publication, preparation, and transaction execution.
