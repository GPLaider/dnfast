# dnfast architecture

## Implemented package pipeline

The public mutation path is an independent libsolv/librpm pipeline:

```text
argv -> checked TransactionIntent
  -> strict dnf.conf and .repo policy
  -> bounded HTTPS metadata refresh
  -> checksum-addressed immutable rpm-md snapshots
  -> root-published repository + RPMDB planning snapshot
  -> direct libsolv dependency transaction and explained plan
  -> RPM payload download bound to primary metadata digest and size
  -> repository fingerprint policy + direct librpm signature verification
  -> fixed root executor with retained descriptors and revalidation
  -> direct librpm check, order, run, verifydb, journal, reconciliation
```

No product path invokes DNF or DNF5. The only executable launched by the CLI mutation path is the
fixed `/usr/libexec/dnfast-executor`; the executor has no general command-runner interface.
Architecture detection may query the system `rpm` command, but package selection and transaction
execution use the native libraries directly.

`dnfast-core` owns package intent and canonical integrity types. `dnfast-repo` treats repository
configuration as untrusted input. `dnfast-metadata`, `dnfast-cache`, and `dnfast-refresh` own
bounded transport, checksum verification, immutable publication, and generation consistency.
`dnfast-planning` publishes one root-owned snapshot binding configuration, repository generations,
trust material, solver policy, and RPMDB inventory. `dnfast-native-sys` and `dnfast-native` isolate
the libsolv/librpm ABI. `dnfast-solver` converts the native transaction to a complete, explained,
canonical plan. `dnfast-executor` revalidates and applies only that approved plan. `dnfast-state`
owns durable transaction journals and post-start reconciliation.

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
scriptlets, triggers, plugins, and RPMDB writes. Native librpm objects remain on one owner thread.
The fixed executor rechecks the canonical plan lifetime, root-owned inputs, metadata and artifact
digests, package identity/vendor/signing fingerprint, RPMDB inventory, and native re-solve before
allowing writes.

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
