# dnfast x86_64 validation handoff

This file is a pointer, not a validation result. Historical Todo numbers and stale claims about
missing x86_64 evidence were removed because they could be mistaken for the current release state.

Use [`docs/public-qemu-matrix.md`](docs/public-qemu-matrix.md) for the public Fedora 44 x86_64 KVM
test boundary. A valid result must come from a fresh native `DNFAST_NATIVE_REAL=1` build, an
installed `/usr/bin/dnfast` and `/usr/libexec/dnfast-executor`, direct libsolv/librpm linkage, all
required public-CLI scenarios, an RPMDB verification, state restoration, and complete VM cleanup.
Direct executor calls, test hooks, examples, TCG, cross-architecture emulation, or a result from an
older source snapshot are not substitutes.

Benchmark evidence is separate from correctness evidence. It must use immutable identical inputs,
independent VM overlays, validated final package state, retained failures, and enough successful
samples per tool and cell. Do not infer a current benchmark or release result from this source
document.

The completed run's exact source identity, changes, commands, raw evidence, checksums, test result,
benchmark conditions, and remaining blockers belong in the external handoff delivered with that
run. When Git metadata is absent from a transferred source archive, the handoff must say so rather
than presenting an embedded commit string as a verified checkout state.
