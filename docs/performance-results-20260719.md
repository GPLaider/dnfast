# Fedora 44 x86_64 performance verification (2026-07-19)

## Supported conclusion

On the tested Fedora 44 x86_64 host and supported command paths, the final daemonless `dnfast`
build was faster than DNF5 and used less peak resident memory. This is an empirical result for the
conditions below, not a universal claim across hardware, repositories, plugins, or unimplemented
features.

## Exact-fair derived-cold planning

Each trial retained identical raw Fedora and updates metadata but removed both tools' derived solver
caches. Application network access was disabled, the OS page cache was retained, `dnfastd` was
inactive, and execution order alternated. The `dnfast` measurement includes its verified internal
publisher plus the first public `/usr/bin/htop --assumeno` solve; DNF5 performed its first
`--cacheonly` solve from the same raw metadata.

| Median | dnfast | DNF5 | DNF5 / dnfast |
| --- | ---: | ---: | ---: |
| Wall time | **12.82 s** | 17.86 s | **1.393x** |
| User CPU | **5.20 s** | 16.47 s | **3.167x** |
| System CPU | **0.67 s** | 0.75 s | **1.119x** |
| Peak RSS | **237,716 KiB** | 541,024 KiB | **2.276x** |

`dnfast` won all five individual wall-time trials. The raw totals were
`12.82, 12.92, 14.19, 10.74, 10.09` seconds for dnfast and
`17.55, 17.86, 17.89, 17.57, 19.49` seconds for DNF5.

## Daemonless process-cold matrix

Each case used a new process, an inactive daemon, identical immutable metadata/cache inputs, and
nine alternating trials.

| Case | dnfast wall / RSS | DNF5 wall / RSS |
| --- | ---: | ---: |
| Package name `htop` | **0.56 s / 142,344 KiB** | 0.86 s / 198,416 KiB |
| Binary `/usr/bin/htop` | **0.66 s / 159,936 KiB** | 0.95 s / 204,904 KiB |
| Deep file path | **0.97 s / 168,260 KiB** | 1.98 s / 221,896 KiB |
| No-change install | **0.56 s / 142,276 KiB** | 0.85 s / 198,140 KiB |

The host used an Intel Core i5-1035G4 with 8 logical CPUs, Fedora kernel
`6.19.10-300.fc44.x86_64`, dnfast `0.1.0`, and DNF5 `5.4.1.0`. Raw logs, integrity receipts, and
their SHA-256 manifest are published with the `v0.1.0` release evidence archive.

## Remaining boundaries

The official Fedora snapshot used for the host test had no modulemd target. General plugin and COPR
repository policy, system-upgrade, and offline sealed reboot flows are not implemented. Earlier
small-fixture measurements also contain cells where DNF5 was faster; they remain valid for those
different workloads and are not erased by this result.
