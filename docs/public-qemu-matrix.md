# Public QEMU matrix harness

For the current x86_64 handoff, begin with
the complete coordinator-supplied out-of-band bootstrap.  It performs sections
0 and 1, then directs the operator to the authenticated extracted
[`START_HERE_X86.md`](../START_HERE_X86.md) for sections 2 through 5 in the
same Bash shell.  The snippets below explain the harness contract; they are not
a substitute for the current operator runbook, its clean environment, trusted
input checks, evidence capture, or return procedure.

`tools/public-qemu-matrix.sh` is the native public-flow harness boundary. It
uses the installed `/usr/bin/dnfast` CLI. It packages the fixed executor at
`/usr/libexec/dnfast-executor` but never invokes that binary directly, nor an
example, debug binary, or test runtime switch.

Run the source-only contract before attempting a guest:

```bash
tools/tests/public-qemu-matrix-contract.sh
tools/public-qemu-matrix.sh --help
```

The harness needs an HTTPS rpm-md fixture origin with the matching public
primary fingerprint and certificate. The fixture server is an explicit test
input, not a caller-controlled input to `dnfast` itself. A future matrix run
must use one fresh endpoint and set these values before invoking `--run`:

```bash
export MATRIX_BASEURL='https://fixture-host.example.invalid/repos/main'
export MATRIX_FINGERPRINT='0123456789ABCDEF0123456789ABCDEF01234567'

tools/public-qemu-matrix.sh \
  --arch aarch64 \
  --baseurl "$MATRIX_BASEURL" \
  --fingerprint "$MATRIX_FINGERPRINT" \
  --receipt /tmp/dnfast-public-qemu-aarch64.raw.log \
  --run
```

For the checked-in aarch64 fixture only, the harness can instead create its
own TLS endpoint inside the guest. This keeps the QEMU user network restricted
and still exercises HTTPS plus the platform certificate verifier:

```bash
tools/public-qemu-matrix.sh \
  --arch aarch64 \
  --baseurl https://localhost:18443 \
  --fingerprint 2B017A94136265DB56C0CCD6DF21D1EED6503531 \
  --guest-fixture \
  --receipt /tmp/dnfast-public-qemu-aarch64.raw.log \
  --run
```

On the current aarch64 host, the default aarch64 image and toolroot come from
`.cache/fedora44-vm`. The run packages both the CLI and fixed executor with
offline `cargo install`, installs them at `/usr/bin/dnfast` and
`/usr/libexec/dnfast-executor` as root-owned `0755` files, publishes the root
planning snapshot with `dnfast repo refresh`, then drives public
plan-to-transaction cases. The
initial matrix executes signed install, remove, upgrade, default-No and
affirmative PTY approval, and non-root apply rejection. It checks
`rpmdb --verifydb`, sorted package and managed-filesystem before/after digests,
no staging residue, and no unfinished input publication. A receipt records a
scenario only after that guest assertion passes.

For x86_64, the harness never emulates another architecture. It fails before
any guest mutation unless `uname -m` is exactly `x86_64` and `/dev/kvm` is
readable and writable. An x86_64 system must provide its own native Fedora 44
image, UEFI files, QEMU binaries, cloud-localds binary, and locked build RPM
repository through these variables:

```bash
export MATRIX_QEMU_SYSTEM=/path/to/qemu-system-x86_64
export MATRIX_QEMU_IMG=/path/to/qemu-img
export MATRIX_CLOUD_LOCALDS=/path/to/cloud-localds
export MATRIX_IMAGE=/path/to/Fedora-Cloud-Base-Generic-44.x86_64.qcow2
export MATRIX_FIRMWARE=/path/to/OVMF_CODE.fd
export MATRIX_VARIABLES=/path/to/OVMF_VARS.fd
export MATRIX_RPM_REPOSITORY=/path/to/locked-rpms
export MATRIX_CREATEREPO=/path/to/createrepo_c
export MATRIX_BUILD_GPG_KEY=/path/to/fedora-build-key.asc
export MATRIX_HOST_TOOLS_SHA256=/path/to/trusted-host-tools.sha256
export MATRIX_GUEST_ASSETS_SHA256=/path/to/trusted-guest-assets.sha256
export MATRIX_RPM_REPOSITORY_SHA256=/path/to/trusted-rpm-repository.sha256
export MATRIX_BUILD_PACKAGES='gcc-... libsolv-devel-... rpm-devel-... pkgconf-pkg-config-... rust-... cargo-...'
```

Obtain the three manifests through an independent trusted channel outside the
transferred USB and extracted run tree.  Preflight byte-compares them with
canonical observations of the host tools, guest assets, and every locked-RPM
repository file.  Use the exact manifest construction order documented in
`START_HERE_X86.md`; a checksum generated beside an untrusted asset does not
authenticate that asset.

Do not treat the existing x86 solver pool probe as an x86_64 transaction
matrix. Do not use a software-emulated fallback. The harness owns only its
`/tmp/dnfast-public-qemu.*` runtime directory and validates the QEMU command
line before terminating the recorded PID.
