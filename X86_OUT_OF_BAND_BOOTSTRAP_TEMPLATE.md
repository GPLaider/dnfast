# dnfast x86 trusted bootstrap message template

This is a **coordinator-side template**, not an operator instruction to read
from the USB.  After producing the final archive, replace the two hash
placeholders with the final values and send the complete message and code block
through a channel independent of the USB.  The operator may change only the
Ventoy mount path before pasting the whole block into one trusted Bash shell.

Do not tell the operator to copy this block from the USB.  The block authenticates
both the outer runbook and archive, extracts the archive without executing its
contents, confirms the extracted runbook, and leaves the variables required by
sections 2 through 5 in the current shell.

## Message to send through the independent channel

The next two values and the entire code block are trusted coordinator input.
Do not substitute values from any file on the USB.

- Runbook SHA-256: `<FINAL-START-HERE-SHA256>`
- Archive SHA-256: `<FINAL-ARCHIVE-SHA256>`

Paste the following into one trusted Bash shell after changing only
`/path/to/Ventoy` to the actual mount path:

```bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

export VENTOY=/path/to/Ventoy
export HANDOFF="$VENTOY/dnfast-fedora44-x86-handoff/current-source-latest"
export EXPECTED_RUNBOOK_SHA256='<FINAL-START-HERE-SHA256>'
export EXPECTED_ARCHIVE_SHA256='<FINAL-ARCHIVE-SHA256>'
export RUN_ID="$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)-$$"
export RUN_ROOT="$HOME/dnfast-x86-current-run-$RUN_ID"

[[ $EXPECTED_RUNBOOK_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ $EXPECTED_ARCHIVE_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ -f $HANDOFF/START_HERE_X86.md && ! -L $HANDOFF/START_HERE_X86.md ]]
[[ -f $HANDOFF/dnfast-x86-handoff-current.tar.gz \
  && ! -L $HANDOFF/dnfast-x86-handoff-current.tar.gz ]]

/usr/bin/env -i \
  PATH=/usr/bin:/bin LC_ALL=C \
  HANDOFF="$HANDOFF" RUN_ROOT="$RUN_ROOT" \
  EXPECTED_RUNBOOK_SHA256="$EXPECTED_RUNBOOK_SHA256" \
  EXPECTED_ARCHIVE_SHA256="$EXPECTED_ARCHIVE_SHA256" \
  /usr/bin/bash --noprofile --norc -euo pipefail -c '
    cd "$HANDOFF"
    runbook_line=$(/usr/bin/sha256sum -- START_HERE_X86.md)
    archive_line=$(/usr/bin/sha256sum -- dnfast-x86-handoff-current.tar.gz)
    [[ ${runbook_line%% *} == "$EXPECTED_RUNBOOK_SHA256" ]]
    [[ ${archive_line%% *} == "$EXPECTED_ARCHIVE_SHA256" ]]
    /usr/bin/sha256sum -c SHA256SUMS-CURRENT.txt
    [[ ! -e $RUN_ROOT ]]
    /usr/bin/mkdir -m 0700 -- "$RUN_ROOT"
    /usr/bin/tar -xzf dnfast-x86-handoff-current.tar.gz -C "$RUN_ROOT"
    [[ -f $RUN_ROOT/dnfast/START_HERE_X86.md ]]
    [[ -d $RUN_ROOT/cargo-home/registry ]]
    /usr/bin/cmp -- START_HERE_X86.md \
      "$RUN_ROOT/dnfast/START_HERE_X86.md"
    extracted_line=$(/usr/bin/sha256sum -- \
      "$RUN_ROOT/dnfast/START_HERE_X86.md")
    [[ ${extracted_line%% *} == "$EXPECTED_RUNBOOK_SHA256" ]]
  '

export CARGO_HOME="$RUN_ROOT/cargo-home"
builtin printf 'AUTHENTICATED_NEXT=%s\n' \
  "$RUN_ROOT/dnfast/START_HERE_X86.md"
```

After `AUTHENTICATED_NEXT=...` appears, open that extracted file, not the USB
copy, and continue at section 2 in the same Bash shell.  Any nonzero exit means
stop; do not open or execute transferred content.
