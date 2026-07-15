#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SOURCE=$ROOT/native/src/solver.c

grep -Fq 'selector_relation_kinds[name_index] =' "$SOURCE" || {
  printf '%s\n' 'selector relation kind: selector provenance assignment is missing' >&2
  exit 1
}
grep -Fq 'ISRELDEP(job.elements[start + 1])' "$SOURCE" || {
  printf '%s\n' 'selector relation kind: exact selector job dependency must use ISRELDEP' >&2
  exit 1
}
grep -Fq 'job.count != start + 2' "$SOURCE" || {
  printf '%s\n' 'selector relation kind: exact selector job must contain one dependency pair' >&2
  exit 1
}
! grep -Fq 'Queue bare_selector;' "$SOURCE" || {
  printf '%s\n' 'selector relation kind: bare selection failure heuristic is forbidden' >&2
  exit 1
}
! grep -Fq 'selection_make(context->pool, &bare_selector' "$SOURCE" || {
  printf '%s\n' 'selector relation kind: bare selector probe is forbidden' >&2
  exit 1
}

printf '%s\n' 'selector_relation_kind_contract=passed'
