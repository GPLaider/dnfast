#!/usr/bin/env bash
set -euo pipefail

readonly limit=250
readonly bindings='./crates/dnfast-native-sys/src/bindings.rs'
readonly generated='./fixtures/rpm/generated/'
violations=0

while IFS= read -r -d '' path; do
    relative="./${path#./}"
    if [[ "$relative" == "$bindings" || "$relative" == "$generated"* ]]; then
        continue
    fi

    count="$({
        awk '
        BEGIN { block_depth = 0; count = 0 }
        {
            line = $0
            code = 0
            quote = ""
            escaped = 0
            for (i = 1; i <= length(line); i++) {
                pair = substr(line, i, 2)
                char = substr(line, i, 1)
                if (block_depth > 0) {
                    if (pair == "/*") { block_depth++; i++; continue }
                    if (pair == "*/") { block_depth--; i++; continue }
                    continue
                }
                if (quote != "") {
                    code = 1
                    if (escaped) { escaped = 0; continue }
                    if (char == "\\") { escaped = 1; continue }
                    if (char == quote) { quote = "" }
                    continue
                }
                if (pair == "//") break
                if (pair == "/*") { block_depth++; i++; continue }
                if (char == "\"" || char == "\047") { quote = char; code = 1; continue }
                if (char !~ /[[:space:]]/) code = 1
            }
            if (code) count++
        }
        END { print count }
        ' "$path"
    })"
    printf '%4d %s\n' "$count" "${path#./}"
    if (( count > limit )); then
        violations=$((violations + 1))
    fi
done < <(
    find crates native fixtures tools -type f \( -name '*.rs' -o -name '*.c' \) -print0 2>/dev/null \
        | sort -z
)

if (( violations > 0 )); then
    printf 'LOC check failed: %d handwritten Rust/C file(s) exceed %d pure LOC\n' \
        "$violations" "$limit" >&2
    exit 1
fi

printf 'LOC check passed: all handwritten Rust/C files are <=%d pure LOC\n' "$limit"
