#!/usr/bin/bash
set -euo pipefail

export LC_ALL=C
export TZ=UTC

if [[ ${EUID} -ne 0 ]]; then
    echo "this gate must run as root" >&2
    exit 2
fi
if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 OUTPUT_DIRECTORY [TRIALS]" >&2
    exit 2
fi

output=$1
trials=${2:-9}
dnfast=${DNFAST_BIN:-/usr/bin/dnfast}
dnf5=${DNF5_BIN:-/usr/bin/dnf5}
repos=(fedora updates)
mkdir -p "$output/raw"
if ! [[ $trials =~ ^[1-9][0-9]*$ ]] || (( trials > 99 )); then
    echo "TRIALS must be between 1 and 99" >&2
    exit 2
fi
if rpm -q htop >/dev/null 2>&1; then
    echo "htop must be absent so both tools solve the same install" >&2
    exit 2
fi
if systemctl is-active --quiet dnfastd.service; then
    echo "dnfastd must be inactive for a daemonless comparison" >&2
    exit 2
fi

cache_inventory() {
    local root=$1
    find "$root" -xdev -type f -print0 2>/dev/null \
        | sort -z \
        | xargs -0 -r sha256sum
}

net_snapshot() {
    awk -F '[: ]+' 'NR > 2 { rx += $3; tx += $11 } END { print rx, tx }' /proc/net/dev
}

selector() {
    case $1 in
        name) printf '%s\n' htop ;;
        binary) printf '%s\n' /usr/bin/htop ;;
        deep-file) printf '%s\n' /usr/share/doc/htop/AUTHORS ;;
        no-change) printf '%s\n' bash ;;
        *) return 2 ;;
    esac
}

run_dnfast() {
    local iteration=$1 case_name=$2 package status prefix
    prefix="$output/raw/dnfast-$case_name-$iteration"
    package=$(selector "$case_name")
    net_snapshot >"$prefix.net-before"
    set +e
    /usr/bin/time -f 'elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\nmax_rss_kib=%M\nexit_status=%x' \
        -o "$prefix.time" \
        "$dnfast" --json install --repo "${repos[0]}" --repo "${repos[1]}" \
        --assumeno "$package" >"$prefix.stdout" 2>"$prefix.stderr"
    status=$?
    set -e
    net_snapshot >"$prefix.net-after"
    printf '%s\n' "$status" >"$prefix.status"
    [[ $status -eq 0 ]]
    if [[ $case_name == no-change ]]; then
        jq -e '.status == "planned" and (.actions | length) == 0 and (.message | startswith("no changes"))' \
            "$prefix.stdout" >/dev/null
    else
        jq -e '.status == "aborted" and ([.actions[].name] | index("htop") != null)' \
            "$prefix.stdout" >/dev/null
    fi
}

run_dnf5() {
    local iteration=$1 case_name=$2 package status prefix
    prefix="$output/raw/dnf5-$case_name-$iteration"
    package=$(selector "$case_name")
    net_snapshot >"$prefix.net-before"
    set +e
    /usr/bin/time -f 'elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\nmax_rss_kib=%M\nexit_status=%x' \
        -o "$prefix.time" \
        "$dnf5" --cacheonly --repo="${repos[0]}" --repo="${repos[1]}" \
        --setopt=install_weak_deps=True --assumeno install "$package" \
        >"$prefix.stdout" 2>"$prefix.stderr"
    status=$?
    set -e
    net_snapshot >"$prefix.net-after"
    printf '%s\n' "$status" >"$prefix.status"
    if [[ $case_name == no-change ]]; then
        [[ $status -eq 0 ]]
        grep -Eqi 'nothing to do|already installed' "$prefix.stdout" "$prefix.stderr"
    else
        [[ $status -eq 1 ]]
        grep -Eq '(^|[[:space:]])htop([[:space:]].*|$)' "$prefix.stdout"
    fi
}

summarize() {
    local tool=$1 case_name=$2
    local data count middle elapsed user system rss
    data=$(mktemp)
    for file in "$output"/raw/"$tool-$case_name-"*.time; do
        awk -F= '/^(elapsed_seconds|user_seconds|system_seconds|max_rss_kib)=/ { value[$1]=$2 }
            END { printf "%s\t%s\t%s\t%s\n", value["elapsed_seconds"], value["user_seconds"], value["system_seconds"], value["max_rss_kib"] }' \
            "$file" >>"$data"
    done
    count=$(wc -l <"$data")
    middle=$(((count + 1) / 2))
    elapsed=$(cut -f1 "$data" | sort -n | sed -n "${middle}p")
    user=$(cut -f2 "$data" | sort -n | sed -n "${middle}p")
    system=$(cut -f3 "$data" | sort -n | sed -n "${middle}p")
    rss=$(cut -f4 "$data" | sort -n | sed -n "${middle}p")
    rm -f "$data"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$tool" "$case_name" "$count" "$elapsed" "$user" "$system" "$rss"
}

{
    uname -a
    systemd-detect-virt || true
    lscpu
    findmnt -no SOURCE,FSTYPE,OPTIONS /
    "$dnfast" --version
    "$dnf5" --version
    systemctl is-enabled dnfastd.service || true
    systemctl is-active dnfastd.service || true
    printf 'dnfast=%s\ndnf5=%s\ntrials=%s\nrepositories=%s,%s\n' \
        "$dnfast" "$dnf5" "$trials" "${repos[0]}" "${repos[1]}"
} >"$output/environment.txt" 2>&1
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' \
    | sort >"$output/rpm-inventory-before.tsv"
rpm --verifydb >"$output/rpmdb-before.txt" 2>&1

# Warm only immutable derived caches before the measured process-cold runs.
run_dnfast warmup name
run_dnf5 warmup name
rm -f "$output"/raw/*warmup*
cache_inventory /var/cache/dnfast >"$output/dnfast-cache-before.SHA256SUMS"
cache_inventory /var/cache/libdnf5 >"$output/dnf5-cache-before.SHA256SUMS"
printf 'iteration\tposition\ttool\tcase\n' >"$output/order.tsv"

cases=(name binary deep-file no-change)
for iteration in $(seq 1 "$trials"); do
    position=0
    offset=$((iteration % 8))
    cells=(
        dnfast:name dnf5:name
        dnf5:binary dnfast:binary
        dnfast:deep-file dnf5:deep-file
        dnf5:no-change dnfast:no-change
    )
    for index in $(seq 0 7); do
        cell=${cells[$(((index + offset) % 8))]}
        tool=${cell%%:*}
        case_name=${cell#*:}
        position=$((position + 1))
        printf '%s\t%s\t%s\t%s\n' "$iteration" "$position" "$tool" "$case_name" \
            >>"$output/order.tsv"
        "run_$tool" "$iteration" "$case_name"
    done
done

printf 'tool\tcase\ttrials\tmedian_elapsed_seconds\tmedian_user_seconds\tmedian_system_seconds\tmedian_max_rss_kib\n' \
    >"$output/summary.tsv"
for case_name in "${cases[@]}"; do
    summarize dnfast "$case_name" >>"$output/summary.tsv"
    summarize dnf5 "$case_name" >>"$output/summary.tsv"
done

printf 'tool\tcase\titeration\trx_bytes_global\ttx_bytes_global\n' >"$output/network-deltas.tsv"
for tool in dnfast dnf5; do
    for case_name in "${cases[@]}"; do
        for iteration in $(seq 1 "$trials"); do
            read -r before_rx before_tx <"$output/raw/$tool-$case_name-$iteration.net-before"
            read -r after_rx after_tx <"$output/raw/$tool-$case_name-$iteration.net-after"
            printf '%s\t%s\t%s\t%s\t%s\n' "$tool" "$case_name" "$iteration" \
                "$((after_rx - before_rx))" "$((after_tx - before_tx))" \
                >>"$output/network-deltas.tsv"
        done
    done
done

cache_inventory /var/cache/dnfast >"$output/dnfast-cache-after.SHA256SUMS"
cache_inventory /var/cache/libdnf5 >"$output/dnf5-cache-after.SHA256SUMS"
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' \
    | sort >"$output/rpm-inventory-after.tsv"
rpm --verifydb >"$output/rpmdb-after.txt" 2>&1
cmp "$output/rpm-inventory-before.tsv" "$output/rpm-inventory-after.tsv"
cmp "$output/dnfast-cache-before.SHA256SUMS" "$output/dnfast-cache-after.SHA256SUMS"
cmp "$output/dnf5-cache-before.SHA256SUMS" "$output/dnf5-cache-after.SHA256SUMS"
if systemctl is-active --quiet dnfastd.service; then
    echo "dnfastd became active during the daemonless comparison" >&2
    exit 1
fi
