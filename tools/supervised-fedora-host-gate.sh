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
trials=${2:-15}
package=/usr/bin/htop
mkdir -p "$output/raw"
if rpm -q htop >/dev/null 2>&1; then
    echo "htop must be absent so both tools solve the same install" >&2
    exit 2
fi

net_snapshot() {
    awk -F '[: ]+' 'NR > 2 { rx += $3; tx += $11 } END { print rx, tx }' /proc/net/dev
}

daemon_snapshot() {
    systemctl show dnfastd.service \
        -p ActiveState -p MainPID -p MemoryCurrent -p MemoryPeak -p CPUUsageNSec
}

wait_for_daemon() {
    local deadline=$((SECONDS + 30))
    until /usr/bin/dnfast daemon status --json 2>/dev/null \
        | jq -e '.message == "resident_daemon=available"' >/dev/null; do
        if (( SECONDS >= deadline )); then
            echo "dnfastd did not become ready" >&2
            return 1
        fi
        sleep 0.025
    done
}

cache_inventory() {
    local root=$1
    find "$root" -xdev -type f -print0 2>/dev/null \
        | sort -z \
        | xargs -0 -r sha256sum
}

run_dnfast_cold() {
    local iteration=$1
    local prefix="$output/raw/dnfast-cold-$iteration"
    local restart_ns ready_ns done_ns status
    # A faster daemon can otherwise trip systemd's default burst limiter during
    # an intentionally restart-heavy benchmark.  Clearing only the historical
    # failed counter does not change the measured service lifecycle.
    systemctl reset-failed dnfastd.service
    restart_ns=$(date +%s%N)
    systemctl restart dnfastd.service
    wait_for_daemon
    ready_ns=$(date +%s%N)
    daemon_snapshot >"$prefix.daemon-before"
    net_snapshot >"$prefix.net-before"
    set +e
    /usr/bin/time -v -o "$prefix.time" \
        perf stat -x, -o "$prefix.perf.csv" -e task-clock,cpu-clock -- \
        /usr/bin/dnfast --json install --repo fedora --repo updates \
        --assumeno "$package" >"$prefix.stdout" 2>"$prefix.stderr"
    status=$?
    set -e
    done_ns=$(date +%s%N)
    printf '%s\n' "$status" >"$prefix.status"
    printf 'restart_to_ready_ns=%s\nready_to_result_ns=%s\nrestart_to_result_ns=%s\n' \
        "$((ready_ns - restart_ns))" "$((done_ns - ready_ns))" \
        "$((done_ns - restart_ns))" >"$prefix.phases"
    net_snapshot >"$prefix.net-after"
    daemon_snapshot >"$prefix.daemon-after"
    jq -e '.status == "aborted" and (.actions | length) == 2' \
        "$prefix.stdout" >/dev/null
    [[ $status -eq 0 ]]
}

run_dnfast_warm() {
    local iteration=$1
    local prefix="$output/raw/dnfast-warm-$iteration"
    local status
    daemon_snapshot >"$prefix.daemon-before"
    net_snapshot >"$prefix.net-before"
    set +e
    /usr/bin/time -v -o "$prefix.time" \
        perf stat -x, -o "$prefix.perf.csv" -e task-clock,cpu-clock -- \
        /usr/bin/dnfast --json install --repo fedora --repo updates \
        --assumeno "$package" >"$prefix.stdout" 2>"$prefix.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$prefix.status"
    net_snapshot >"$prefix.net-after"
    daemon_snapshot >"$prefix.daemon-after"
    jq -e '.status == "aborted" and (.actions | length) == 2' \
        "$prefix.stdout" >/dev/null
    [[ $status -eq 0 ]]
}

run_dnf5() {
    local iteration=$1
    local prefix="$output/raw/dnf5-cold-$iteration"
    local status
    net_snapshot >"$prefix.net-before"
    set +e
    /usr/bin/time -v -o "$prefix.time" \
        perf stat -x, -o "$prefix.perf.csv" -e task-clock,cpu-clock -- \
        /usr/bin/dnf5 --cacheonly --repo=fedora --repo=updates \
        --setopt=install_weak_deps=True --assumeno install "$package" \
        >"$prefix.stdout" 2>"$prefix.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$prefix.status"
    net_snapshot >"$prefix.net-after"
    grep -q '^ htop ' "$prefix.stdout"
    grep -q '^ hwloc-libs ' "$prefix.stdout"
    [[ $status -eq 1 ]]
}

{
    uname -a
    systemd-detect-virt || true
    lscpu
    findmnt -no SOURCE,FSTYPE,OPTIONS /
    /usr/bin/dnfast --version
    /usr/bin/dnf5 --version
    printf 'package=%s\ntrials=%s\n' "$package" "$trials"
} >"$output/environment.txt" 2>&1
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' \
    | sort >"$output/rpm-inventory-before.tsv"
rpm --verifydb >"$output/rpmdb-before.txt" 2>&1
cache_inventory /var/cache/dnfast >"$output/dnfast-cache-before.SHA256SUMS"
cache_inventory /var/cache/libdnf5 >"$output/dnf5-cache-before.SHA256SUMS"
printf 'iteration\tposition\tcell\n' >"$output/order.tsv"

for iteration in $(seq 1 "$trials"); do
    case $((iteration % 3)) in
        1)
            cells=(dnf5 cold warm)
            ;;
        2)
            cells=(warm dnf5 cold)
            ;;
        0)
            cells=(cold warm dnf5)
            ;;
    esac
    position=0
    for cell in "${cells[@]}"; do
        position=$((position + 1))
        printf '%s\t%s\t%s\n' "$iteration" "$position" "$cell" >>"$output/order.tsv"
        case $cell in
            cold) run_dnfast_cold "$iteration" ;;
            warm) run_dnfast_warm "$iteration" ;;
            dnf5) run_dnf5 "$iteration" ;;
        esac
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
daemon_snapshot >"$output/dnfastd-final.txt"
