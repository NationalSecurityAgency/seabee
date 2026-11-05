#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Measures SeaBee overhead on system calls that reach SeaBee hooks, and log loss under audit load.
# See docs/docs/performance.md.
#
# Requirements: run as root from the repository root after `make install-release`,
# `make gen-root-key-ci` and `make install-root-key`; stress-ng and gcc installed;
# SeaBee not running.
#
# Usage: sudo bash scripts/benchmark.sh [seconds per stressor (default 20)] [runs (default 3)]
set -e

SECONDS_PER=${1:-20}
RUNS=${2:-3}
STRESSORS="open fork exec kill chmod rename"
WORK=/tmp/seabee-bench
OUT=$WORK/results
SEABEE=/usr/sbin/seabee
ROOT_KEY=seabee-root-private-key.pem

if [ "$EUID" -ne 0 ]; then
  echo "run as root"
  exit 1
fi
for f in "$SEABEE" "$ROOT_KEY" "$(command -v stress-ng)" "$(command -v gcc)"; do
  if [ ! -e "$f" ]; then
    echo "missing: $f"
    exit 1
  fi
done

rm -rf "$WORK"
mkdir -p "$WORK/protected" "$WORK/audit" "$OUT"
chmod 1777 "$WORK" "$WORK/protected"

# median bogo ops/s (real time) of one stressor over RUNS runs
# runs as nobody, since stress-ng skips the exec stressor as root
run_stressor() {
  local name=$1 dir=$2
  for _ in $(seq "$RUNS"); do
    rm -f "$WORK/s.yaml"
    runuser -u nobody -- stress-ng --"$name" 1 --timeout "${SECONDS_PER}s" --temp-path "$dir" \
      --metrics-brief --yaml "$WORK/s.yaml" >/dev/null 2>&1
    awk '/bogo-ops-per-second-real-time/ {print $2}' "$WORK/s.yaml"
  done | sort -n | awk '{v[NR]=$1} END {print v[int((NR+1)/2)]}'
}

run_all() {
  local label=$1 dir=$2
  for s in $STRESSORS; do
    echo "$label $s $(run_stressor "$s" "$dir")" | tee -a "$OUT/stressors.txt"
  done
}

start_seabee() {
  "$SEABEE" --sigint true >"$OUT/seabee-$1.log" 2>&1 &
  SEABEE_PID=$!
  for _ in $(seq 30); do
    seabeectl list >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "SeaBee did not start"
  exit 1
}

stop_seabee() {
  kill -INT "$SEABEE_PID"
  wait "$SEABEE_PID" || true
}

add_policy() {
  local yaml=$1
  seabeectl sign -t "$yaml" -k "$ROOT_KEY" -o "$yaml.sign" --nopass >/dev/null
  seabeectl update -t "$yaml" -s "$yaml.sign" >/dev/null
}

# 1. no SeaBee
run_all none "$WORK"

# 2. SeaBee running, no policy: hooks run, objects are unlabeled
start_seabee nopolicy
run_all seabee "$WORK"
stop_seabee

# 3. stress-ng in the scope of a policy, working in a protected directory:
#    every process and file it creates is labeled
cat >"$WORK/bench_policy.yaml" <<YAML
name: benchmark-policy
version: 1
scope:
  - $(command -v stress-ng)
files:
  - $WORK/protected
config:
  file_write_access: block
  map_access: block
  ptrace_access: block
  signal_access: block
YAML
start_seabee policy
add_policy "$WORK/bench_policy.yaml"
run_all policy "$WORK/protected"
stop_seabee
seabeectl clean policy >/dev/null

# 4. log loss: N audited writes from an unlabeled process
cat >"$WORK/writer.c" <<'C'
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
	long n = atol(argv[2]);
	long delay_us = argc > 3 ? atol(argv[3]) : 0;
	for (long i = 0; i < n; i++) {
		int fd = open(argv[1], O_WRONLY);
		if (fd >= 0)
			close(fd);
		if (delay_us)
			usleep(delay_us);
	}
	return 0;
}
C
gcc -O2 -o "$WORK/writer" "$WORK/writer.c"
touch "$WORK/audit/audited_file"
cat >"$WORK/audit_policy.yaml" <<YAML
name: benchmark-audit-policy
version: 1
scope:
  - /nonexistent/benchmark/scope
files:
  - $WORK/audit/audited_file
config:
  file_write_access: audit
YAML
for spec in "100000 0" "1000000 0" "100000 10"; do
  read -r n delay <<<"$spec"
  set -- "$n" "$delay"
  start_seabee "audit-$1-$2"
  add_policy "$WORK/audit_policy.yaml"
  start=$(date +%s.%N)
  "$WORK/writer" "$WORK/audit/audited_file" "$1" "$2"
  end=$(date +%s.%N)
  sleep 5
  stop_seabee
  seabeectl clean policy >/dev/null
  # each audited open is logged twice: by file_open and by inode_permission
  logged=$(grep -c "file_access: audit" "$OUT/seabee-audit-$1-$2.log" || true)
  echo "writes $1 delay_us $2 seconds $(echo "$end - $start" | bc) expected $(($1 * 2)) logged $logged" |
    tee -a "$OUT/logloss.txt"
done

echo "results in $OUT"
