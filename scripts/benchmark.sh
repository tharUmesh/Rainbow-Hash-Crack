#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  benchmark.sh  —  Automated timing sweep for all HPC cracker implementations
#
#  Usage:
#    chmod +x scripts/benchmark.sh
#    ./scripts/benchmark.sh <password> <length>
#
#  Example:
#    ./scripts/benchmark.sh "ab3" 3
#
#  Output:
#    results/benchmark_<timestamp>.csv
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Arguments ────────────────────────────────────────────────────────────────
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <password_to_crack> <password_length>"
    exit 1
fi

PASSWORD="$1"
LENGTH="$2"
TARGET_HASH=$(echo -n "$PASSWORD" | sha256sum | awk '{print $1}')

echo "Password   : $PASSWORD"
echo "Length     : $LENGTH"
echo "SHA-256    : $TARGET_HASH"
echo ""

# ── Output setup ─────────────────────────────────────────────────────────────
RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CSV="$RESULTS_DIR/benchmark_${TIMESTAMP}.csv"

echo "implementation,param_label,param_value,time_ms,found" > "$CSV"

BINDIR="./bin"

# ── Helper: extract timing from program output ────────────────────────────────
extract_time() {
    # Looks for: "Execution Time: 123 ms"
    grep -oP 'Execution Time: \K[0-9]+' <<< "$1" || echo "N/A"
}

extract_found() {
    grep -qi "SUCCESS" <<< "$1" && echo "yes" || echo "no"
}

# ── 1. Serial (single run — baseline) ────────────────────────────────────────
echo "── Running serial baseline..."
if [[ -x "$BINDIR/serial_cracker" ]]; then
    OUTPUT=$("$BINDIR/serial_cracker" "$LENGTH" "$TARGET_HASH" 2>&1)
    TIME=$(extract_time "$OUTPUT")
    FOUND=$(extract_found "$OUTPUT")
    echo "serial,threads,1,$TIME,$FOUND" >> "$CSV"
    echo "  serial → ${TIME} ms  (found: $FOUND)"
else
    echo "  [SKIP] serial_cracker not built"
fi

# ── 2. POSIX Threads (sweep thread counts) ───────────────────────────────────
echo "── Running pthreads sweep..."
THREAD_COUNTS=(1 2 4 8 16)
if [[ -x "$BINDIR/pthreads_cracker" ]]; then
    for T in "${THREAD_COUNTS[@]}"; do
        OUTPUT=$("$BINDIR/pthreads_cracker" "$LENGTH" "$TARGET_HASH" "$T" 2>&1)
        TIME=$(extract_time "$OUTPUT")
        FOUND=$(extract_found "$OUTPUT")
        echo "pthreads,threads,$T,$TIME,$FOUND" >> "$CSV"
        echo "  pthreads t=$T → ${TIME} ms  (found: $FOUND)"
    done
else
    echo "  [SKIP] pthreads_cracker not built"
fi

# ── 3. MPI (sweep process counts) ────────────────────────────────────────────
echo "── Running MPI sweep..."
MPI_COUNTS=(2 4 8)
if [[ -x "$BINDIR/mpi_cracker" ]]; then
    for P in "${MPI_COUNTS[@]}"; do
        OUTPUT=$(mpirun -np "$P" "$BINDIR/mpi_cracker" "$LENGTH" "$TARGET_HASH" 2>&1)
        TIME=$(extract_time "$OUTPUT")
        FOUND=$(extract_found "$OUTPUT")
        echo "mpi,processes,$P,$TIME,$FOUND" >> "$CSV"
        echo "  mpi np=$P → ${TIME} ms  (found: $FOUND)"
    done
else
    echo "  [SKIP] mpi_cracker not built"
fi

# ── 4. Hybrid MPI+CUDA ───────────────────────────────────────────────────────
echo "── Running hybrid sweep..."
HYBRID_COUNTS=(2 4)
if [[ -x "$BINDIR/hybrid_cracker" ]]; then
    for P in "${HYBRID_COUNTS[@]}"; do
        OUTPUT=$(mpirun -np "$P" "$BINDIR/hybrid_cracker" "$LENGTH" "$TARGET_HASH" 2>&1)
        TIME=$(extract_time "$OUTPUT")
        FOUND=$(extract_found "$OUTPUT")
        echo "hybrid,processes,$P,$TIME,$FOUND" >> "$CSV"
        echo "  hybrid np=$P → ${TIME} ms  (found: $FOUND)"
    done
else
    echo "  [SKIP] hybrid_cracker not built"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "Results saved to: $CSV"
