#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  a3 Performance Benchmark: raw axum vs a3 minimal vs a3 full${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

# ─── Check oha ────────────────────────────────────────────────────────────────

if ! command -v oha &>/dev/null; then
    echo -e "${YELLOW}oha not found. Installing via cargo...${NC}"
    cargo install oha
fi

echo -e "${GREEN}oha version:${NC} $(oha --version)"
echo

# ─── Build ────────────────────────────────────────────────────────────────────

echo -e "${GREEN}Building benchmarks in release mode...${NC}"
cargo build --release -p a3-performance-bench 2>&1
echo

# ─── Helpers ──────────────────────────────────────────────────────────────────

RELEASE_DIR="$PROJECT_ROOT/target/release"

wait_for_port() {
    local port=$1
    local max_wait=10
    local waited=0
    while ! curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; do
        sleep 0.2
        waited=$((waited + 1))
        if [ $waited -ge $((max_wait * 5)) ]; then
            echo "ERROR: Server on port $port did not start within ${max_wait}s"
            exit 1
        fi
    done
}

kill_server() {
    local pid=$1
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

# Parse oha JSON output for key metrics
extract_metrics() {
    local json="$1"
    python3 -c "
import sys, json
d = json.loads(sys.argv[1])
rps = d['summary']['requestsPerSec']
avg = d['summary']['average']
p = d.get('latencyPercentiles', {})
p50 = p.get('p50', 0)
p99 = p.get('p99', 0)
print(f'{rps:.0f}|{avg:.6f}|{p50:.6f}|{p99:.6f}')
" "$json"
}

run_bench() {
    local url="$1"
    shift
    local extra_args=("$@")

    echo -e "  ${YELLOW}Warming up...${NC}" >&2
    if [ ${#extra_args[@]} -gt 0 ]; then
        oha -z 3s -c 10 --no-tui "${extra_args[@]}" "$url" >/dev/null 2>&1 || true
    else
        oha -z 3s -c 10 --no-tui "$url" >/dev/null 2>&1 || true
    fi

    echo -e "  ${YELLOW}Measuring (10s, 50 connections)...${NC}" >&2
    if [ ${#extra_args[@]} -gt 0 ]; then
        oha -z 10s -c 50 --no-tui --output-format json "${extra_args[@]}" "$url" 2>/dev/null
    else
        oha -z 10s -c 50 --no-tui --output-format json "$url" 2>/dev/null
    fi
}

# ─── 1. Raw Axum ──────────────────────────────────────────────────────────────

echo -e "${GREEN}[1/3] Starting raw_axum_server (port 3001)...${NC}"
"$RELEASE_DIR/raw_axum_server" &
RAW_PID=$!
wait_for_port 3001

echo -e "${GREEN}  Benchmarking GET /health on raw axum...${NC}"
RAW_HEALTH_JSON=$(run_bench "http://127.0.0.1:3001/health")
RAW_HEALTH=$(extract_metrics "$RAW_HEALTH_JSON")

kill_server $RAW_PID
echo -e "${GREEN}  Done.${NC}"
echo

# ─── 2. a3 Minimal ───────────────────────────────────────────────────────────

echo -e "${GREEN}[2/3] Starting a3_minimal_server (port 3002)...${NC}"
"$RELEASE_DIR/a3_minimal_server" >/dev/null 2>&1 &
MIN_PID=$!
wait_for_port 3002

echo -e "${GREEN}  Benchmarking GET /health on a3 minimal...${NC}"
MIN_HEALTH_JSON=$(run_bench "http://127.0.0.1:3002/health")
MIN_HEALTH=$(extract_metrics "$MIN_HEALTH_JSON")

kill_server $MIN_PID
echo -e "${GREEN}  Done.${NC}"
echo

# ─── 3. a3 Full ──────────────────────────────────────────────────────────────

echo -e "${GREEN}[3/3] Starting a3_full_server (port 3003)...${NC}"
"$RELEASE_DIR/a3_full_server" > /tmp/a3_full_output.txt 2>&1 &
FULL_PID=$!
wait_for_port 3003

# Read JWT token from output
JWT_TOKEN=$(grep 'JWT_TOKEN=' /tmp/a3_full_output.txt | head -1 | cut -d= -f2)
if [ -z "$JWT_TOKEN" ]; then
    echo "ERROR: Could not read JWT token from a3_full_server output"
    kill_server $FULL_PID
    exit 1
fi
echo -e "  ${CYAN}JWT token acquired${NC}"

echo -e "${GREEN}  Benchmarking GET /health on a3 full...${NC}"
FULL_HEALTH_JSON=$(run_bench "http://127.0.0.1:3003/health")
FULL_HEALTH=$(extract_metrics "$FULL_HEALTH_JSON")

echo -e "${GREEN}  Benchmarking POST /tasks on a3 full (JWT + validation)...${NC}"
FULL_TASKS_JSON=$(run_bench "http://127.0.0.1:3003/tasks" \
    -m POST \
    -T "application/json" \
    -d '{"name":"benchmark-task","description":"A task for benchmarking"}' \
    -H "Authorization: Bearer ${JWT_TOKEN}")
FULL_TASKS=$(extract_metrics "$FULL_TASKS_JSON")

kill_server $FULL_PID
rm -f /tmp/a3_full_output.txt
echo -e "${GREEN}  Done.${NC}"
echo

# ─── Results ──────────────────────────────────────────────────────────────────

# Parse individual values
RAW_RPS=$(echo "$RAW_HEALTH" | cut -d'|' -f1)
RAW_AVG=$(echo "$RAW_HEALTH" | cut -d'|' -f2)
RAW_P50=$(echo "$RAW_HEALTH" | cut -d'|' -f3)
RAW_P99=$(echo "$RAW_HEALTH" | cut -d'|' -f4)

MIN_RPS=$(echo "$MIN_HEALTH" | cut -d'|' -f1)
MIN_AVG=$(echo "$MIN_HEALTH" | cut -d'|' -f2)
MIN_P50=$(echo "$MIN_HEALTH" | cut -d'|' -f3)
MIN_P99=$(echo "$MIN_HEALTH" | cut -d'|' -f4)

FULL_H_RPS=$(echo "$FULL_HEALTH" | cut -d'|' -f1)
FULL_H_AVG=$(echo "$FULL_HEALTH" | cut -d'|' -f2)
FULL_H_P50=$(echo "$FULL_HEALTH" | cut -d'|' -f3)
FULL_H_P99=$(echo "$FULL_HEALTH" | cut -d'|' -f4)

FULL_T_RPS=$(echo "$FULL_TASKS" | cut -d'|' -f1)
FULL_T_AVG=$(echo "$FULL_TASKS" | cut -d'|' -f2)
FULL_T_P50=$(echo "$FULL_TASKS" | cut -d'|' -f3)
FULL_T_P99=$(echo "$FULL_TASKS" | cut -d'|' -f4)

# Calculate ratios
MIN_RATIO=$(python3 -c "print(f'{${MIN_RPS}/${RAW_RPS}*100:.1f}%')")
FULL_H_RATIO=$(python3 -c "print(f'{${FULL_H_RPS}/${RAW_RPS}*100:.1f}%')")

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  RESULTS${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo "GET /health"
echo "┌──────────────────┬────────────┬────────────┬────────────┬────────────┬──────────┐"
echo "│ Server           │    Req/s   │  Avg (s)   │  p50 (s)   │  p99 (s)   │  Ratio   │"
echo "├──────────────────┼────────────┼────────────┼────────────┼────────────┼──────────┤"
printf "│ %-16s │ %10s │ %10s │ %10s │ %10s │ %8s │\n" "raw axum" "$RAW_RPS" "$RAW_AVG" "$RAW_P50" "$RAW_P99" "baseline"
printf "│ %-16s │ %10s │ %10s │ %10s │ %10s │ %8s │\n" "a3 minimal" "$MIN_RPS" "$MIN_AVG" "$MIN_P50" "$MIN_P99" "$MIN_RATIO"
printf "│ %-16s │ %10s │ %10s │ %10s │ %10s │ %8s │\n" "a3 full" "$FULL_H_RPS" "$FULL_H_AVG" "$FULL_H_P50" "$FULL_H_P99" "$FULL_H_RATIO"
echo "└──────────────────┴────────────┴────────────┴────────────┴────────────┴──────────┘"
echo
echo "POST /tasks (JWT + Valid<CreateTaskInput> + rate limit)"
echo "┌──────────────────┬────────────┬────────────┬────────────┬────────────┐"
echo "│ Server           │    Req/s   │  Avg (s)   │  p50 (s)   │  p99 (s)   │"
echo "├──────────────────┼────────────┼────────────┼────────────┼────────────┤"
printf "│ %-16s │ %10s │ %10s │ %10s │ %10s │\n" "a3 full" "$FULL_T_RPS" "$FULL_T_AVG" "$FULL_T_P50" "$FULL_T_P99"
echo "└──────────────────┴────────────┴────────────┴────────────┴────────────┘"
echo

# ─── Update RESULTS.md ───────────────────────────────────────────────────────

RESULTS_FILE="$SCRIPT_DIR/RESULTS.md"
DATE=$(date '+%Y-%m-%d %H:%M:%S')
OS_INFO=$(uname -srm)
CPU_INFO=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || lscpu 2>/dev/null | grep 'Model name' | sed 's/.*: *//' || echo "unknown")
RUST_VER=$(rustc --version)

MIN_PASS=$(python3 -c "print('x' if ${MIN_RPS}/${RAW_RPS}>=0.9 else ' ')")
FULL_PASS=$(python3 -c "print('x' if ${FULL_H_RPS}/${RAW_RPS}>=0.7 else ' ')")

cat > "$RESULTS_FILE" << EOF
# a3 Performance Benchmark Results

## Environment

- **Date**: ${DATE}
- **OS**: ${OS_INFO}
- **CPU**: ${CPU_INFO}
- **Rust**: ${RUST_VER}

## Configuration

- Duration: 10s per test
- Concurrency: 50 connections
- Warmup: 3s at 10 connections

## Results

### GET /health

| Server | Requests/sec | Avg Latency (s) | p50 (s) | p99 (s) | Ratio vs raw axum |
|--------|-------------|-----------------|---------|---------|-------------------|
| raw axum (3001) | ${RAW_RPS} | ${RAW_AVG} | ${RAW_P50} | ${RAW_P99} | baseline |
| a3 minimal (3002) | ${MIN_RPS} | ${MIN_AVG} | ${MIN_P50} | ${MIN_P99} | ${MIN_RATIO} |
| a3 full (3003) | ${FULL_H_RPS} | ${FULL_H_AVG} | ${FULL_H_P50} | ${FULL_H_P99} | ${FULL_H_RATIO} |

### POST /tasks (JWT + Validation + Rate Limit)

| Server | Requests/sec | Avg Latency (s) | p50 (s) | p99 (s) |
|--------|-------------|-----------------|---------|---------|
| a3 full (3003) | ${FULL_T_RPS} | ${FULL_T_AVG} | ${FULL_T_P50} | ${FULL_T_P99} |

## Acceptance Criteria

- [${MIN_PASS}] a3 minimal / raw axum >= 90% throughput (actual: ${MIN_RATIO})
- [${FULL_PASS}] a3 full (health) / raw axum >= 70% throughput (actual: ${FULL_H_RATIO})
EOF

echo -e "${GREEN}Results written to ${RESULTS_FILE}${NC}"
