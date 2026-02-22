# acube Performance Benchmark Results

## Environment

- **Date**: 2026-02-22 13:09:03
- **OS**: Darwin 24.6.0 arm64
- **CPU**: Apple M4
- **Rust**: rustc 1.93.1 (01f6ddf75 2026-02-11)

## Configuration

- Duration: 10s per test
- Concurrency: 50 connections
- Warmup: 3s at 10 connections

## Results

### GET /health

| Server | Requests/sec | Avg Latency (s) | p50 (s) | p99 (s) | Ratio vs raw axum |
|--------|-------------|-----------------|---------|---------|-------------------|
| raw axum (3001) | 209166 | 0.000238 | 0.000217 | 0.000678 | baseline |
| acube minimal (3002) | 189603 | 0.000263 | 0.000250 | 0.000574 | 90.6% |
| acube full (3003) | 174181 | 0.000286 | 0.000262 | 0.000711 | 83.3% |

### POST /tasks (JWT + Validation + Rate Limit)

| Server | Requests/sec | Avg Latency (s) | p50 (s) | p99 (s) |
|--------|-------------|-----------------|---------|---------|
| acube full (3003) | 159588 | 0.000312 | 0.000277 | 0.001001 |

## Acceptance Criteria

- [x] acube minimal / raw axum >= 90% throughput (actual: 90.6%)
- [x] acube full (health) / raw axum >= 70% throughput (actual: 83.3%)
