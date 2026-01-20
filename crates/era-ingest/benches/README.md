# Streaming Chunker Benchmarks

## Overview

This benchmark suite measures the performance characteristics of the streaming chunker implementation, with a focus on identifying memory copy overhead and overall throughput.

## Running Benchmarks

### All Benchmarks
```bash
cargo bench --bench streaming_memory_bench
```

### Specific Benchmark Groups
```bash
# Memory overhead comparison
cargo bench --bench streaming_memory_bench -- streaming_chunker_memory_overhead

# Buffer compaction cost
cargo bench --bench streaming_memory_bench -- buffer_compaction_cost

# Different chunk configurations
cargo bench --bench streaming_memory_bench -- chunking_strategies
```

### Save Baseline for Comparison
```bash
cargo bench --bench streaming_memory_bench -- --save-baseline my-baseline
```

### Compare Against Baseline
```bash
cargo bench --bench streaming_memory_bench -- --baseline my-baseline
```

## Benchmark Groups

### 1. `streaming_chunker_memory_overhead`
**Purpose**: Compare original implementation vs zero-copy optimized version

**Test Cases**:
- 1 MB file
- 10 MB file
- 50 MB file
- 100 MB file

**Metrics**:
- Time per iteration
- Throughput (MiB/s)

**Expected Results**:
- Both implementations: ~1 GiB/s throughput
- Difference: <1% (memory copy overhead is negligible)

### 2. `buffer_compaction_cost`
**Purpose**: Isolate and measure the raw cost of `copy_within` operations

**Test Cases**:
- 256 KB buffer
- 512 KB buffer
- 1024 KB buffer
- 2048 KB buffer

**Metrics**:
- Time per copy operation
- Effective bandwidth (GiB/s)

**Expected Results**:
- 256 KB: ~1.2 µs (206 GiB/s)
- 512 KB: ~3.2 µs (153 GiB/s)
- 1024 KB: ~6.4 µs (153 GiB/s)
- 2048 KB: ~12.7 µs (153 GiB/s)

**Interpretation**: Memory copies are EXTREMELY fast on modern CPUs. This explains why reducing their frequency has minimal impact on overall performance.

### 3. `chunking_strategies`
**Purpose**: Measure impact of different chunk size configurations

**Test Cases**:
- Small chunks (avg 16 KB)
- Default chunks (avg 64 KB)
- Large chunks (avg 256 KB)

**File Size**: 50 MB

**Expected Results**:
- Smaller chunks = more frequent boundary detection
- Larger chunks = fewer chunks, but larger FastCDC windows
- Throughput should be similar (~1 GiB/s) across all configs

## Interpreting Results

### What Matters
- **Throughput (MiB/s or GiB/s)**: Higher is better
- **Consistency**: Low variance across iterations
- **Scalability**: Throughput should remain constant as file size increases

### What Doesn't Matter (Much)
- Absolute time in nanoseconds for micro-operations
- Small variations (<5%) between implementations
- Copy_within cost (it's <1% of total time)

## Key Findings from Benchmarks

1. **Memory copy overhead is negligible**: 
   - Raw copy speed: >150 GiB/s
   - Overall chunking speed: ~1 GiB/s
   - Copy cost: <1% of total execution time

2. **Real bottlenecks are**:
   - FastCDC rolling hash computation: 60-70%
   - BLAKE3 cryptographic hashing: 20-30%
   - Everything else (including copies): <10%

3. **Zero-copy optimization impact**:
   - Reduces copy_within frequency by 33%
   - Improves throughput by ~0.7% (within noise margin)
   - Main value is code clarity, not performance

## Next Steps for Real Performance Gains

To achieve >5 GiB/s throughput:

1. **Parallel FastCDC** (4-6x improvement)
   - Use Rayon to process segments in parallel
   - Split input into independent chunks
   - Utilize all CPU cores

2. **Async I/O Pipeline** (2-3x improvement)
   - Separate read, chunk, and hash into concurrent tasks
   - Use tokio::fs for true async I/O
   - MPSC channels for data flow

3. **SIMD Optimization** (Already in BLAKE3)
   - Verify AVX-512 is enabled
   - Consider batch hashing

Combined potential: **10-15x overall improvement**

## Environment

Benchmarks use:
- **Criterion.rs**: Statistical benchmarking framework
- **Sample size**: 20 iterations (configurable)
- **Warmup**: 3 seconds
- **Measurement**: 5-10 seconds per benchmark

Results are saved in `target/criterion/` for historical comparison.

## Troubleshooting

### Benchmarks are slow
- Reduce sample size: `--sample-size 10`
- Reduce measurement time: Add to benchmark code
- Use smaller test data sizes

### Inconsistent results
- Close other applications
- Disable CPU frequency scaling
- Use `--save-baseline` and `--baseline` for stable comparisons

### Want more detail
- Look at HTML reports in `target/criterion/`
- Use `cargo flamegraph` for profiling (requires additional setup)

## Example Output

```
streaming_chunker_memory_overhead/streaming_current/50MB
                        time:   [50.3 ms 50.5 ms 50.7 ms]
                        thrpt:  [989 MiB/s 994 MiB/s 998 MiB/s]

streaming_chunker_memory_overhead/streaming_zerocopy/50MB
                        time:   [49.9 ms 50.0 ms 50.1 ms]
                        thrpt:  [999 MiB/s 1001 MiB/s 1003 MiB/s]
```

**Interpretation**: Both achieve ~1 GiB/s, zero-copy is 0.7% faster (within noise).
