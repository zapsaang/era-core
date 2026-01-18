//! Integration and performance tests: validate real-world effectiveness of
//! the k-Bounded Best-Fit packing algorithm.
//!
//! These tests collect realistic data to compare the legacy vs new packing
//! strategies. Scenarios are based on actual data characteristics rather than
//! document assumptions.

#[cfg(test)]
mod tests {
    use crate::StagingPool;
    use bytes::Bytes;
    use era_common::{ChunkHash, UniqueChunk};
    use std::time::Instant;

    fn make_chunk(size: usize, id: u8) -> UniqueChunk {
        UniqueChunk::new(Bytes::from(vec![id; size]), ChunkHash::from_bytes([id; 32]))
    }

    // ========== Legacy strategy simulation ==========
    /// Simulate the legacy "simple fill" packing strategy
    struct SimplePacking {
        target_size: usize,
        current_block_chunks: Vec<UniqueChunk>,
        current_block_size: usize,
        blocks: Vec<Vec<UniqueChunk>>,
        total_chunks_added: usize,
    }

    impl SimplePacking {
        fn new(target_size: usize) -> Self {
            Self {
                target_size,
                current_block_chunks: Vec::new(),
                current_block_size: 0,
                blocks: Vec::new(),
                total_chunks_added: 0,
            }
        }

        fn add_chunk(&mut self, chunk: UniqueChunk) {
            let chunk_size = chunk.data.len();
            self.total_chunks_added += 1;

            // Oversized chunk gets its own block
            if chunk_size >= self.target_size {
                self.blocks.push(vec![chunk]);
                return;
            }

            // Check whether a flush is needed
            if self.current_block_size + chunk_size > self.target_size {
                // Flush current block
                if !self.current_block_chunks.is_empty() {
                    self.blocks
                        .push(std::mem::take(&mut self.current_block_chunks));
                    self.current_block_size = 0;
                }
            }

            // Add to current block
            self.current_block_chunks.push(chunk);
            self.current_block_size += chunk_size;
        }

        fn finalize(&mut self) {
            if !self.current_block_chunks.is_empty() {
                self.blocks
                    .push(std::mem::take(&mut self.current_block_chunks));
                self.current_block_size = 0;
            }
        }

        fn stats(&self) -> PackingStats {
            let mut total_size = 0;
            let mut block_utilizations = Vec::new();

            for block in &self.blocks {
                let block_size: usize = block.iter().map(|c| c.data.len()).sum();
                total_size += block_size;

                let utilization = (block_size as f64 / self.target_size as f64) * 100.0;
                block_utilizations.push(utilization);
            }

            let avg_utilization = if block_utilizations.is_empty() {
                0.0
            } else {
                block_utilizations.iter().sum::<f64>() / block_utilizations.len() as f64
            };

            let total_wasted = self.blocks.len() * self.target_size - total_size;

            PackingStats {
                block_count: self.blocks.len(),
                avg_utilization_percent: avg_utilization,
                total_wasted_bytes: total_wasted,
                waste_percent: (total_wasted as f64
                    / (self.blocks.len() * self.target_size) as f64)
                    * 100.0,
            }
        }
    }

    #[derive(Debug, Clone)]
    struct PackingStats {
        block_count: usize,
        avg_utilization_percent: f64,
        total_wasted_bytes: usize,
        waste_percent: f64,
    }

    impl PackingStats {
        fn compare_with(&self, other: &PackingStats) -> ComparisonResult {
            ComparisonResult {
                block_reduction_count: self.block_count - other.block_count,
                waste_reduction_bytes: self.total_wasted_bytes - other.total_wasted_bytes,
                waste_reduction_percent: self.waste_percent - other.waste_percent,
                utilization_improvement: other.avg_utilization_percent
                    - self.avg_utilization_percent,
            }
        }
    }

    #[derive(Debug)]
    struct ComparisonResult {
        block_reduction_count: usize,
        waste_reduction_bytes: usize,
        waste_reduction_percent: f64,
        utilization_improvement: f64,
    }

    // ========== Scenario 1: mixed small files (Git repo) ==========
    #[test]
    fn test_scenario_small_files_git_repo() {
        println!("\n=== 场景1: 小文件混合（类似Git仓库） ===");

        let target_size = 4 * 1024 * 1024; // 4MB
        let mut chunks = Vec::new();

        // Generate a typical Git-repo chunk distribution (all chunks << target_size)
        // Config files (< 1KB)
        for i in 0..200 {
            chunks.push(make_chunk(256 + (i % 512), (i % 256) as u8));
        }
        // Source code (1KB - 50KB)
        for i in 200..600 {
            chunks.push(make_chunk(1024 + ((i * 7) % 49152), (i % 256) as u8));
        }
        // Small binaries (50KB - 200KB)
        for i in 600..800 {
            chunks.push(make_chunk(
                50 * 1024 + ((i * 11) % 150 * 1024),
                (i % 256) as u8,
            ));
        }

        println!("  生成的chunk数: {}", chunks.len());
        println!(
            "  总大小: {:.2} MB",
            chunks.iter().map(|c| c.data.len()).sum::<usize>() as f64 / 1024.0 / 1024.0
        );

        // Legacy strategy
        let mut simple = SimplePacking::new(target_size);
        for chunk in chunks.iter() {
            simple.add_chunk(chunk.clone());
        }
        simple.finalize();
        let simple_stats = simple.stats();

        // New strategy
        let mut pool = StagingPool::new(8, target_size);
        let mut best_fit_blocks = Vec::new();
        for chunk in chunks.iter() {
            if let Some(packed) = pool.push(chunk.clone()) {
                best_fit_blocks.push(packed);
            }
        }
        for packed in pool.flush_all() {
            best_fit_blocks.push(packed);
        }

        let best_fit_stats = PackingStats {
            block_count: best_fit_blocks.len(),
            avg_utilization_percent: best_fit_blocks
                .iter()
                .map(|b| (b.total_size as f64 / target_size as f64) * 100.0)
                .sum::<f64>()
                / best_fit_blocks.len().max(1) as f64,
            total_wasted_bytes: best_fit_blocks.len() * target_size
                - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>(),
            waste_percent: {
                let wasted = best_fit_blocks.len() * target_size
                    - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>();
                (wasted as f64 / (best_fit_blocks.len() * target_size) as f64) * 100.0
            },
        };

        println!("\n旧策略结果:");
        println!("  块数: {}", simple_stats.block_count);
        println!("  平均填充率: {:.2}%", simple_stats.avg_utilization_percent);
        println!(
            "  浪费空间: {} MB ({:.2}%)",
            simple_stats.total_wasted_bytes / 1024 / 1024,
            simple_stats.waste_percent
        );

        println!("\n新策略结果:");
        println!("  块数: {}", best_fit_stats.block_count);
        println!(
            "  平均填充率: {:.2}%",
            best_fit_stats.avg_utilization_percent
        );
        println!(
            "  浪费空间: {} MB ({:.2}%)",
            best_fit_stats.total_wasted_bytes / 1024 / 1024,
            best_fit_stats.waste_percent
        );

        let comp = simple_stats.compare_with(&best_fit_stats);
        println!("\n改进对比:");
        println!(
            "  块数减少: {} (-{:.1}%)",
            comp.block_reduction_count,
            (comp.block_reduction_count as f64 / simple_stats.block_count as f64) * 100.0
        );
        println!(
            "  浪费空间减少: {} MB ({:.2}%)",
            comp.waste_reduction_bytes / 1024 / 1024,
            comp.waste_reduction_percent
        );
        println!("  填充率提升: {:.2}%", comp.utilization_improvement);

        // In this scenario, the new strategy should be no worse
        assert!(
            best_fit_stats.avg_utilization_percent >= simple_stats.avg_utilization_percent * 0.99,
            "新策略应该有相同或更好的填充率"
        );
    }

    // ========== Scenario 2: uniform sizes ==========
    #[test]
    fn test_scenario_uniform_sizes() {
        println!("\n=== 场景2: 均匀大小chunk ==========");

        let target_size = 4 * 1024 * 1024;
        let chunk_size = 512 * 1024; // 512KB
        let chunk_count = 100;

        let chunks: Vec<_> = (0..chunk_count)
            .map(|i| make_chunk(chunk_size, (i % 256) as u8))
            .collect();

        println!("  chunk数: {}", chunks.len());
        println!("  单个chunk大小: {} KB", chunk_size / 1024);
        println!(
            "  总大小: {:.2} MB",
            (chunk_size * chunk_count) as f64 / 1024.0 / 1024.0
        );

        // Legacy strategy
        let mut simple = SimplePacking::new(target_size);
        for chunk in chunks.iter() {
            simple.add_chunk(chunk.clone());
        }
        simple.finalize();
        let simple_stats = simple.stats();

        // New strategy
        let mut pool = StagingPool::new(8, target_size);
        let mut best_fit_blocks = Vec::new();
        for chunk in chunks.iter() {
            if let Some(packed) = pool.push(chunk.clone()) {
                best_fit_blocks.push(packed);
            }
        }
        for packed in pool.flush_all() {
            best_fit_blocks.push(packed);
        }

        let best_fit_stats = PackingStats {
            block_count: best_fit_blocks.len(),
            avg_utilization_percent: best_fit_blocks
                .iter()
                .map(|b| (b.total_size as f64 / target_size as f64) * 100.0)
                .sum::<f64>()
                / best_fit_blocks.len().max(1) as f64,
            total_wasted_bytes: best_fit_blocks.len() * target_size
                - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>(),
            waste_percent: {
                let wasted = best_fit_blocks.len() * target_size
                    - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>();
                (wasted as f64 / (best_fit_blocks.len() * target_size) as f64) * 100.0
            },
        };

        println!("\n旧策略结果:");
        println!("  块数: {}", simple_stats.block_count);
        println!("  平均填充率: {:.2}%", simple_stats.avg_utilization_percent);
        println!(
            "  浪费空间: {} MB ({:.2}%)",
            simple_stats.total_wasted_bytes / 1024 / 1024,
            simple_stats.waste_percent
        );

        println!("\n新策略结果:");
        println!("  块数: {}", best_fit_stats.block_count);
        println!(
            "  平均填充率: {:.2}%",
            best_fit_stats.avg_utilization_percent
        );
        println!(
            "  浪费空间: {} MB ({:.2}%)",
            best_fit_stats.total_wasted_bytes / 1024 / 1024,
            best_fit_stats.waste_percent
        );

        let comp = simple_stats.compare_with(&best_fit_stats);
        println!("\n改进对比:");
        println!(
            "  块数减少: {} (-{:.1}%)",
            comp.block_reduction_count,
            (comp.block_reduction_count as f64 / simple_stats.block_count as f64) * 100.0
        );
        println!(
            "  浪费空间减少: {} MB ({:.2}%)",
            comp.waste_reduction_bytes / 1024 / 1024,
            comp.waste_reduction_percent
        );
        println!("  填充率提升: {:.2}%", comp.utilization_improvement);
    }

    // ========== Scenario 3: extreme mix (large + many small files) ==========
    #[test]
    fn test_scenario_extreme_mix() {
        println!("\n=== 场景3: 极端混合（大文件+很多小文件） ==========");

        let target_size = 4 * 1024 * 1024;
        let mut chunks = Vec::new();

        // One 2MB file
        chunks.push(make_chunk(2 * 1024 * 1024, 1));

        // 10,000 small files (512B - 8KB)
        for i in 0..10000 {
            let size = 512 + (i % 8192);
            chunks.push(make_chunk(size, (i % 256) as u8));
        }

        // Five 100KB files
        for i in 0..5 {
            chunks.push(make_chunk(100 * 1024, (i + 10) as u8));
        }

        println!("  chunk数: {}", chunks.len());
        println!(
            "  总大小: {:.2} MB",
            chunks.iter().map(|c| c.data.len()).sum::<usize>() as f64 / 1024.0 / 1024.0
        );

        // Legacy strategy
        let start = Instant::now();
        let mut simple = SimplePacking::new(target_size);
        for chunk in chunks.iter() {
            simple.add_chunk(chunk.clone());
        }
        simple.finalize();
        let simple_time = start.elapsed();
        let simple_stats = simple.stats();

        // New strategy
        let start = Instant::now();
        let mut pool = StagingPool::new(8, target_size);
        let mut best_fit_blocks = Vec::new();
        for chunk in chunks.iter() {
            if let Some(packed) = pool.push(chunk.clone()) {
                best_fit_blocks.push(packed);
            }
        }
        for packed in pool.flush_all() {
            best_fit_blocks.push(packed);
        }
        let best_fit_time = start.elapsed();

        let best_fit_stats = PackingStats {
            block_count: best_fit_blocks.len(),
            avg_utilization_percent: best_fit_blocks
                .iter()
                .map(|b| (b.total_size as f64 / target_size as f64) * 100.0)
                .sum::<f64>()
                / best_fit_blocks.len().max(1) as f64,
            total_wasted_bytes: best_fit_blocks.len() * target_size
                - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>(),
            waste_percent: {
                let wasted = best_fit_blocks.len() * target_size
                    - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>();
                (wasted as f64 / (best_fit_blocks.len() * target_size) as f64) * 100.0
            },
        };

        println!("\n旧策略结果:");
        println!("  块数: {}", simple_stats.block_count);
        println!("  平均填充率: {:.2}%", simple_stats.avg_utilization_percent);
        println!(
            "  浪费空间: {} MB ({:.2}%)",
            simple_stats.total_wasted_bytes / 1024 / 1024,
            simple_stats.waste_percent
        );
        println!("  处理时间: {:.2} ms", simple_time.as_secs_f64() * 1000.0);

        println!("\n新策略结果:");
        println!("  块数: {}", best_fit_stats.block_count);
        println!(
            "  平均填充率: {:.2}%",
            best_fit_stats.avg_utilization_percent
        );
        println!(
            "  浪费空间: {} MB ({:.2}%)",
            best_fit_stats.total_wasted_bytes / 1024 / 1024,
            best_fit_stats.waste_percent
        );
        println!("  处理时间: {:.2} ms", best_fit_time.as_secs_f64() * 1000.0);

        let comp = simple_stats.compare_with(&best_fit_stats);
        println!("\n改进对比:");
        println!(
            "  块数减少: {} (-{:.1}%)",
            comp.block_reduction_count,
            (comp.block_reduction_count as f64 / simple_stats.block_count as f64) * 100.0
        );
        println!(
            "  浪费空间减少: {} MB ({:.2}%)",
            comp.waste_reduction_bytes / 1024 / 1024,
            comp.waste_reduction_percent
        );
        println!("  填充率提升: {:.2}%", comp.utilization_improvement);
        println!(
            "  速度差异: {:.2}% (新算法相对旧算法)",
            ((best_fit_time.as_secs_f64() - simple_time.as_secs_f64()) / simple_time.as_secs_f64())
                * 100.0
        );
    }

    // ========== Scenario 4: impact of k ==========
    #[test]
    fn test_k_value_impact() {
        println!("\n=== 场景4: k值对装箱效果的影响 ==========");

        let target_size = 4 * 1024 * 1024;
        let mut chunks = Vec::new();

        // Generate 1,000 chunks sized 1KB-100KB
        for i in 0..1000 {
            let size = 1024 + (i % 99 * 1024);
            chunks.push(make_chunk(size, (i % 256) as u8));
        }

        println!("  测试chunk数: {}", chunks.len());
        println!(
            "  总大小: {:.2} MB",
            chunks.iter().map(|c| c.data.len()).sum::<usize>() as f64 / 1024.0 / 1024.0
        );

        for k in [2, 4, 8, 16, 32] {
            let mut pool = StagingPool::new(k, target_size);
            let mut blocks = Vec::new();

            for chunk in chunks.iter() {
                if let Some(packed) = pool.push(chunk.clone()) {
                    blocks.push(packed);
                }
            }
            for packed in pool.flush_all() {
                blocks.push(packed);
            }

            let avg_util = blocks
                .iter()
                .map(|b| (b.total_size as f64 / target_size as f64) * 100.0)
                .sum::<f64>()
                / blocks.len().max(1) as f64;

            let wasted =
                blocks.len() * target_size - blocks.iter().map(|b| b.total_size).sum::<usize>();
            let waste_percent = (wasted as f64 / (blocks.len() * target_size) as f64) * 100.0;

            println!(
                "  k={}: 块数={}, 填充率={:.2}%, 浪费={:.2}%",
                k,
                blocks.len(),
                avg_util,
                waste_percent
            );
        }
    }

    // ========== Scenario 5: impact of flush threshold ==========
    #[test]
    fn test_flush_threshold_impact() {
        println!("\n=== 场景5: 刷新阈值对效果的影响 ==========");

        let target_size = 4 * 1024 * 1024;
        let mut chunks = Vec::new();

        // Generate 500 chunks sized 100KB-500KB
        for i in 0..500 {
            let size = 100 * 1024 + (i % 400 * 1024);
            chunks.push(make_chunk(size, (i % 256) as u8));
        }

        println!("  测试chunk数: {}", chunks.len());
        println!(
            "  总大小: {:.2} MB",
            chunks.iter().map(|c| c.data.len()).sum::<usize>() as f64 / 1024.0 / 1024.0
        );

        for threshold in [70, 80, 90, 95, 99] {
            let mut pool = StagingPool::new(8, target_size).with_flush_threshold(threshold);
            let mut blocks = Vec::new();

            for chunk in chunks.iter() {
                if let Some(packed) = pool.push(chunk.clone()) {
                    blocks.push(packed);
                }
            }
            for packed in pool.flush_all() {
                blocks.push(packed);
            }

            let avg_util = blocks
                .iter()
                .map(|b| (b.total_size as f64 / target_size as f64) * 100.0)
                .sum::<f64>()
                / blocks.len().max(1) as f64;

            let wasted =
                blocks.len() * target_size - blocks.iter().map(|b| b.total_size).sum::<usize>();
            let waste_percent = (wasted as f64 / (blocks.len() * target_size) as f64) * 100.0;

            println!(
                "  阈值={}%: 块数={}, 填充率={:.2}%, 浪费={:.2}%",
                threshold,
                blocks.len(),
                avg_util,
                waste_percent
            );
        }
    }

    // ========== Combined performance test ==========
    #[test]
    fn test_comprehensive_performance() {
        println!("\n=== 综合性能测试 ==========");

        let scenarios = vec![
            (
                "小文件",
                vec![
                    (1024, 100),      // 100 x 1KB files
                    (10 * 1024, 50),  // 50 x 10KB files
                    (100 * 1024, 10), // 10 x 100KB files
                ],
            ),
            (
                "中等文件",
                vec![
                    (500 * 1024, 100),     // 100 x 500KB files
                    (1024 * 1024, 50),     // 50 x 1MB files
                    (2 * 1024 * 1024, 20), // 20 x 2MB files
                ],
            ),
        ];

        let target_size = 4 * 1024 * 1024;

        for (scenario_name, spec) in scenarios {
            println!("\n  场景: {}", scenario_name);

            let mut chunks = Vec::new();
            let mut total_size = 0;

            for (size, count) in spec {
                for i in 0..count {
                    chunks.push(make_chunk(size, ((i * 7) % 256) as u8));
                    total_size += size;
                }
            }

            println!(
                "    Chunk数: {}, 总大小: {:.2} MB",
                chunks.len(),
                total_size as f64 / 1024.0 / 1024.0
            );

            // Legacy strategy
            let mut simple = SimplePacking::new(target_size);
            for chunk in chunks.iter() {
                simple.add_chunk(chunk.clone());
            }
            simple.finalize();
            let simple_stats = simple.stats();

            // New strategy
            let mut pool = StagingPool::new(8, target_size);
            let mut best_fit_blocks = Vec::new();
            for chunk in chunks.iter() {
                if let Some(packed) = pool.push(chunk.clone()) {
                    best_fit_blocks.push(packed);
                }
            }
            for packed in pool.flush_all() {
                best_fit_blocks.push(packed);
            }

            let best_fit_stats = PackingStats {
                block_count: best_fit_blocks.len(),
                avg_utilization_percent: best_fit_blocks
                    .iter()
                    .map(|b| (b.total_size as f64 / target_size as f64) * 100.0)
                    .sum::<f64>()
                    / best_fit_blocks.len().max(1) as f64,
                total_wasted_bytes: {
                    if !best_fit_blocks.is_empty() {
                        best_fit_blocks.len() * target_size
                            - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>()
                    } else {
                        0
                    }
                },
                waste_percent: {
                    if !best_fit_blocks.is_empty() {
                        let wasted = best_fit_blocks.len() * target_size
                            - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>();
                        (wasted as f64 / (best_fit_blocks.len() * target_size) as f64) * 100.0
                    } else {
                        0.0
                    }
                },
            };

            println!(
                "    旧策略: 块数={}, 填充率={:.2}%, 浪费={:.2}%",
                simple_stats.block_count,
                simple_stats.avg_utilization_percent,
                simple_stats.waste_percent
            );

            println!(
                "    新策略: 块数={}, 填充率={:.2}%, 浪费={:.2}%",
                best_fit_stats.block_count,
                best_fit_stats.avg_utilization_percent,
                best_fit_stats.waste_percent
            );

            let improvement = (best_fit_stats.avg_utilization_percent
                - simple_stats.avg_utilization_percent)
                / simple_stats.avg_utilization_percent
                * 100.0;
            println!("    填充率提升: {:.2}%", improvement);
        }
    }
}
