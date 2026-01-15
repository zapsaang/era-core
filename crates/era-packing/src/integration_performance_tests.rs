//! 集成测试和性能测试：k-Bounded Best-Fit装箱算法真实效果验证
//!
//! 这些测试收集真实数据，对比旧/新装箱策略的效果
//! 测试场景基于真实的数据特征，不基于文档假设

#[cfg(test)]
mod tests {
    use crate::StagingPool;
    use bytes::Bytes;
    use era_common::{ChunkHash, UniqueChunk};
    use std::time::Instant;

    fn make_chunk(size: usize, id: u8) -> UniqueChunk {
        UniqueChunk::new(Bytes::from(vec![id; size]), ChunkHash::from_bytes([id; 32]))
    }

    // ========== 旧策略模拟 ==========
    /// 模拟旧的"简单填充"装箱策略
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

            // 超大chunk单独成块
            if chunk_size >= self.target_size {
                self.blocks.push(vec![chunk]);
                return;
            }

            // 检查是否需要刷新
            if self.current_block_size + chunk_size > self.target_size {
                // 刷新当前块
                if !self.current_block_chunks.is_empty() {
                    self.blocks
                        .push(std::mem::take(&mut self.current_block_chunks));
                    self.current_block_size = 0;
                }
            }

            // 添加到当前块
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
            let mut total_chunks = 0;
            let mut block_utilizations = Vec::new();

            for block in &self.blocks {
                let block_size: usize = block.iter().map(|c| c.data.len()).sum();
                total_size += block_size;
                total_chunks += block.len();

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
                total_size,
                total_chunks,
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
        #[allow(dead_code)]
        total_size: usize,
        #[allow(dead_code)]
        total_chunks: usize,
        avg_utilization_percent: f64,
        total_wasted_bytes: usize,
        waste_percent: f64,
    }

    impl PackingStats {
        fn compare_with(&self, other: &PackingStats) -> ComparisonResult {
            ComparisonResult {
                block_reduction: (self.block_count as i32 - other.block_count as i32)
                    / self.block_count.max(1) as i32,
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
        #[allow(dead_code)]
        block_reduction: i32,
        block_reduction_count: usize,
        waste_reduction_bytes: usize,
        waste_reduction_percent: f64,
        utilization_improvement: f64,
    }

    // ========== 场景1: 小文件混合（Git仓库） ==========
    #[test]
    fn test_scenario_small_files_git_repo() {
        println!("\n=== 场景1: 小文件混合（类似Git仓库） ===");

        let target_size = 4 * 1024 * 1024; // 4MB
        let mut chunks = Vec::new();

        // 生成典型的Git仓库chunk分布 - 所有chunk都远小于target_size
        // 配置文件 (< 1KB)
        for i in 0..200 {
            chunks.push(make_chunk(256 + (i % 512), (i % 256) as u8));
        }
        // 源代码 (1KB - 50KB)
        for i in 200..600 {
            chunks.push(make_chunk(1024 + ((i * 7) % 49152), (i % 256) as u8));
        }
        // 小二进制 (50KB - 200KB)
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

        // 旧策略
        let mut simple = SimplePacking::new(target_size);
        for chunk in chunks.iter() {
            simple.add_chunk(chunk.clone());
        }
        simple.finalize();
        let simple_stats = simple.stats();

        // 新策略
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
            total_size: best_fit_blocks.iter().map(|b| b.total_size).sum(),
            total_chunks: best_fit_blocks.iter().map(|b| b.chunks.len()).sum(),
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

        // 在这个场景中，新策略至少不会更差
        assert!(
            best_fit_stats.avg_utilization_percent >= simple_stats.avg_utilization_percent * 0.99,
            "新策略应该有相同或更好的填充率"
        );
    }

    // ========== 场景2: 均匀大小 ==========
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

        // 旧策略
        let mut simple = SimplePacking::new(target_size);
        for chunk in chunks.iter() {
            simple.add_chunk(chunk.clone());
        }
        simple.finalize();
        let simple_stats = simple.stats();

        // 新策略
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
            total_size: best_fit_blocks.iter().map(|b| b.total_size).sum(),
            total_chunks: best_fit_blocks.iter().map(|b| b.chunks.len()).sum(),
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

    // ========== 场景3: 极端混合（大文件+很多小文件） ==========
    #[test]
    fn test_scenario_extreme_mix() {
        println!("\n=== 场景3: 极端混合（大文件+很多小文件） ==========");

        let target_size = 4 * 1024 * 1024;
        let mut chunks = Vec::new();

        // 1个2MB文件
        chunks.push(make_chunk(2 * 1024 * 1024, 1));

        // 10000个小文件 (512 - 8KB)
        for i in 0..10000 {
            let size = 512 + (i % 8192);
            chunks.push(make_chunk(size, (i % 256) as u8));
        }

        // 5个100KB文件
        for i in 0..5 {
            chunks.push(make_chunk(100 * 1024, (i + 10) as u8));
        }

        println!("  chunk数: {}", chunks.len());
        println!(
            "  总大小: {:.2} MB",
            chunks.iter().map(|c| c.data.len()).sum::<usize>() as f64 / 1024.0 / 1024.0
        );

        // 旧策略
        let start = Instant::now();
        let mut simple = SimplePacking::new(target_size);
        for chunk in chunks.iter() {
            simple.add_chunk(chunk.clone());
        }
        simple.finalize();
        let simple_time = start.elapsed();
        let simple_stats = simple.stats();

        // 新策略
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
            total_size: best_fit_blocks.iter().map(|b| b.total_size).sum(),
            total_chunks: best_fit_blocks.iter().map(|b| b.chunks.len()).sum(),
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

    // ========== 场景4: k值的影响测试 ==========
    #[test]
    fn test_k_value_impact() {
        println!("\n=== 场景4: k值对装箱效果的影响 ==========");

        let target_size = 4 * 1024 * 1024;
        let mut chunks = Vec::new();

        // 生成1000个chunk，大小1KB-100KB
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

    // ========== 场景5: 不同阈值的影响 ==========
    #[test]
    fn test_flush_threshold_impact() {
        println!("\n=== 场景5: 刷新阈值对效果的影响 ==========");

        let target_size = 4 * 1024 * 1024;
        let mut chunks = Vec::new();

        // 生成500个chunk，大小100KB-500KB
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

    // ========== 综合性能测试 ==========
    #[test]
    fn test_comprehensive_performance() {
        println!("\n=== 综合性能测试 ==========");

        let scenarios = vec![
            (
                "小文件",
                vec![
                    (1024, 100),      // 100个1KB文件
                    (10 * 1024, 50),  // 50个10KB文件
                    (100 * 1024, 10), // 10个100KB文件
                ],
            ),
            (
                "中等文件",
                vec![
                    (500 * 1024, 100),     // 100个500KB文件
                    (1 * 1024 * 1024, 50), // 50个1MB文件
                    (2 * 1024 * 1024, 20), // 20个2MB文件
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

            // 旧策略
            let mut simple = SimplePacking::new(target_size);
            for chunk in chunks.iter() {
                simple.add_chunk(chunk.clone());
            }
            simple.finalize();
            let simple_stats = simple.stats();

            // 新策略
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
                total_size: best_fit_blocks.iter().map(|b| b.total_size).sum(),
                total_chunks: best_fit_blocks.iter().map(|b| b.chunks.len()).sum(),
                avg_utilization_percent: best_fit_blocks
                    .iter()
                    .map(|b| (b.total_size as f64 / target_size as f64) * 100.0)
                    .sum::<f64>()
                    / best_fit_blocks.len().max(1) as f64,
                total_wasted_bytes: {
                    if best_fit_blocks.len() > 0 {
                        best_fit_blocks.len() * target_size
                            - best_fit_blocks.iter().map(|b| b.total_size).sum::<usize>()
                    } else {
                        0
                    }
                },
                waste_percent: {
                    if best_fit_blocks.len() > 0 {
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
