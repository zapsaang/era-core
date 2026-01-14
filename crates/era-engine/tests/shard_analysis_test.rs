//! Analyze shard distribution for fault tolerance

#[test]
fn test_shard_distribution_analysis() {
    println!("\n=== SHARD DISTRIBUTION ANALYSIS FOR MATRIX ===\n");
    
    let configs = vec![
        (3, 4, 2, "3 volumes vs 6 shards"),
        (4, 4, 2, "4 volumes vs 6 shards"),
        (6, 4, 2, "6 volumes vs 6 shards"),
        (8, 4, 2, "8 volumes vs 6 shards"),
    ];

    for (volume_count, data_shards, parity_shards, label) in configs {
        let total_shards = data_shards + parity_shards;
        println!("Configuration: {} ({} total shards)", label, total_shards);
        
        // Analyze which shards go to which volumes
        for block_seq in 0..3 {
            let mut vol_shards: Vec<Vec<usize>> = vec![Vec::new(); volume_count];
            
            for shard_idx in 0..total_shards {
                let vol_idx = (shard_idx + block_seq) % volume_count;
                vol_shards[vol_idx].push(shard_idx);
            }
            
            println!("  Block {}: {:?}", block_seq, vol_shards);
        }

        // Analyze losing volumes
        println!("  Fault tolerance analysis:");
        for volumes_to_lose in 1..volume_count {
            let remaining = volume_count - volumes_to_lose;
            
            // In worst case, which volumes do we lose?
            // Calculate minimum shards we could have
            let mut min_shards = remaining * total_shards;
            min_shards /= volume_count;
            
            let can_recover = min_shards >= data_shards;
            let status = if can_recover { "✅" } else { "❌" };
            
            println!("    Lose {} volumes → {} remain → ~{} shards → {}",
                volumes_to_lose, remaining, min_shards, status);
        }
        println!();
    }
}
