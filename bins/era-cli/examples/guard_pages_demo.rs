//! Cross-platform Guard Pages demonstration
//!
//! This example demonstrates that Guard Pages work on all major platforms:
//! - Linux (via mmap + mprotect)
//! - macOS (via mmap + mprotect)
//! - Windows (via VirtualAlloc + VirtualProtect)

use era_crypto::{print_security_report, SecureBuffer, SecureMemoryConfig};

fn main() {
    println!("═══════════════════════════════════════════════════════════");
    println!("  ERA - Cross-Platform Guard Pages Demonstration");
    println!("═══════════════════════════════════════════════════════════\n");

    // Print comprehensive security report
    print_security_report();

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Testing Guard Pages Protection");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Test 1: Basic allocation with guard pages
    println!("Test 1: Basic SecureBuffer with Guard Pages");
    let config = SecureMemoryConfig {
        enable_mlock: true,
        enable_guard_pages: true,
        strict_mlock: false,
    };

    match SecureBuffer::<1024>::with_config(config) {
        Ok(mut buffer) => {
            println!("  ✅ Successfully allocated 1KB with guard pages");

            // Write and read data
            for i in 0..1024 {
                buffer.as_mut()[i] = (i % 256) as u8;
            }

            // Verify
            let mut errors = 0;
            for i in 0..1024 {
                if buffer.as_ref()[i] != (i % 256) as u8 {
                    errors += 1;
                }
            }

            if errors == 0 {
                println!("  ✅ Data integrity verified (1024 bytes)");
            } else {
                println!("  ❌ Data corruption detected: {} errors", errors);
            }

            if buffer.is_locked() {
                println!("  ✅ Memory successfully locked (protected from swap)");
            } else {
                println!("  ⚠️  Memory not locked (may swap to disk)");
            }
        }
        Err(e) => {
            println!("  ❌ Failed to allocate: {}", e);
        }
    }

    println!();

    // Test 2: Large allocation (multiple pages)
    println!("Test 2: Large SecureBuffer (64KB)");
    match SecureBuffer::<65536>::with_config(config) {
        Ok(mut buffer) => {
            println!("  ✅ Successfully allocated 64KB with guard pages");

            // Write pattern
            buffer.as_mut()[0] = 0xAA;
            buffer.as_mut()[32767] = 0xBB;
            buffer.as_mut()[65535] = 0xCC;

            // Verify
            if buffer.as_ref()[0] == 0xAA
                && buffer.as_ref()[32767] == 0xBB
                && buffer.as_ref()[65535] == 0xCC
            {
                println!("  ✅ Boundary checks passed");
            } else {
                println!("  ❌ Boundary check failed");
            }
        }
        Err(e) => {
            println!("  ❌ Failed to allocate: {}", e);
        }
    }

    println!();

    // Test 3: Performance comparison
    println!("Test 3: Performance Impact");

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = SecureBuffer::<32>::with_config(SecureMemoryConfig {
            enable_guard_pages: true,
            enable_mlock: false,
            strict_mlock: false,
        });
    }
    let with_guards = start.elapsed();

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = SecureBuffer::<32>::with_config(SecureMemoryConfig {
            enable_guard_pages: false,
            enable_mlock: false,
            strict_mlock: false,
        });
    }
    let without_guards = start.elapsed();

    println!("  With guard pages:    {:?}", with_guards);
    println!("  Without guard pages: {:?}", without_guards);

    let overhead = if without_guards.as_nanos() > 0 {
        ((with_guards.as_nanos() as f64 / without_guards.as_nanos() as f64) - 1.0) * 100.0
    } else {
        0.0
    };

    println!("  Overhead: {:.1}%", overhead);

    if overhead < 10.0 {
        println!("  ✅ Acceptable performance overhead");
    } else {
        println!("  ⚠️  High overhead (consider for high-security scenarios only)");
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Platform-Specific Information");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    #[cfg(target_os = "linux")]
    {
        println!("Platform: Linux");
        println!("  Implementation: mmap + mprotect");
        println!("  Guard Page Mechanism: PROT_NONE pages");
        println!("  Memory Lock: mlock(2)");
        println!("  Status: ✅ Full Support");
    }

    #[cfg(target_os = "macos")]
    {
        println!("Platform: macOS");
        println!("  Implementation: mmap + mprotect");
        println!("  Guard Page Mechanism: PROT_NONE pages");
        println!("  Memory Lock: mlock(2)");
        println!("  Status: ✅ Full Support");
    }

    #[cfg(target_os = "windows")]
    {
        println!("Platform: Windows");
        println!("  Implementation: VirtualAlloc + VirtualProtect");
        println!("  Guard Page Mechanism: PAGE_NOACCESS pages");
        println!("  Memory Lock: VirtualLock");
        println!("  Status: ✅ Full Support");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        println!("Platform: Unknown/Other");
        println!("  Status: ⚠️  Guard Pages not implemented");
        println!("  Fallback: Standard allocation");
    }

    println!("\n═══════════════════════════════════════════════════════════");
    println!("  Demonstration Complete");
    println!("═══════════════════════════════════════════════════════════");
}
