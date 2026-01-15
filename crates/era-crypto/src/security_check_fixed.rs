//! Runtime security features check
//!
//! This module provides utilities to check which security features
//! are available on the current platform at runtime.

use crate::secure_memory::check_security_features;

/// Print a security features report to stderr
pub fn print_security_report() {
    let report = check_security_features();

    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  ERA Crypto Security Features Report");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("Platform: {}", report.platform);
    eprintln!();

    // Zeroize Allocator
    if report.zeroize_alloc_enabled {
        eprintln!("✅ Zeroize Allocator: Enabled");
        eprintln!("   Automatic secure memory cleanup on deallocation");
    } else {
        eprintln!("❌ Zeroize Allocator: Disabled");
        eprintln!("   ⚠️  WARNING: Memory may not be securely erased");
    }
    eprintln!();

    // Memory Locking
    if report.mlock_available {
        eprintln!("✅ Memory Locking: Available");
        eprintln!("   Protection against swap-to-disk (prevents key leakage)");
        #[cfg(unix)]
        eprintln!("   Implementation: mlock(2)");
        #[cfg(windows)]
        eprintln!("   Implementation: VirtualLock");
    } else {
        eprintln!("❌ Memory Locking: NOT Available");
        eprintln!("   ⚠️  WARNING: Keys may be swapped to disk");
        eprintln!("   Recommendation: Upgrade to a platform with mlock/VirtualLock");
    }
    eprintln!();

    // Overall assessment
    if report.zeroize_alloc_enabled && report.mlock_available {
        eprintln!("✅ Overall Security: EXCELLENT");
        eprintln!("   All security features are available and functioning");
    } else if report.zeroize_alloc_enabled || report.mlock_available {
        eprintln!("⚠️  Overall Security: GOOD");
        eprintln!("   Core security features available");
    } else {
        eprintln!("❌ Overall Security: REDUCED");
        eprintln!("   Platform lacks some security features");
        eprintln!("   NOT RECOMMENDED for production use with sensitive data");
    }

    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

/// Check if zeroize allocator is enabled and warn if not
pub fn verify_security_or_warn() -> bool {
    let report = check_security_features();

    if !report.zeroize_alloc_enabled {
        eprintln!("⚠️  WARNING: Zeroize Allocator NOT enabled!");
        eprintln!("   Platform: {}", report.platform);
        eprintln!("   Risk: Memory may not be securely erased after use");
        eprintln!("   Recommendation: Ensure zeroize-alloc dependency is enabled");
        return false;
    }

    true
}

/// Check if memory locking is available and warn if not
pub fn verify_mlock_or_warn() -> bool {
    let report = check_security_features();

    if !report.mlock_available {
        eprintln!("⚠️  WARNING: Memory Locking NOT available on this platform!");
        eprintln!("   Platform: {}", report.platform);
        eprintln!("   Risk: Cryptographic keys may be swapped to disk");
        eprintln!("   Recommendation: Use a platform with mlock/VirtualLock support");
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_report() {
        // Should not panic
        print_security_report();
    }

    #[test]
    fn test_verify_security() {
        // Just verify it doesn't panic
        let _result = verify_security_or_warn();
    }

    #[test]
    fn test_verify_mlock() {
        let result = verify_mlock_or_warn();

        #[cfg(any(unix, windows))]
        assert!(result);

        #[cfg(not(any(unix, windows)))]
        assert!(!result);
    }
}
