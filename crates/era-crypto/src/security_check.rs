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

    // Guard Pages
    if report.guard_pages_available {
        eprintln!("✅ Guard Pages: Available");
        eprintln!("   Protection against buffer overflows (Heartbleed-style attacks)");
        eprintln!("   Page Size: {} bytes", report.page_size);
    } else {
        eprintln!("❌ Guard Pages: NOT Available");
        eprintln!("   ⚠️  WARNING: System vulnerable to buffer overflow attacks");
        eprintln!("   Recommendation: Use a platform with mprotect/VirtualProtect support");
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
    if report.guard_pages_available && report.mlock_available {
        eprintln!("✅ Overall Security: EXCELLENT");
        eprintln!("   All security features are available and functioning");
    } else if report.guard_pages_available || report.mlock_available {
        eprintln!("⚠️  Overall Security: PARTIAL");
        eprintln!("   Some security features missing - acceptable for non-critical use");
    } else {
        eprintln!("❌ Overall Security: POOR");
        eprintln!("   Platform lacks critical security features");
        eprintln!("   NOT RECOMMENDED for production use with sensitive data");
    }

    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

/// Check if guard pages are available and warn if not
pub fn verify_guard_pages_or_warn() -> bool {
    let report = check_security_features();

    if !report.guard_pages_available {
        eprintln!("⚠️  WARNING: Guard Pages NOT available on this platform!");
        eprintln!("   Platform: {}", report.platform);
        eprintln!("   Risk: Buffer overflow attacks may succeed");
        eprintln!("   Recommendation: Use Linux/macOS/Windows for production");
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
    fn test_verify_guard_pages() {
        let result = verify_guard_pages_or_warn();

        // On unix/windows should be true
        #[cfg(any(unix, windows))]
        assert!(result);

        // On other platforms should be false
        #[cfg(not(any(unix, windows)))]
        assert!(!result);
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
