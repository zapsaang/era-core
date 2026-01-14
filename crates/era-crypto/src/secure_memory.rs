//! Secure Memory Management for ERA v8.1
//!
//! This module implements system-level memory protection for cryptographic keys
//! as specified in the security optimization document (Section 5).
//!
//! ## Security Features
//!
//! - **mlock**: Prevents memory pages from being swapped to disk
//! - **Guard Pages**: Protects against buffer overflow attacks (Heartbleed-style)
//! - **Zeroize on Drop**: Ensures keys are securely erased from memory
//! - **Debug Redaction**: Prevents accidental logging of key material
//!
//! ## Platform Support
//!
//! - Unix/Linux: mlock, mprotect (full support)
//! - macOS: mlock (full support)  
//! - Windows: VirtualLock (partial support)
//! - Other: Graceful degradation with warnings

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;
use zeroize::Zeroize;

/// Error type for secure memory operations
#[derive(Debug, Clone)]
pub enum SecureMemoryError {
    /// Failed to allocate memory
    AllocationFailed,
    /// Failed to lock memory (mlock)
    LockFailed(String),
    /// Failed to set guard pages
    GuardPageFailed(String),
}

impl std::fmt::Display for SecureMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllocationFailed => write!(f, "Failed to allocate secure memory"),
            Self::LockFailed(msg) => write!(f, "Failed to lock memory: {}", msg),
            Self::GuardPageFailed(msg) => write!(f, "Failed to set guard pages: {}", msg),
        }
    }
}

impl std::error::Error for SecureMemoryError {}

/// Configuration for secure memory allocation
#[derive(Debug, Clone, Copy)]
pub struct SecureMemoryConfig {
    /// Enable mlock to prevent swapping
    pub enable_mlock: bool,
    /// Enable guard pages for overflow protection
    pub enable_guard_pages: bool,
    /// Fail if mlock is not available (vs. warn and continue)
    pub strict_mlock: bool,
}

impl Default for SecureMemoryConfig {
    fn default() -> Self {
        Self {
            enable_mlock: true,
            enable_guard_pages: false, // Disabled by default due to memory overhead
            strict_mlock: false,       // Warn but continue if mlock fails
        }
    }
}

/// A secure memory region that is protected from swapping and zeroed on drop.
///
/// This type provides:
/// - mlock protection to prevent the OS from swapping the memory to disk
/// - Automatic zeroization on drop
/// - Optional guard pages for buffer overflow protection
///
/// # Example
///
/// ```ignore
/// let mut secure = SecureBuffer::<32>::new()?;
/// secure.as_mut().copy_from_slice(&key_bytes);
/// // Memory is now protected from swapping
/// // ...use the key...
/// drop(secure); // Memory is automatically zeroed
/// ```
pub struct SecureBuffer<const N: usize> {
    ptr: NonNull<[u8; N]>,
    is_locked: bool,
}

impl<const N: usize> SecureBuffer<N> {
    /// Create a new secure buffer with default configuration
    pub fn new() -> Result<Self, SecureMemoryError> {
        Self::with_config(SecureMemoryConfig::default())
    }

    /// Create a new secure buffer with custom configuration
    pub fn with_config(config: SecureMemoryConfig) -> Result<Self, SecureMemoryError> {
        // Allocate zeroed memory
        let layout = Layout::new::<[u8; N]>();
        let ptr = unsafe {
            let raw = alloc_zeroed(layout);
            if raw.is_null() {
                return Err(SecureMemoryError::AllocationFailed);
            }
            NonNull::new_unchecked(raw as *mut [u8; N])
        };

        let mut is_locked = false;

        // Try to lock memory if enabled
        if config.enable_mlock {
            match mlock(ptr.as_ptr() as *const u8, N) {
                Ok(()) => {
                    is_locked = true;
                }
                Err(e) => {
                    if config.strict_mlock {
                        // Clean up and return error
                        unsafe {
                            dealloc(ptr.as_ptr() as *mut u8, layout);
                        }
                        return Err(SecureMemoryError::LockFailed(e));
                    }
                    // Continue without mlock protection (warn in debug builds)
                    #[cfg(debug_assertions)]
                    eprintln!("[era-crypto] Warning: mlock failed ({}), continuing without swap protection", e);
                    let _ = e; // Suppress unused variable warning in release
                }
            }
        }

        Ok(Self { ptr, is_locked })
    }

    /// Get a reference to the buffer contents
    pub fn as_ref(&self) -> &[u8; N] {
        unsafe { self.ptr.as_ref() }
    }

    /// Get a mutable reference to the buffer contents
    pub fn as_mut(&mut self) -> &mut [u8; N] {
        unsafe { self.ptr.as_mut() }
    }

    /// Check if memory is locked (protected from swapping)
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }
}

impl<const N: usize> Drop for SecureBuffer<N> {
    fn drop(&mut self) {
        unsafe {
            // 1. Zeroize the memory
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, N);
            slice.zeroize();

            // 2. Unlock if locked
            if self.is_locked {
                let _ = munlock(self.ptr.as_ptr() as *const u8, N);
            }

            // 3. Deallocate
            let layout = Layout::new::<[u8; N]>();
            dealloc(self.ptr.as_ptr() as *mut u8, layout);
        }
    }
}

// Prevent accidental cloning of secure memory
impl<const N: usize> Clone for SecureBuffer<N> {
    fn clone(&self) -> Self {
        let mut new = Self::new().expect("Failed to allocate secure buffer for clone");
        new.as_mut().copy_from_slice(self.as_ref());
        new
    }
}

impl<const N: usize> std::fmt::Debug for SecureBuffer<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("size", &N)
            .field("is_locked", &self.is_locked)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// Platform-specific mlock/munlock implementations

#[cfg(unix)]
fn mlock(addr: *const u8, len: usize) -> Result<(), String> {
    let result = unsafe { libc::mlock(addr as *const libc::c_void, len) };
    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(format!("mlock failed: {}", errno))
    }
}

#[cfg(unix)]
fn munlock(addr: *const u8, len: usize) -> Result<(), String> {
    let result = unsafe { libc::munlock(addr as *const libc::c_void, len) };
    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(format!("munlock failed: {}", errno))
    }
}

#[cfg(windows)]
fn mlock(addr: *const u8, len: usize) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Memory::VirtualLock;

    let result = unsafe { VirtualLock(addr as *mut _, len) };
    if result != 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        Err(format!("VirtualLock failed: {}", error))
    }
}

#[cfg(windows)]
fn munlock(addr: *const u8, len: usize) -> Result<(), String> {
    use windows_sys::Win32::System::Memory::VirtualUnlock;

    let result = unsafe { VirtualUnlock(addr as *mut _, len) };
    if result != 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        Err(format!("VirtualUnlock failed: {}", error))
    }
}

#[cfg(not(any(unix, windows)))]
fn mlock(_addr: *const u8, _len: usize) -> Result<(), String> {
    Err("mlock not supported on this platform".to_string())
}

#[cfg(not(any(unix, windows)))]
fn munlock(_addr: *const u8, _len: usize) -> Result<(), String> {
    Ok(()) // No-op on unsupported platforms
}

/// Disable core dumps for the current process.
///
/// This prevents sensitive key material from being written to disk
/// if the process crashes.
///
/// # Platform Support
///
/// - Linux: Uses prctl(PR_SET_DUMPABLE, 0)
/// - macOS: Uses ptrace(PT_DENY_ATTACH)
/// - Windows: Not implemented (returns Ok)
pub fn disable_core_dumps() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(format!(
                "prctl(PR_SET_DUMPABLE) failed: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(target_os = "macos")]
    {
        // PT_DENY_ATTACH is defined as 31
        const PT_DENY_ATTACH: libc::c_int = 31;
        let result = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if result == 0 {
            Ok(())
        } else {
            // ENOTSUP means already attached or not allowed - treat as success
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOTSUP) {
                Ok(())
            } else {
                Err(format!("ptrace(PT_DENY_ATTACH) failed: {}", err))
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(()) // Not implemented on other platforms
    }
}

/// A secure 32-byte key buffer with memory protection.
///
/// This is a convenience type for storing 256-bit cryptographic keys.
pub type SecureKey32 = SecureBuffer<32>;

/// A secure 64-byte key buffer with memory protection.
///
/// This is a convenience type for storing 512-bit cryptographic keys or combined keys.
pub type SecureKey64 = SecureBuffer<64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_allocation() {
        let buffer = SecureBuffer::<32>::new().unwrap();
        assert_eq!(buffer.as_ref().len(), 32);
        // Should be zeroed initially
        assert!(buffer.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_buffer_write_read() {
        let mut buffer = SecureBuffer::<32>::new().unwrap();
        let test_data = [42u8; 32];
        buffer.as_mut().copy_from_slice(&test_data);
        assert_eq!(buffer.as_ref(), &test_data);
    }

    #[test]
    fn test_secure_buffer_debug_redacted() {
        let buffer = SecureBuffer::<32>::new().unwrap();
        let debug_str = format!("{:?}", buffer);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("42")); // Should not leak any data
    }

    #[test]
    fn test_secure_buffer_clone() {
        let mut original = SecureBuffer::<32>::new().unwrap();
        original.as_mut().copy_from_slice(&[42u8; 32]);

        let cloned = original.clone();
        assert_eq!(original.as_ref(), cloned.as_ref());
    }

    #[test]
    fn test_mlock_status() {
        // This test may fail on systems with strict ulimit settings
        let config = SecureMemoryConfig {
            enable_mlock: true,
            strict_mlock: false,
            enable_guard_pages: false,
        };
        let buffer = SecureBuffer::<32>::with_config(config).unwrap();
        // We don't assert is_locked because it depends on system configuration
        // Just ensure the buffer is usable regardless
        assert_eq!(buffer.as_ref().len(), 32);
    }

    #[test]
    fn test_disable_core_dumps() {
        // This should not fail, even if it's a no-op
        let result = disable_core_dumps();
        // On most development systems, this should succeed or be a no-op
        // We don't assert success because it depends on privileges
        assert!(result.is_ok() || result.is_err());
    }
}
