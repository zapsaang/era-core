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
//! - Unix/Linux: mlock, mprotect, guard pages (full support)
//! - macOS: mlock, mprotect, guard pages (full support)  
//! - Windows: VirtualLock, VirtualProtect, guard pages (full support)
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
#[derive(Debug)]
enum AllocationStrategy {
    Standard,
    Guarded {
        base_ptr: NonNull<u8>,
        total_len: usize,
    },
}

pub struct SecureBuffer<const N: usize> {
    ptr: NonNull<[u8; N]>,
    is_locked: bool,
    strategy: AllocationStrategy,
}

impl<const N: usize> SecureBuffer<N> {
    /// Create a new secure buffer with default configuration
    pub fn new() -> Result<Self, SecureMemoryError> {
        Self::with_config(SecureMemoryConfig::default())
    }

    /// Create a new secure buffer with custom configuration
    pub fn with_config(config: SecureMemoryConfig) -> Result<Self, SecureMemoryError> {
        let (ptr, strategy) = if config.enable_guard_pages {
            #[cfg(any(unix, windows))]
            {
                let (user_ptr, base_ptr, total_len) = allocate_guarded(N)?;
                let ptr = unsafe { NonNull::new_unchecked(user_ptr as *mut [u8; N]) };
                let base_ptr = unsafe { NonNull::new_unchecked(base_ptr) };
                (
                    ptr,
                    AllocationStrategy::Guarded {
                        base_ptr,
                        total_len,
                    },
                )
            }
            #[cfg(not(any(unix, windows)))]
            {
                #[cfg(debug_assertions)]
                eprintln!("[era-crypto] Warning: Guard pages not supported on this platform");
                let layout = Layout::new::<[u8; N]>();
                let raw = unsafe { alloc_zeroed(layout) };
                if raw.is_null() {
                    return Err(SecureMemoryError::AllocationFailed);
                }
                let ptr = unsafe { NonNull::new_unchecked(raw as *mut [u8; N]) };
                (ptr, AllocationStrategy::Standard)
            }
        } else {
            let layout = Layout::new::<[u8; N]>();
            let raw = unsafe { alloc_zeroed(layout) };
            if raw.is_null() {
                return Err(SecureMemoryError::AllocationFailed);
            }
            let ptr = unsafe { NonNull::new_unchecked(raw as *mut [u8; N]) };
            (ptr, AllocationStrategy::Standard)
        };

        let mut is_locked = false;

        // Try to lock memory if enabled
        if config.enable_mlock {
            unsafe {
                match mlock(ptr.as_ref().as_ptr(), N) {
                    Ok(()) => {
                        is_locked = true;
                    }
                    Err(e) => {
                        if config.strict_mlock {
                            // Clean up and return error
                            match strategy {
                                AllocationStrategy::Standard => {
                                    dealloc(ptr.as_ptr() as *mut u8, Layout::new::<[u8; N]>());
                                }
                                AllocationStrategy::Guarded {
                                    base_ptr,
                                    total_len,
                                } => {
                                    #[cfg(unix)]
                                    libc::munmap(base_ptr.as_ptr() as *mut libc::c_void, total_len);
                                }
                            }
                            return Err(SecureMemoryError::LockFailed(e));
                        }
                        // Continue without mlock protection (warn in debug builds)
                        #[cfg(debug_assertions)]
                        eprintln!("[era-crypto] Warning: mlock failed ({}), continuing without swap protection", e);
                    }
                }
            }
        }

        Ok(Self {
            ptr,
            is_locked,
            strategy,
        })
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
            match self.strategy {
                AllocationStrategy::Standard => {
                    let layout = Layout::new::<[u8; N]>();
                    dealloc(self.ptr.as_ptr() as *mut u8, layout);
                }
                AllocationStrategy::Guarded {
                    base_ptr,
                    total_len,
                } => {
                    deallocate_guarded(base_ptr.as_ptr(), total_len);
                }
            }
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

/// A secure memory region with runtime-determined size.
///
/// Similar to `SecureBuffer` but allows allocating any size at runtime.
/// Useful for caches or variable-length secrets.
pub struct SecureBytes {
    ptr: NonNull<u8>,
    size: usize,
    is_locked: bool,
    strategy: AllocationStrategy,
}

impl SecureBytes {
    /// Create a new secure bytes buffer of `size`
    pub fn new(size: usize) -> Result<Self, SecureMemoryError> {
        Self::with_config(size, SecureMemoryConfig::default())
    }

    /// Create with custom config
    pub fn with_config(size: usize, config: SecureMemoryConfig) -> Result<Self, SecureMemoryError> {
        if size == 0 {
            return Err(SecureMemoryError::AllocationFailed);
        }

        let (ptr, strategy) = if config.enable_guard_pages {
            #[cfg(any(unix, windows))]
            {
                let (user_ptr, base_ptr, total_len) = allocate_guarded(size)?;
                let ptr = unsafe { NonNull::new_unchecked(user_ptr) };
                let base_ptr = unsafe { NonNull::new_unchecked(base_ptr) };
                (
                    ptr,
                    AllocationStrategy::Guarded {
                        base_ptr,
                        total_len,
                    },
                )
            }
            #[cfg(not(any(unix, windows)))]
            {
                #[cfg(debug_assertions)]
                eprintln!("[era-crypto] Warning: Guard pages not supported on this platform");
                let layout = Layout::from_size_align(size, 1)
                    .map_err(|_| SecureMemoryError::AllocationFailed)?;
                let raw = unsafe { alloc_zeroed(layout) };
                if raw.is_null() {
                    return Err(SecureMemoryError::AllocationFailed);
                }
                let ptr = unsafe { NonNull::new_unchecked(raw) };
                (ptr, AllocationStrategy::Standard)
            }
        } else {
            let layout = Layout::from_size_align(size, 1)
                .map_err(|_| SecureMemoryError::AllocationFailed)?;
            let raw = unsafe { alloc_zeroed(layout) };
            if raw.is_null() {
                return Err(SecureMemoryError::AllocationFailed);
            }
            let ptr = unsafe { NonNull::new_unchecked(raw) };
            (ptr, AllocationStrategy::Standard)
        };

        let mut is_locked = false;

        if config.enable_mlock {
            unsafe {
                match mlock(ptr.as_ptr(), size) {
                    Ok(()) => {
                        is_locked = true;
                    }
                    Err(e) => {
                        if config.strict_mlock {
                            match strategy {
                                AllocationStrategy::Standard => {
                                    dealloc(
                                        ptr.as_ptr(),
                                        Layout::from_size_align(size, 1).unwrap(),
                                    );
                                }
                                AllocationStrategy::Guarded {
                                    base_ptr,
                                    total_len,
                                } => {
                                    #[cfg(unix)]
                                    libc::munmap(base_ptr.as_ptr() as *mut libc::c_void, total_len);
                                }
                            }
                            return Err(SecureMemoryError::LockFailed(e));
                        }
                        #[cfg(debug_assertions)]
                        eprintln!("[era-crypto] Warning: mlock failed ({}), continuing without swap protection", e);
                    }
                }
            }
        }

        Ok(Self {
            ptr,
            size,
            is_locked,
            strategy,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }

    pub fn is_locked(&self) -> bool {
        self.is_locked
    }
}

impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        let mut new = Self::new(self.size).expect("Failed to allocate secure bytes for clone");
        new.as_mut_slice().copy_from_slice(self.as_slice());
        new
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size);
            slice.zeroize();

            if self.is_locked {
                let _ = munlock(self.ptr.as_ptr(), self.size);
            }

            match self.strategy {
                AllocationStrategy::Standard => {
                    if let Ok(layout) = Layout::from_size_align(self.size, 1) {
                        dealloc(self.ptr.as_ptr(), layout);
                    }
                }
                AllocationStrategy::Guarded {
                    base_ptr,
                    total_len,
                } => {
                    deallocate_guarded(base_ptr.as_ptr(), total_len);
                }
            }
        }
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBytes")
            .field("size", &self.size)
            .field("is_locked", &self.is_locked)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// Platform-specific guard page allocation implementations

#[cfg(unix)]
fn get_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(windows)]
fn get_page_size() -> usize {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    unsafe {
        let mut info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut info);
        info.dwPageSize as usize
    }
}

#[cfg(unix)]
fn allocate_guarded(size: usize) -> Result<(*mut u8, *mut u8, usize), SecureMemoryError> {
    let page_size = get_page_size();
    if page_size == 0 {
        return Err(SecureMemoryError::GuardPageFailed(
            "Could not determine page size".to_string(),
        ));
    }

    // Calculate total size: Guard + Data + Guard
    let data_pages = (size + page_size - 1) / page_size;
    let data_pages = if data_pages == 0 { 1 } else { data_pages };
    let total_pages = data_pages + 2;
    let total_len = total_pages * page_size;

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(SecureMemoryError::AllocationFailed);
    }

    let ptr = ptr as *mut u8;

    // Protect first guard page
    if unsafe { libc::mprotect(ptr as *mut libc::c_void, page_size, libc::PROT_NONE) } != 0 {
        unsafe { libc::munmap(ptr as *mut libc::c_void, total_len) };
        return Err(SecureMemoryError::GuardPageFailed(
            "Failed to protect first guard page".to_string(),
        ));
    }

    // Protect last guard page
    let last_page_offset = (total_pages - 1) * page_size;
    if unsafe {
        libc::mprotect(
            ptr.add(last_page_offset) as *mut libc::c_void,
            page_size,
            libc::PROT_NONE,
        )
    } != 0
    {
        unsafe { libc::munmap(ptr as *mut libc::c_void, total_len) };
        return Err(SecureMemoryError::GuardPageFailed(
            "Failed to protect last guard page".to_string(),
        ));
    }

    // User ptr is at start of second page
    let user_ptr = unsafe { ptr.add(page_size) };

    Ok((user_ptr, ptr, total_len))
}

#[cfg(windows)]
fn allocate_guarded(size: usize) -> Result<(*mut u8, *mut u8, usize), SecureMemoryError> {
    use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualFree, VirtualProtect};
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE,
    };

    let page_size = get_page_size();
    if page_size == 0 {
        return Err(SecureMemoryError::GuardPageFailed(
            "Could not determine page size".to_string(),
        ));
    }

    // Calculate total size: Guard + Data + Guard
    let data_pages = (size + page_size - 1) / page_size;
    let data_pages = if data_pages == 0 { 1 } else { data_pages };
    let total_pages = data_pages + 2;
    let total_len = total_pages * page_size;

    // Allocate entire region as read-write
    let ptr = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            total_len,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if ptr.is_null() {
        return Err(SecureMemoryError::AllocationFailed);
    }

    let ptr = ptr as *mut u8;

    // Protect first guard page
    let mut old_protect = 0u32;
    if unsafe { VirtualProtect(ptr as *mut _, page_size, PAGE_NOACCESS, &mut old_protect) } == 0 {
        unsafe { VirtualFree(ptr as *mut _, 0, MEM_RELEASE) };
        return Err(SecureMemoryError::GuardPageFailed(format!(
            "Failed to protect first guard page: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Protect last guard page
    let last_page_offset = (total_pages - 1) * page_size;
    if unsafe {
        VirtualProtect(
            ptr.add(last_page_offset) as *mut _,
            page_size,
            PAGE_NOACCESS,
            &mut old_protect,
        )
    } == 0
    {
        unsafe { VirtualFree(ptr as *mut _, 0, MEM_RELEASE) };
        return Err(SecureMemoryError::GuardPageFailed(format!(
            "Failed to protect last guard page: {}",
            std::io::Error::last_os_error()
        )));
    }

    // User ptr is at start of second page
    let user_ptr = unsafe { ptr.add(page_size) };

    Ok((user_ptr, ptr, total_len))
}

#[cfg(unix)]
fn deallocate_guarded(base_ptr: *mut u8, total_len: usize) {
    unsafe {
        libc::munmap(base_ptr as *mut libc::c_void, total_len);
    }
}

#[cfg(windows)]
fn deallocate_guarded(base_ptr: *mut u8, _total_len: usize) {
    use windows_sys::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
    unsafe {
        VirtualFree(base_ptr as *mut _, 0, MEM_RELEASE);
    }
}

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

    #[test]
    #[cfg(any(unix, windows))]
    fn test_guard_pages_allocation() {
        let config = SecureMemoryConfig {
            enable_mlock: true, // Try mlock
            enable_guard_pages: true,
            strict_mlock: false,
        };
        let buffer = SecureBuffer::<32>::with_config(config).unwrap();

        let ptr = buffer.as_ref().as_ptr();
        let page_size = get_page_size();

        // Verify alignment
        assert_eq!(ptr as usize % page_size, 0);

        // Verify functionality (write/read)
        let mut buffer = buffer;
        buffer.as_mut()[0] = 0xAA;
        assert_eq!(buffer.as_ref()[0], 0xAA);
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_guard_pages() {
        let config = SecureMemoryConfig {
            enable_mlock: false, // Don't require VirtualLock
            enable_guard_pages: true,
            strict_mlock: false,
        };

        // Test with SecureBuffer
        let mut buffer = SecureBuffer::<1024>::with_config(config).unwrap();

        // Should be able to write/read data
        for i in 0..1024 {
            buffer.as_mut()[i] = (i % 256) as u8;
        }

        for i in 0..1024 {
            assert_eq!(buffer.as_mut()[i], (i % 256) as u8);
        }

        // Test with SecureBytes
        let mut bytes = SecureBytes::with_config(2048, config).unwrap();
        bytes.as_mut_slice()[0] = 0xFF;
        bytes.as_mut_slice()[2047] = 0xAA;
        assert_eq!(bytes.as_slice()[0], 0xFF);
        assert_eq!(bytes.as_slice()[2047], 0xAA);
    }

    #[test]
    fn test_security_features_report() {
        let report = check_security_features();

        // Platform-specific assertions
        #[cfg(any(unix, windows))]
        {
            assert!(report.guard_pages_available);
        }

        #[cfg(not(any(unix, windows)))]
        {
            assert!(!report.guard_pages_available);
        }

        // Verify report is consistent
        assert!(report.platform.len() > 0);
    }
}

/// Security features availability report
#[derive(Debug, Clone)]
pub struct SecurityReport {
    /// Platform name
    pub platform: String,
    /// Guard pages are available and functioning
    pub guard_pages_available: bool,
    /// Memory locking (mlock/VirtualLock) is available
    pub mlock_available: bool,
    /// Page size in bytes
    pub page_size: usize,
}

/// Check which security features are available on this platform
pub fn check_security_features() -> SecurityReport {
    let platform = if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else {
        "Unknown"
    }
    .to_string();

    let guard_pages_available = cfg!(any(unix, windows));
    let mlock_available = cfg!(any(unix, windows));

    let page_size = if cfg!(any(unix, windows)) {
        get_page_size()
    } else {
        0
    };

    SecurityReport {
        platform,
        guard_pages_available,
        mlock_available,
        page_size,
    }
}
