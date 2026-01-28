//! ACL serialization using rkyv for zero-copy binary format.
//!
//! This module provides binary serialization for POSIX ACL entries,
//! replacing the previous JSON-based serialization.

use rkyv::{Archive, Deserialize, Serialize};

/// ACL entry kind (mirrors exacl::AclEntryKind)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(u8)]
pub enum AclEntryKind {
    User = 0,
    Group = 1,
    Other = 2,
    Mask = 3,
    /// NFSv4 "everyone" special identifier
    Everyone = 4,
    /// Unknown/unsupported entry type
    Unknown = 255,
}

impl From<exacl::AclEntryKind> for AclEntryKind {
    fn from(kind: exacl::AclEntryKind) -> Self {
        use exacl::AclEntryKind as E;
        match kind {
            E::User => AclEntryKind::User,
            E::Group => AclEntryKind::Group,
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            E::Other => AclEntryKind::Other,
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            E::Mask => AclEntryKind::Mask,
            #[cfg(target_os = "freebsd")]
            E::Everyone => AclEntryKind::Everyone,
            E::Unknown => AclEntryKind::Unknown,
            // Catch-all for platform-specific variants not available on this platform
            #[allow(unreachable_patterns)]
            _ => AclEntryKind::Unknown,
        }
    }
}

impl From<AclEntryKind> for exacl::AclEntryKind {
    fn from(kind: AclEntryKind) -> Self {
        use exacl::AclEntryKind as E;
        match kind {
            AclEntryKind::User => E::User,
            AclEntryKind::Group => E::Group,
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            AclEntryKind::Other => E::Other,
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            AclEntryKind::Mask => E::Mask,
            #[cfg(target_os = "freebsd")]
            AclEntryKind::Everyone => E::Everyone,
            // Fallback for variants not available on this platform
            _ => E::Unknown,
        }
    }
}

/// Permission flags for ACL entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct AclPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl From<exacl::Perm> for AclPerms {
    fn from(perm: exacl::Perm) -> Self {
        Self {
            read: perm.contains(exacl::Perm::READ),
            write: perm.contains(exacl::Perm::WRITE),
            execute: perm.contains(exacl::Perm::EXECUTE),
        }
    }
}

impl From<AclPerms> for exacl::Perm {
    fn from(perms: AclPerms) -> Self {
        let mut p = exacl::Perm::empty();
        if perms.read {
            p |= exacl::Perm::READ;
        }
        if perms.write {
            p |= exacl::Perm::WRITE;
        }
        if perms.execute {
            p |= exacl::Perm::EXECUTE;
        }
        p
    }
}

/// NFSv4 ACL flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct AclFlags {
    pub bits: u32,
}

impl From<exacl::Flag> for AclFlags {
    fn from(flag: exacl::Flag) -> Self {
        Self { bits: flag.bits() }
    }
}

impl From<AclFlags> for exacl::Flag {
    fn from(flags: AclFlags) -> Self {
        exacl::Flag::from_bits_truncate(flags.bits)
    }
}

/// A single ACL entry (mirrors exacl::AclEntry)
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct AclEntry {
    pub kind: AclEntryKind,
    /// User or group name (empty for UserObj/GroupObj/Other/Mask)
    pub name: String,
    pub perms: AclPerms,
    pub flags: AclFlags,
    /// NFSv4: true for allow, false for deny
    pub allow: bool,
}

impl From<&exacl::AclEntry> for AclEntry {
    fn from(entry: &exacl::AclEntry) -> Self {
        Self {
            kind: entry.kind.into(),
            name: entry.name.clone(),
            perms: entry.perms.into(),
            flags: entry.flags.into(),
            allow: entry.allow,
        }
    }
}

impl From<&AclEntry> for exacl::AclEntry {
    fn from(entry: &AclEntry) -> Self {
        Self {
            kind: entry.kind.into(),
            name: entry.name.clone(),
            perms: entry.perms.into(),
            flags: entry.flags.into(),
            allow: entry.allow,
        }
    }
}

/// Collection of ACL entries for serialization
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct AclData {
    pub entries: Vec<AclEntry>,
}

impl AclData {
    /// Create from exacl entries
    pub fn from_exacl(entries: &[exacl::AclEntry]) -> Self {
        Self {
            entries: entries.iter().map(AclEntry::from).collect(),
        }
    }

    /// Convert back to exacl entries
    pub fn to_exacl(&self) -> Vec<exacl::AclEntry> {
        self.entries.iter().map(exacl::AclEntry::from).collect()
    }

    /// Serialize to bytes using rkyv
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        rkyv::to_bytes::<_, 256>(self).ok().map(|v| v.to_vec())
    }

    /// Deserialize from bytes using rkyv
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let archived = rkyv::check_archived_root::<Self>(data).ok()?;
        let deserialized: Self = archived.deserialize(&mut rkyv::Infallible).ok()?;
        Some(deserialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl_roundtrip() {
        let acl_data = AclData {
            entries: vec![
                AclEntry {
                    kind: AclEntryKind::User,
                    name: "testuser".to_string(),
                    perms: AclPerms {
                        read: true,
                        write: true,
                        execute: false,
                    },
                    flags: AclFlags { bits: 0 },
                    allow: true,
                },
                AclEntry {
                    kind: AclEntryKind::Group,
                    name: "testgroup".to_string(),
                    perms: AclPerms {
                        read: true,
                        write: false,
                        execute: false,
                    },
                    flags: AclFlags { bits: 0 },
                    allow: true,
                },
            ],
        };

        let bytes = acl_data.to_bytes().expect("serialization failed");
        let restored = AclData::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(restored.entries.len(), 2);
        assert_eq!(restored.entries[0].name, "testuser");
        assert_eq!(restored.entries[1].name, "testgroup");
    }
}
