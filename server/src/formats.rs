use object::Object;
use serde::{Deserialize, Serialize};

use crate::errors::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolFormat {
    /// ELF debug info (split .debug file or a full binary), identified by the
    /// GNU build ID note.
    Elf,
    /// Mach-O DWARF (the file inside a dSYM bundle, or a full binary),
    /// identified by its LC_UUID.
    #[serde(rename = "macho")]
    MachO,
    /// Windows PDB, identified by GUID + age (the windbg/symsrv convention).
    Pdb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    /// Lowercase hex identifier: ELF build ID, Mach-O UUID, or PDB GUID+age.
    /// This is the `{id}` in `GET /buildid/{id}/debuginfo`.
    pub id: String,
    pub format: SymbolFormat,
    /// Best-effort architecture label ("x86_64", "aarch64", ...).
    pub arch: Option<String>,
}

const MSF_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

/// Identifies an uploaded symbol file and derives its build identifier. The
/// server derives identifiers itself (rather than trusting the uploader) so
/// that lookups can never be poisoned by a mislabelled upload.
pub fn identify(data: &[u8]) -> Result<SymbolInfo, Error> {
    if data.starts_with(MSF_MAGIC) {
        return identify_pdb(data);
    }

    let file = object::File::parse(data)
        .map_err(|e| Error::UnrecognisedFormat(format!("not a PDB, ELF or Mach-O file: {e}")))?;

    let arch = arch_label(file.architecture());

    match &file {
        object::File::Elf32(_) | object::File::Elf64(_) => {
            let build_id = file
                .build_id()
                .map_err(|e| Error::UnrecognisedFormat(format!("reading ELF build ID: {e}")))?
                .ok_or_else(|| {
                    Error::UnrecognisedFormat(
                        "ELF file carries no GNU build ID note; link with --build-id".to_string(),
                    )
                })?;
            Ok(SymbolInfo {
                id: hex::encode(build_id),
                format: SymbolFormat::Elf,
                arch,
            })
        }
        object::File::MachO32(_) | object::File::MachO64(_) => {
            let uuid = file
                .mach_uuid()
                .map_err(|e| Error::UnrecognisedFormat(format!("reading Mach-O UUID: {e}")))?
                .ok_or_else(|| {
                    Error::UnrecognisedFormat("Mach-O file carries no LC_UUID".to_string())
                })?;
            Ok(SymbolInfo {
                id: hex::encode(uuid),
                format: SymbolFormat::MachO,
                arch,
            })
        }
        _ => Err(Error::UnrecognisedFormat(
            "unsupported object format (expected ELF, Mach-O or PDB)".to_string(),
        )),
    }
}

fn identify_pdb(data: &[u8]) -> Result<SymbolInfo, Error> {
    let cursor = std::io::Cursor::new(data);
    let mut pdb = pdb::PDB::open(cursor)
        .map_err(|e| Error::UnrecognisedFormat(format!("parsing PDB: {e}")))?;
    let info = pdb
        .pdb_information()
        .map_err(|e| Error::UnrecognisedFormat(format!("reading PDB information: {e}")))?;

    // The symsrv identifier is the GUID (32 hex chars) followed by the age in
    // uppercase-free hex with no padding; normalised to lowercase here since
    // ids are case-insensitive lookups on our side.
    let id = format!("{:x}{:x}", info.guid.simple(), info.age);
    Ok(SymbolInfo {
        id,
        format: SymbolFormat::Pdb,
        arch: None,
    })
}

fn arch_label(arch: object::Architecture) -> Option<String> {
    use object::Architecture;
    Some(
        match arch {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
            Architecture::I386 => "i386",
            Architecture::Arm => "arm",
            Architecture::Riscv64 => "riscv64",
            Architecture::Unknown => return None,
            other => return Some(format!("{other:?}").to_lowercase()),
        }
        .to_string(),
    )
}

/// Validates and normalises a build-id path parameter: lowercase hex, bounded
/// length. Anything else is rejected before it can reach storage lookups.
pub fn sanitize_id(id: &str) -> Result<String, Error> {
    if id.len() < 2 || id.len() > 128 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadRequest("invalid build id".to_string()));
    }
    Ok(id.to_ascii_lowercase())
}

/// A minimal but valid ELF carrying a GNU build-id note — shared by tests
/// that need a real identifiable symbol file.
#[cfg(test)]
pub(crate) fn minimal_elf_with_build_id(build_id: &[u8]) -> Vec<u8> {
    tests::minimal_elf_with_build_id(build_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but spec-valid ELF64 (little-endian, aarch64) consisting of
    /// just an ELF header and one PT_NOTE segment holding a GNU build ID.
    pub(crate) fn minimal_elf_with_build_id(build_id: &[u8]) -> Vec<u8> {
        let ehsize = 64u64;
        let phentsize = 56u64;
        let note_off = ehsize + phentsize;

        // Note: namesz=4 ("GNU\0"), descsz=len, type=3 (NT_GNU_BUILD_ID)
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());
        note.extend_from_slice(&(build_id.len() as u32).to_le_bytes());
        note.extend_from_slice(&3u32.to_le_bytes());
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(build_id);
        while note.len() % 4 != 0 {
            note.push(0);
        }

        let mut out = Vec::new();
        // ELF header
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]); // magic, 64-bit, LE, current
        out.extend_from_slice(&[0; 8]); // padding
        out.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        out.extend_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        out.extend_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        out.extend_from_slice(&0u64.to_le_bytes()); // entry
        out.extend_from_slice(&ehsize.to_le_bytes()); // phoff
        out.extend_from_slice(&0u64.to_le_bytes()); // shoff
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&(ehsize as u16).to_le_bytes()); // ehsize
        out.extend_from_slice(&(phentsize as u16).to_le_bytes()); // phentsize
        out.extend_from_slice(&1u16.to_le_bytes()); // phnum
        out.extend_from_slice(&0u16.to_le_bytes()); // shentsize
        out.extend_from_slice(&0u16.to_le_bytes()); // shnum
        out.extend_from_slice(&0u16.to_le_bytes()); // shstrndx
        assert_eq!(out.len(), ehsize as usize);

        // PT_NOTE program header
        out.extend_from_slice(&4u32.to_le_bytes()); // PT_NOTE
        out.extend_from_slice(&4u32.to_le_bytes()); // flags (R)
        out.extend_from_slice(&note_off.to_le_bytes()); // offset
        out.extend_from_slice(&note_off.to_le_bytes()); // vaddr
        out.extend_from_slice(&note_off.to_le_bytes()); // paddr
        out.extend_from_slice(&(note.len() as u64).to_le_bytes()); // filesz
        out.extend_from_slice(&(note.len() as u64).to_le_bytes()); // memsz
        out.extend_from_slice(&4u64.to_le_bytes()); // align

        out.extend_from_slice(&note);
        out
    }

    /// A minimal Mach-O 64-bit (arm64) header with a single LC_UUID command.
    fn minimal_macho_with_uuid(uuid: [u8; 16]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xfeedfacfu32.to_le_bytes()); // MH_MAGIC_64
        out.extend_from_slice(&0x0100000cu32.to_le_bytes()); // CPU_TYPE_ARM64
        out.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        out.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        out.extend_from_slice(&1u32.to_le_bytes()); // ncmds
        out.extend_from_slice(&24u32.to_le_bytes()); // sizeofcmds
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        // LC_UUID
        out.extend_from_slice(&0x1bu32.to_le_bytes());
        out.extend_from_slice(&24u32.to_le_bytes());
        out.extend_from_slice(&uuid);
        out
    }

    #[test]
    fn identifies_elf_build_ids() {
        let build_id = [0xacu8, 0xc4, 0x48, 0xb4, 0x69, 0xde, 0x7b, 0x83, 0x99, 0x41];
        let elf = minimal_elf_with_build_id(&build_id);
        let info = identify(&elf).expect("identify ELF");
        assert_eq!(info.format, SymbolFormat::Elf);
        assert_eq!(info.id, hex::encode(build_id));
        assert_eq!(info.arch.as_deref(), Some("aarch64"));
    }

    #[test]
    fn rejects_elf_without_build_id() {
        let mut elf = minimal_elf_with_build_id(&[0xab; 8]);
        // Corrupt the note type so it is no longer NT_GNU_BUILD_ID.
        let note_type_offset = (64 + 56 + 8) as usize;
        elf[note_type_offset] = 1;
        assert!(matches!(
            identify(&elf),
            Err(Error::UnrecognisedFormat(_))
        ));
    }

    #[test]
    fn identifies_macho_uuids() {
        let uuid = [0x11u8; 16];
        let macho = minimal_macho_with_uuid(uuid);
        let info = identify(&macho).expect("identify Mach-O");
        assert_eq!(info.format, SymbolFormat::MachO);
        assert_eq!(info.id, hex::encode(uuid));
        assert_eq!(info.arch.as_deref(), Some("aarch64"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            identify(b"definitely not a symbol file"),
            Err(Error::UnrecognisedFormat(_))
        ));
        // A PDB magic with a truncated body must fail cleanly, not panic.
        assert!(matches!(
            identify(MSF_MAGIC),
            Err(Error::UnrecognisedFormat(_))
        ));
    }

    #[test]
    fn sanitizes_ids() {
        assert_eq!(sanitize_id("ABCDEF12").unwrap(), "abcdef12");
        assert!(sanitize_id("xyz").is_err());
        assert!(sanitize_id("a").is_err());
        assert!(sanitize_id("../../etc/passwd").is_err());
    }
}
