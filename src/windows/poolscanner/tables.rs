//! Pool tag constraints from the pinned Volatility reference tables.

pub(super) const OPTIONAL_HEADERS: [&str; 9] = [
    "CREATOR_INFO",
    "NAME_INFO",
    "HANDLE_INFO",
    "QUOTA_INFO",
    "PROCESS_INFO",
    "AUDIT_INFO",
    "EXTENDED_INFO",
    "HANDLE_REVOCATION_INFO",
    "PADDING_INFO",
];

pub(super) struct Constraint {
    pub(super) tag: &'static [u8],
    pub(super) type_name: &'static str,
    pub(super) object_type: Option<&'static str>,
    pub(super) minimum: u64,
    pub(super) page: u8,
    pub(super) skip_type: bool,
    pub(super) extra: &'static [&'static str],
}

impl Constraint {
    pub(super) const fn new(
        tag: &'static [u8],
        type_name: &'static str,
        object_type: Option<&'static str>,
        minimum: u64,
        page: u8,
        skip_type: bool,
        extra: &'static [&'static str],
    ) -> Self {
        Self {
            tag,
            type_name,
            object_type,
            minimum,
            page,
            skip_type,
            extra,
        }
    }
}

pub(super) const CONSTRAINTS: &[Constraint] = &[
    Constraint::new(b"AtmT", "_RTL_ATOM_TABLE", None, 200, 7, false, &[]),
    Constraint::new(
        &[b'P', b'r', b'o', 0xe3],
        "_EPROCESS",
        Some("Process"),
        600,
        6,
        true,
        &[],
    ),
    Constraint::new(b"Proc", "_EPROCESS", Some("Process"), 600, 6, true, &[]),
    Constraint::new(
        &[b'T', b'h', b'r', 0xe5],
        "_ETHREAD",
        Some("Thread"),
        600,
        6,
        true,
        &[],
    ),
    Constraint::new(b"Thre", "_ETHREAD", Some("Thread"), 600, 6, false, &[]),
    Constraint::new(
        &[b'F', b'i', b'l', 0xe5],
        "_FILE_OBJECT",
        Some("File"),
        150,
        6,
        false,
        &[],
    ),
    Constraint::new(b"File", "_FILE_OBJECT", Some("File"), 150, 6, false, &[]),
    Constraint::new(
        &[b'M', b'u', b't', 0xe1],
        "_KMUTANT",
        Some("Mutant"),
        64,
        6,
        false,
        &[],
    ),
    Constraint::new(b"Muta", "_KMUTANT", Some("Mutant"), 64, 6, false, &[]),
    Constraint::new(
        &[b'D', b'r', b'i', 0xf6],
        "_DRIVER_OBJECT",
        Some("Driver"),
        248,
        6,
        false,
        &["_DRIVER_EXTENSION"],
    ),
    Constraint::new(
        b"Driv",
        "_DRIVER_OBJECT",
        Some("Driver"),
        248,
        6,
        false,
        &[],
    ),
    Constraint::new(b"MmLd", "_LDR_DATA_TABLE_ENTRY", None, 76, 6, false, &[]),
    Constraint::new(
        &[b'S', b'y', b'm', 0xe2],
        "_OBJECT_SYMBOLIC_LINK",
        Some("SymbolicLink"),
        72,
        5,
        false,
        &[],
    ),
    Constraint::new(
        b"Symb",
        "_OBJECT_SYMBOLIC_LINK",
        Some("SymbolicLink"),
        72,
        5,
        false,
        &[],
    ),
    Constraint::new(b"CM10", "_CMHIVE", None, 800, 5, true, &[]),
];
