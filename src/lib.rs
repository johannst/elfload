#![no_std]

#[derive(Debug)]
pub enum Error {
    /// Wrong or missing ELF file magic.
    WrongElfMagic,
    /// No more bytes left while parsing the ELF file.
    OutOfBytes,
    /// Unknown value in `e_ident:EI_CLASS` byte.
    UnknownBitness(u8),
    /// Unknown value in `e_ident:EI_DATA` byte.
    UnknownEndianess(u8),
    /// Unknown value in `e_machine` bytes.
    UnknownMachine(u16),
}

type Result<T> = core::result::Result<T, Error>;

/// Helper trait to define trait bounds providing endian aware construction methods.
trait FromEndian: Sized {
    const N: usize = core::mem::size_of::<Self>();
    fn from_le_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self>;
    fn from_be_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self>;
}

/// Helper macro to easily implement [`FromEndian`] trait for basic types.
macro_rules! impl_from_endian {
    ($ty: ty) => {
        impl FromEndian for $ty {
            fn from_le_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
                bytes
                    .as_ref()
                    .get(..Self::N)?
                    .try_into()
                    .map(<$ty>::from_le_bytes)
                    .ok()
            }

            fn from_be_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
                bytes
                    .as_ref()
                    .get(..Self::N)?
                    .try_into()
                    .map(<$ty>::from_be_bytes)
                    .ok()
            }
        }
    };
}

impl_from_endian!(u8);
impl_from_endian!(u16);
impl_from_endian!(u32);
impl_from_endian!(u64);

/// Helper to safely construct generic types from a stream of bytes.
struct ByteReader<'bytes> {
    bytes: &'bytes [u8],
    pos: usize,
}

impl<'bytes> ByteReader<'bytes> {
    /// Construct a new [`ByteReader`] instance from a slice of bytes.
    const fn new(bytes: &'bytes [u8]) -> ByteReader<'_> {
        ByteReader { bytes, pos: 0 }
    }

    /// Safely extract a slice of bytes with the given length `len`.
    fn read_slice(&mut self, len: usize) -> Result<&'bytes [u8]> {
        if let Some(bytes) = self.bytes.get(self.pos..self.pos + len) {
            self.bump(len);
            Ok(bytes)
        } else {
            Err(Error::OutOfBytes)
        }
    }

    /// Safely extract an `E` with the endianess given by [`en`][Endian].
    fn read<E: FromEndian>(&mut self, en: Endian) -> Result<E> {
        let bytes = self.bytes.get(self.pos..).ok_or(Error::OutOfBytes)?;

        let val = match en {
            Endian::Little => E::from_le_bytes(&bytes),
            Endian::Big => E::from_be_bytes(&bytes),
        };

        if val.is_some() {
            self.bump(E::N);
        }

        val.ok_or(Error::OutOfBytes)
    }

    /// Safely extract a value of size [`bit`][Bit] with the endianess given by [`en`][Endian].
    fn read_native(&mut self, en: Endian, bit: Bit) -> Result<u64> {
        match bit {
            Bit::Bit32 => self.read::<u32>(en).map(u64::from),
            Bit::Bit64 => self.read::<u64>(en),
        }
    }

    /// Increment the current position of the [`ByteReader`] by `inc`.
    #[inline]
    fn bump(&mut self, inc: usize) {
        self.pos += inc;
    }

    /// Set the current position of the [`ByteReader`] to `pos`.
    #[inline]
    fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Get the current position of the [`ByteReader`].
    #[inline]
    const fn pos(&self) -> usize {
        self.pos
    }
}

/// Possible ELF endian variants.
#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl TryFrom<u8> for Endian {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Endian::Little),
            2 => Ok(Endian::Big),
            _ => Err(Error::UnknownEndianess(v)),
        }
    }
}

/// Possible ELF bit variants.
#[derive(Debug, Clone, Copy)]
enum Bit {
    Bit32,
    Bit64,
}

impl TryFrom<u8> for Bit {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Bit::Bit32),
            2 => Ok(Bit::Bit64),
            _ => Err(Error::UnknownBitness(v)),
        }
    }
}

impl Into<usize> for Bit {
    fn into(self) -> usize {
        match self {
            Bit::Bit32 => 4,
            Bit::Bit64 => 8,
        }
    }
}

/// Possible ELF machine variants.
#[derive(Debug, Clone, Copy)]
pub enum Machine {
    X86_64,
    RiscV,
}

impl TryFrom<u16> for Machine {
    type Error = Error;

    fn try_from(v: u16) -> Result<Self> {
        match v {
            62 => Ok(Machine::X86_64),
            243 => Ok(Machine::RiscV),
            _ => Err(Error::UnknownMachine(v)),
        }
    }
}

/// Possible ELF program header variants.
#[derive(Clone, Copy)]
pub enum SegmentType {
    Load,
    Dynamic,
    Interp,
    Note,
    Phdr,
    Unknown(u32),
}

impl From<u32> for SegmentType {
    fn from(v: u32) -> Self {
        match v {
            1 => SegmentType::Load,
            2 => SegmentType::Dynamic,
            3 => SegmentType::Interp,
            6 => SegmentType::Phdr,
            _ => SegmentType::Unknown(v),
        }
    }
}

/// An ELF file program header and segment bytes.
pub struct Segment<'bytes> {
    bytes: &'bytes [u8],
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    flags: u32,
    typ: SegmentType,
}

impl Segment<'_> {
    /// Check if `addr` falls into the virtual address range covered by the segment.
    #[inline]
    pub const fn contains(&self, addr: u64) -> bool {
        self.vaddr <= addr && addr < (self.vaddr + self.memsz)
    }

    /// ELF segment raw bytes.
    #[inline]
    pub const fn bytes(&self) -> &'_ [u8] {
        self.bytes
    }

    /// ELF segment virtual address.
    #[inline]
    pub const fn vaddr(&self) -> u64 {
        self.vaddr
    }

    /// ELF segment physical address.
    #[inline]
    pub const fn paddr(&self) -> u64 {
        self.paddr
    }

    /// ELF segment physical address.
    #[inline]
    pub const fn zero_padding(&self) -> u64 {
        self.memsz - self.filesz
    }

    /// Indicate whether segment is `executable`.
    #[inline]
    pub const fn exec(&self) -> bool {
        const PF_X: u32 = 1 << 0;
        (self.flags & PF_X) != 0
    }

    /// Indicate whether segment is `writeable`.
    #[inline]
    pub const fn write(&self) -> bool {
        const PF_W: u32 = 1 << 1;
        (self.flags & PF_W) != 0
    }

    /// Indicate whether segment is `readable`.
    #[inline]
    pub const fn read(&self) -> bool {
        const PF_R: u32 = 1 << 2;
        (self.flags & PF_R) != 0
    }

    /// ELF segment type.
    #[inline]
    pub const fn typ(&self) -> SegmentType {
        self.typ
    }
}

/// Iterator type over ELF program header and segments.
struct SegmentIter<'bytes> {
    reader: ByteReader<'bytes>,
    bit: Bit,
    endian: Endian,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    ph: usize,
}

impl<'bytes> SegmentIter<'bytes> {
    /// Create a new [`SegmentIter`].
    const fn new(
        bytes: &'bytes [u8],
        bit: Bit,
        endian: Endian,
        phoff: usize,
        phentsize: usize,
        phnum: usize,
    ) -> Self {
        SegmentIter {
            reader: ByteReader::new(bytes),
            bit,
            endian,
            phoff,
            phentsize,
            phnum,
            ph: 0,
        }
    }
}

impl<'bytes> Iterator for SegmentIter<'bytes> {
    type Item = Segment<'bytes>;

    /// Try to parse next ELF program header and segment bytes.
    fn next(&mut self) -> Option<Self::Item> {
        if self.ph < self.phnum {
            // Position byte reader at the start of the current program header.
            let off = self.ph.checked_mul(self.phentsize)?;
            let pos = off.checked_add(self.phoff)?;
            self.reader.set_pos(pos);

            // Bump to the next program header.
            self.ph += 1;

            // Get some aliases.
            let r = &mut self.reader;
            let bit = self.bit;
            let en = self.endian;

            // Parse program header.
            let typ = r.read::<u32>(en).map(SegmentType::from).ok()?;
            let mut flags = 0;
            // Elf64 program header has flags field here.
            if matches!(bit, Bit::Bit64) {
                flags = r.read::<u32>(en).ok()?
            }
            let offset = r.read_native(en, bit).ok()?;
            let vaddr = r.read_native(en, bit).ok()?;
            let paddr = r.read_native(en, bit).ok()?;
            let filesz = r.read_native(en, bit).ok()?;
            let memsz = r.read_native(en, bit).ok()?;
            debug_assert!(memsz >= filesz);
            // Elf32 program header has flags field here.
            if matches!(bit, Bit::Bit32) {
                flags = r.read::<u32>(en).ok()?
            }
            let _align = r.read_native(en, bit).ok()?;

            let data_off = usize::try_from(offset).ok()?;
            let data_len = usize::try_from(filesz).ok()?;

            // Seek to start of the segment bytes.
            r.set_pos(data_off);

            // Get slice of segment bytes.
            let bytes = r.read_slice(data_len).ok()?;
            debug_assert_eq!(filesz, bytes.len() as u64);

            Some(Segment {
                bytes,
                vaddr,
                paddr,
                memsz,
                filesz,
                flags,
                typ,
            })
        } else {
            None
        }
    }
}

/// An ELF file.
pub struct Elf<'bytes> {
    bytes: &'bytes [u8],
    bit: Bit,
    endian: Endian,
    machine: Machine,
    entry: u64,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
}

impl<'bytes> Elf<'bytes> {
    /// Try to parse an [`Elf`] object from the `bytes` given.
    pub fn parse(bytes: &'bytes [u8]) -> Result<Elf<'bytes>> {
        let mut r = ByteReader::new(bytes);

        if !matches!(r.read_slice(4), Ok(b"\x7fELF")) {
            return Err(Error::WrongElfMagic);
        }

        let bit = r.read::<u8>(Endian::Little).map(Bit::try_from)??;
        let endian = r.read::<u8>(Endian::Little).map(Endian::try_from)??;

        // Consume rest of e_ident.
        r.bump(10);

        let _type = r.read::<u16>(endian)?;
        let machine = r.read::<u16>(endian).map(Machine::try_from)??;
        let _version = r.read::<u32>(endian)?;
        let entry = r.read_native(endian, bit)?;
        let phoff = r.read_native(endian, bit).map(usize::try_from)?.unwrap();
        let _shoff = r.read_native(endian, bit)?;
        let _flags = r.read::<u32>(endian)?;
        let ehsize = r.read::<u16>(endian)?;
        let phentsize = r.read::<u16>(endian).map(usize::try_from)?.unwrap();
        let phnum = r.read::<u16>(endian).map(usize::try_from)?.unwrap();
        let _shentsize = r.read::<u16>(endian)?;
        let _shnum = r.read::<u16>(endian)?;
        let _shstrndf = r.read::<u16>(endian)?;

        assert_eq!(r.pos(), usize::from(ehsize));

        Ok(Elf {
            bytes,
            bit,
            endian,
            machine,
            entry,
            phoff,
            phentsize,
            phnum,
        })
    }

    /// Get the machine field from the ELF header.
    #[inline]
    pub const fn machine(&self) -> Machine {
        self.machine
    }

    /// Get the virtual address of the `entrypoint` from the ELF header.
    #[inline]
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// Get an iterator of the program header segments of type `PT_LOAD`.
    #[inline]
    pub fn load_segments(&self) -> impl Iterator<Item = Segment<'bytes>> {
        SegmentIter::new(
            self.bytes,
            self.bit,
            self.endian,
            self.phoff,
            self.phentsize,
            self.phnum,
        )
        .filter(|s| matches!(s.typ(), SegmentType::Load))
    }
}
