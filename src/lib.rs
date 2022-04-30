#![no_std]

#[derive(Debug)]
pub enum Error {
    /// Wrong or missing ELF file magic.
    WrongElfMagic,
    /// No more bytes left while parsing the ELF file.
    OutOfBytes,
    /// Const generic on `Elf` is too small to hold all `LOAD` from the ELF file.
    OutOfLoadSegments,
    /// Failed to convert between data types internally.
    TypeConversion(&'static str),
    /// Unknown value in `e_ident:EI_CLASS` byte.
    UnknownBitness(u8),
    /// Unknown value in `e_ident:EI_DATA` byte.
    UnknownEndianess(u8),
    /// Unknown value in `e_machine` bytes.
    UnknownMachine(u16),
}

type Result<T> = core::result::Result<T, Error>;

trait FromEndian: Sized {
    const N: usize = core::mem::size_of::<Self>();
    fn from_le_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self>;
    fn from_be_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self>;
}

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

impl_from_endian!(u16);
impl_from_endian!(u32);
impl_from_endian!(u64);

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

struct ElfReader<'bytes> {
    bytes: &'bytes [u8],
    pos: usize,
}

impl<'bytes> ElfReader<'bytes> {
    const fn new(bytes: &'bytes [u8]) -> ElfReader<'_> {
        ElfReader { bytes, pos: 0 }
    }

    fn read_slice(&mut self, len: usize) -> Result<&'bytes [u8]> {
        if let Some(bytes) = self.bytes.get(self.pos..self.pos + len) {
            self.bump(len);
            Ok(bytes)
        } else {
            Err(Error::OutOfBytes)
        }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if let Some(byte) = self.bytes.get(self.pos) {
            self.bump(1);
            Ok(*byte)
        } else {
            Err(Error::OutOfBytes)
        }
    }

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

    fn read_native(&mut self, en: Endian, bt: Bit) -> Result<u64> {
        match bt {
            Bit::Bit32 => self.read::<u32>(en).map(u64::from),
            Bit::Bit64 => self.read::<u64>(en),
        }
    }

    #[inline]
    fn bump(&mut self, inc: usize) {
        self.pos += inc;
    }

    #[inline]
    fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    #[inline]
    const fn pos(&self) -> usize {
        self.pos
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LoadSegment<'bytes> {
    pub vaddr: u64,
    pub bytes: &'bytes [u8],
    pub zero_pad: u64,
    pub x: bool,
    pub w: bool,
    pub r: bool,
}

impl LoadSegment<'_> {
    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        let len = u64::try_from(self.bytes.len()).expect("segment byte len exceeds u64");
        self.vaddr <= addr && addr < (self.vaddr + len + self.zero_pad)
    }
}

#[derive(Debug)]
pub struct Elf<'bytes, const N: usize> {
    machine: Machine,
    entry: u64,
    load_segments: [Option<LoadSegment<'bytes>>; N],
}

impl<'bytes, const N: usize> Elf<'bytes, N> {
    pub fn parse(b: &'bytes [u8]) -> Result<Elf<'bytes, N>> {
        let mut r = ElfReader::new(b);

        //
        // Parse ELF header.
        //

        if !matches!(r.read_slice(4), Ok(b"\x7fELF")) {
            return Err(Error::WrongElfMagic);
        }

        let bit = r.read_u8().map(Bit::try_from)??;
        let en = r.read_u8().map(Endian::try_from)??;

        // Consume rest of e_ident.
        r.bump(10);

        let _type = r.read::<u16>(en)?;
        let machine = r.read::<u16>(en).map(Machine::try_from)??;
        let _version = r.read::<u32>(en)?;
        let entry = r.read_native(en, bit)?;
        let phoff = r.read_native(en, bit)?;
        let _shoff = r.read_native(en, bit)?;
        let _flags = r.read::<u32>(en)?;
        let ehsize = r.read::<u16>(en)?;
        let phentsize = r.read::<u16>(en)?;
        let phnum = r.read::<u16>(en)?;
        let _shentsize = r.read::<u16>(en)?;
        let _shnum = r.read::<u16>(en)?;
        let _shstrndf = r.read::<u16>(en)?;

        assert_eq!(r.pos(), usize::from(ehsize));

        //
        // Parse load program header.
        //

        let mut load_segments = [None; N];
        let mut load_segments_slice = &mut load_segments[..];

        const PT_LOAD: u32 = 1;
        const PF_X: u32 = 1 << 0;
        const PF_W: u32 = 1 << 1;
        const PF_R: u32 = 1 << 2;

        let phoff = usize::try_from(phoff)
            .map_err(|_| Error::TypeConversion("phoff does not fit into usize"))?;

        for ph in 0..phnum {
            let off = ph
                .checked_mul(phentsize)
                .map(usize::from)
                .ok_or(Error::TypeConversion("phdr offset does not fit into usize"))?;
            let pos = phoff.checked_add(off).ok_or(Error::TypeConversion(
                "phdr position does not fit into usize",
            ))?;
            r.set_pos(pos);

            // We only care about load segments.
            if r.read::<u32>(en)? != PT_LOAD {
                continue;
            }

            let mut flags = 0;

            // Elf64 program header has flags field here.
            if matches!(bit, Bit::Bit64) {
                flags = r.read::<u32>(en)?
            }
            let offset = r.read_native(en, bit)?;
            let vaddr = r.read_native(en, bit)?;
            let _paddr = r.read_native(en, bit)?;
            let filesz = r.read_native(en, bit)?;
            let memsz = r.read_native(en, bit)?;
            // Elf32 program header has flags field here.
            if matches!(bit, Bit::Bit32) {
                flags = r.read::<u32>(en)?
            }
            let _align = r.read_native(en, bit)?;

            let data_off = usize::try_from(offset)
                .map_err(|_| Error::TypeConversion("file offset does not fit into usize"))?;
            let data_len = usize::try_from(filesz)
                .map_err(|_| Error::TypeConversion("file size does not fit into usize"))?;

            // Seek to start of PT_LOAD segment bytes.
            r.set_pos(data_off);

            // Get slice of PT_LOAD segment bytes.
            let bytes = r.read_slice(data_len)?;
            let x = (flags & PF_X) != 0;
            let w = (flags & PF_W) != 0;
            let r = (flags & PF_R) != 0;

            load_segments_slice = load_segments_slice
                .split_first_mut()
                .map(|(slot, rest)| {
                    *slot = Some(LoadSegment {
                        vaddr,
                        bytes,
                        zero_pad: memsz - filesz,
                        x,
                        w,
                        r,
                    });
                    rest
                })
                .ok_or(Error::OutOfLoadSegments)?;
        }

        Ok(Elf {
            machine,
            entry,
            load_segments,
        })
    }

    #[inline]
    pub fn machine(&self) -> Machine {
        self.machine
    }

    #[inline]
    pub fn entry(&self) -> u64 {
        self.entry
    }

    #[inline]
    pub fn load_segments(&self) -> impl Iterator<Item = &LoadSegment<'bytes>> {
        self.load_segments.iter().flatten()
    }
}
