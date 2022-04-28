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

type Result<T> = std::result::Result<T, Error>;

trait FromEndian: Sized {
    const N: usize = std::mem::size_of::<Self>();
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

#[derive(Debug)]
pub struct LoadSegment<'bytes> {
    pub vaddr: u64,
    pub bytes: &'bytes [u8],
    pub zero_pad: usize,
    pub x: bool,
    pub w: bool,
    pub r: bool,
}

#[derive(Debug)]
pub struct Elf<'bytes> {
    pub machine: Machine,
    pub entry: u64,
    pub load_segments: Vec<LoadSegment<'bytes>>,
}

impl Elf<'_> {
    pub fn parse<'bytes>(b: &'bytes [u8]) -> Result<Elf<'bytes>> {
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

        let mut load_segments = Vec::with_capacity(usize::from(phnum));

        const PT_LOAD: u32 = 1;
        const PF_X: u32 = 1 << 0;
        const PF_W: u32 = 1 << 1;
        const PF_R: u32 = 1 << 2;

        let phoff = usize::try_from(phoff).expect("phoff too large!");

        for ph in 0..phnum {
            let off = ph.checked_mul(phentsize).map(usize::from).expect("phdr offset overflowed");
            let pos = phoff.checked_add(off).expect("phdr position overflowed");
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

            let offset = usize::try_from(offset).expect("file offset too large");
            let filesz = usize::try_from(filesz).expect("file size too large");
            let memsz = usize::try_from(memsz).expect("mem size too large");

            // Seek to start of PT_LOAD segment bytes.
            r.set_pos(offset);

            // Get slice of PT_LOAD segment bytes.
            let bytes = r.read_slice(filesz)?;
            let x = (flags & PF_X) != 0;
            let w = (flags & PF_W) != 0;
            let r = (flags & PF_R) != 0;

            load_segments.push(LoadSegment {
                vaddr,
                bytes,
                zero_pad: memsz - filesz,
                x,
                w,
                r,
            });
        }

        Ok(Elf {
            machine,
            entry,
            load_segments,
        })
    }
}
