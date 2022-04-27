use elfload::Elf;

fn main() {
    let ls_bytes = include_bytes!("/bin/ls");

    match Elf::parse(ls_bytes) {
        Ok(elf) => {
            println!("ELF machine: {:?} entry: 0x{:08x}", elf.machine, elf.entry);
            for l in &elf.load_segments {
                println!(
                    "LOAD: vaddr: 0x{:08x} zero_pad: {:8} {}{}{}",
                    l.vaddr,
                    l.zero_pad,
                    if l.x { 'X' } else { '-' },
                    if l.w { 'W' } else { '-' },
                    if l.r { 'R' } else { '-' }
                );
            }
        }
        Err(e) => {
            eprintln!("Parsing /bin/ls ELF file failed with {:?}.", e);
        }
    }
}
