use std::{env, error::Error, fs::File, path::Path};
use memmap2::Mmap;
use goblin::elf::{program_header::PF_X, Elf};
use capstone::prelude::*;
use goblin::elf::section_header::SHF_EXECINSTR;

mod llil;                // <-- your Expr/Instr/translate_arm64 lives here

fn main() -> Result<(), Box<dyn Error>> {
    // ------- 1. open + mmap ----------
    let path = env::args().nth(1).expect("give .so path");
    let file = File::open(&path)?;
    let map  = unsafe { Mmap::map(&file)? };        // readonly mmap :contentReference[oaicite:5]{index=5}

    // ------- 2. parse ELF header ------
    let elf = Elf::parse(&map)?;                    // zero-copy :contentReference[oaicite:6]{index=6}

    // ------- 3. set up Capstone -------
    let cs = Capstone::new()
        .arm64()                                   // or .x86(), etc.
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()?;

    // ------- 4. iterate executable segments ----
    for ph in elf.program_headers.iter().filter(|ph| ph.is_executable()) {
        let range = ph.file_range();              // Range<usize>
        if range.is_empty() { continue; }

        let bytes = &map[range.clone()];          // slice straight from mmap
        let vaddr = ph.p_vaddr;

        println!(
            "\nSEGMENT @ file 0x{:x} (size 0x{:x}) → vaddr 0x{:x}",
            range.start, range.len(), vaddr
        );

        // 4.a  hex-dump first ≤32 bytes
        let dump_len = bytes.len().min(32);
        print!("  first {dump_len} bytes: ");
        for b in &bytes[..dump_len] { print!("{b:02x} "); }
        println!();

        // 4.b  decode instructions one-by-one
        let mut cur_off  = 0;
        let mut cur_addr = vaddr;

        while cur_off < bytes.len() {
            let insns = cs.disasm_count(&bytes[cur_off..], cur_addr, 1)?;
            if insns.is_empty() {
                //println!("  {cur_addr:08x}: <undecodable>");
                // break;
                cur_off  += 4;
                cur_addr += 4 as u64;
                continue;
            }

            let insn = insns.get(0).unwrap();
            let size = insn.bytes().len();
            let il   = llil::translate_arm64(&cs, insn)?;

            println!(
                "  {:#010x}: {:<12} {:<24} {:?}",
                insn.address(),
                insn.mnemonic().unwrap_or(""),
                insn.op_str().unwrap_or(""),
                il
            );

            cur_off  += size;
            cur_addr += size as u64;
        }
    }
    Ok(())
}

// ----- convenience extension traits -----
trait PhExt {
    fn is_executable(&self) -> bool;
    fn file_range(&self) -> Option<(u64,u64)>;
}
impl PhExt for goblin::elf::ProgramHeader {
    fn is_executable(&self) -> bool { self.p_flags & PF_X != 0 }
    fn file_range(&self) -> Option<(u64,u64)> {
        if self.p_filesz == 0 { None } else { Some((self.p_offset, self.p_filesz)) }
    }
}
