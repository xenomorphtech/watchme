
// capstone_llil_example.rs — minimal demo (compiles on Rust 1.78 + capstone 0.13.0)
// Disassembles a tiny AArch64 snippet with Capstone and lifts it into a
// hand‑rolled Binary‑Ninja‑style Low‑Level IL (LLIL).
//
// Build:
//   cargo new demo && cd demo
//   echo 'capstone = "0.13"' >> Cargo.toml
//   paste this file into src/main.rs
//   cargo run --release

use capstone::arch::arm64::{self, Arm64Insn, Arm64OperandType, ArchMode};
use capstone::prelude::*;
use capstone::RegId;
use std::error::Error;
use capstone::Insn;
use capstone::arch::arm64::Arm64Operand;

/// Value width in bytes (BN LLIL tracks sizes explicitly)
pub type Size = u8;

/// Minimal register set for the demo
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Reg {
    X(u8),
    SP,
    LR,
    ZR,
}

/// Tiny expression tree (subset of BN LLIL)
#[derive(Clone, Debug)]
pub enum Expr {
    Const(Size, u64),
    Reg(Size, Reg),
}

/// Basic‑block label wrapper for type‑safety
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Label(pub usize);

/// IL instructions we actually emit in this demo
#[derive(Clone, Debug)]
pub enum Instr {
    SetReg(Reg, Expr),
    Ret,
    Unimpl,
}

// ─────────────────────────────────────────────────────────────
// Fresh‑label generator (thread‑local counter is fine for a demo)
// ─────────────────────────────────────────────────────────────
thread_local! {
    static LABEL_COUNTER: std::cell::Cell<usize> = std::cell::Cell::new(0);
}
fn _fresh_label() -> Label { // not used yet, but kept for future CF work
    LABEL_COUNTER.with(|c| { let id = c.get(); c.set(id + 1); Label(id) })
}

// ─────────────────────────────────────────────────────────────
// Capstone → LLIL translator (MOV‑imm & RET only, for brevity)
// ─────────────────────────────────────────────────────────────
pub fn translate_arm64(cs: &Capstone, insn: &Insn) -> Result<Instr, Box<dyn Error>> {
    match insn.id().0 {
        id if id == Arm64Insn::ARM64_INS_MOV as u32 => {
            let detail = cs.insn_detail(insn)?;
            let det = detail.arch_detail();
            let arch_detail = det.arm64().ok_or("Not AArch64")?;
            let ops: Vec<Arm64Operand> = arch_detail.operands().collect();
            // Destination register is always first operand
            // dst register
            // println!("{:?}", ops);
            // [Arm64Operand { vector_index: None, vas: ARM64_VAS_INVALID, shift: Invalid, ext: ARM64_EXT_INVALID, op_type: Reg(RegId(216)) }, Arm64Operand { vector_index: None, vas: ARM64_VAS_INVALID, shift: Invalid, ext: ARM64_EXT_INVALID, op_type: Imm(1) }]
            let dst_reg = match ops[0].op_type {
                Arm64OperandType::Reg(rid) => reg_from_cs(rid),
                _ => Reg::ZR,
            };
            // immediate value
            let imm_val = match ops[1].op_type {
                Arm64OperandType::Imm(val) => val as u64,
                _ => 0,
            };
            Ok(Instr::SetReg(dst_reg, Expr::Const(8, imm_val)))
            //Ok(Instr::Unimpl)
        }
        id if id == Arm64Insn::ARM64_INS_RET as u32 => Ok(Instr::Ret),
        _ => Ok(Instr::Unimpl),
    }
}

/// Convert Capstone register id ➜ our tiny `Reg` enum
fn reg_from_cs(rid: RegId) -> Reg {
    let raw = rid.0 as u32;
    match raw {
        id if id >= arm64::Arm64Reg::ARM64_REG_X0 as u32 && id <= arm64::Arm64Reg::ARM64_REG_X28 as u32 => {
            Reg::X((id - arm64::Arm64Reg::ARM64_REG_X0 as u32) as u8)
        }
        id if id == arm64::Arm64Reg::ARM64_REG_SP as u32 => Reg::SP,
        id if id == arm64::Arm64Reg::ARM64_REG_LR as u32 => Reg::LR,
        _ => Reg::ZR,
    }
}

// ─────────────────────────────────────────────────────────────
// Demo driver: disassemble + translate + print IL
// ─────────────────────────────────────────────────────────────
fn main() -> Result<(), Box<dyn Error>> {
    // Machine code: `mov x0, #1 ; ret`
    const CODE: &[u8] = b"\x20\x00\x80\xd2\xc0\x03\x5f\xd6";

    // Capstone disassembler setup
    let cs = Capstone::new()
        .arm64()
        .mode(ArchMode::Arm) // 64‑bit AArch64 mode
        .detail(true)        // request operand details
        .build()?;

    let insns = cs.disasm_all(CODE, 0x1000)?;

    // Translate each instruction to IL and print
    for insn in insns.as_ref() {
        let il = translate_arm64(&cs, insn)?;
        println!("{:#x}: {:?}", insn.address(), il);
    }
    Ok(())
}

