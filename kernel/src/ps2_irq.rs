//! Isolated real IRQ1 i8042 → bounded SPSC queue acceptance path for QEMU.
//! PIC IRQ0 and all slave IRQs stay masked. Handler never renders/decodes,
//! logs, allocates, locks, changes device config or calls shell commands.
//! Experimental BSP-only legacy PC; not a production PS/2/USB driver.

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::structures::idt::InterruptStackFrame;
use crate::ps2_scancode_queue::ScancodeQueue;

pub const VECTOR: u8 = 0x21;
const MASTER_COMMAND: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_COMMAND: u16 = 0xa0;
const SLAVE_DATA: u16 = 0xa1;

static SCANCODES: ScancodeQueue<64> = ScancodeQueue::new();
static IRQS: AtomicUsize = AtomicUsize::new(0);
static EOIS: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn outb(port: u16, value: u8) {
    // SAFETY: only isolated QEMU legacy PIC command/data ports.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value,
        options(nomem, nostack, preserves_flags)); }
}
fn wait_io() { outb(0x80, 0); }

pub extern "x86-interrupt" fn irq1(_frame: InterruptStackFrame) {
    IRQS.fetch_add(1, Ordering::Relaxed);
    if let Some(scan) = crate::ps2_keyboard::read_scancode() {
        // Losing even a break code can corrupt modifier state. The queue
        // poisons the foreground session instead of silently dropping it.
        SCANCODES.push(scan);
    }
    // Acknowledge the master PIC even if OBF is empty or the queue is full;
    // otherwise the IRQ line could remain blocked indefinitely.
    outb(MASTER_COMMAND, 0x20);
    EOIS.fetch_add(1, Ordering::Release);
}

/// Called once on BSP after its IDT already contains our IRQ1 vector.
pub fn start() {
    x86_64::instructions::interrupts::disable();
    // Reinitialize legacy PICs while masked. Use existing QEMU timer-smoke
    // remap (master 0x20, slave 0x28) but unmask IRQ1 ONLY.
    outb(MASTER_DATA, 0xff);
    outb(SLAVE_DATA, 0xff);
    outb(MASTER_COMMAND, 0x11); wait_io();
    outb(SLAVE_COMMAND, 0x11); wait_io();
    outb(MASTER_DATA, 0x20); wait_io();
    outb(SLAVE_DATA, 0x28); wait_io();
    outb(MASTER_DATA, 0x04); wait_io();
    outb(SLAVE_DATA, 0x02); wait_io();
    outb(MASTER_DATA, 0x01); wait_io();
    outb(SLAVE_DATA, 0x01); wait_io();
    outb(SLAVE_DATA, 0xff);
    outb(MASTER_DATA, 0xfd); // master IRQ1 only (bit 1 cleared)
    x86_64::instructions::interrupts::enable();
}

/// Read by foreground only; no PS/2 0x60/0x64 polling outside the handler.
pub fn take() -> Result<Option<u8>, ()> {
    SCANCODES.pop()
}

pub fn evidence() -> (usize, usize, usize, bool) {
    (
        IRQS.load(Ordering::Acquire),
        EOIS.load(Ordering::Acquire),
        SCANCODES.dropped(),
        SCANCODES.poisoned(),
    )
}
