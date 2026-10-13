//! Legacy PC PIT + 8259 PIC hardware IRQ0 smoke proof (BSP only).
//! Enabled only with the timer-smoke feature. This is not scheduling or SMP.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::structures::idt::InterruptStackFrame;
use crate::serial;

pub const TIMER_VECTOR: u8 = 32;
const MASTER_COMMAND: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_COMMAND: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;
const PIT_COMMAND: u16 = 0x43;
const PIT_CHANNEL0: u16 = 0x40;
const PIT_CLOCK_HZ: u32 = 1_193_182;
const FREQUENCY_HZ: u32 = 100;
const REQUIRED_TICKS: u64 = 8;
const MAX_SPINS: u64 = 500_000_000;
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn outb(port: u16, value: u8) {
    // SAFETY: isolated QEMU-only legacy PIC/PIT hardware ports.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value,
            options(nomem, nostack, preserves_flags));
    }
}
#[inline]
fn io_wait() { outb(0x80, 0); }

/// IRQ-safe fast path: atomic tick increment and mandatory PIC master EOI.
pub extern "x86-interrupt" fn irq0(_frame: InterruptStackFrame) {
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    outb(MASTER_COMMAND, 0x20);
}

fn setup_pic() {
    outb(MASTER_DATA, 0xff);
    outb(SLAVE_DATA, 0xff);
    outb(MASTER_COMMAND, 0x11); io_wait();
    outb(SLAVE_COMMAND, 0x11); io_wait();
    outb(MASTER_DATA, TIMER_VECTOR as u8); io_wait();
    outb(SLAVE_DATA, 0x28); io_wait();
    outb(MASTER_DATA, 0x04); io_wait();
    outb(SLAVE_DATA, 0x02); io_wait();
    outb(MASTER_DATA, 0x01); io_wait();
    outb(SLAVE_DATA, 0x01); io_wait();
    outb(SLAVE_DATA, 0xff);
    outb(MASTER_DATA, 0xfe); // enable IRQ0 only
}

fn setup_pit() {
    let divisor = (PIT_CLOCK_HZ / FREQUENCY_HZ) as u16;
    // PIT channel 0, low/high bytes, mode 2 rate generator, binary.
    outb(PIT_COMMAND, 0x34);
    outb(PIT_CHANNEL0, divisor as u8);
    outb(PIT_CHANNEL0, (divisor >> 8) as u8);
}

pub fn verify() -> bool {
    // APs have parked with interrupts disabled. BSP owns legacy IRQ path.
    x86_64::instructions::interrupts::disable();
    TIMER_TICKS.store(0, Ordering::Relaxed);
    setup_pic();
    setup_pit();
    serial::write_fmt(format_args!(
        "WOLFOS_TIMER_BEGIN vector={} hz={} required={}\n",
        TIMER_VECTOR, FREQUENCY_HZ, REQUIRED_TICKS
    ));
    x86_64::instructions::interrupts::enable();
    let mut success = false;
    for _ in 0..MAX_SPINS {
        if TIMER_TICKS.load(Ordering::Relaxed) >= REQUIRED_TICKS {
            success = true;
            break;
        }
        core::hint::spin_loop();
    }
    x86_64::instructions::interrupts::disable();
    outb(MASTER_DATA, 0xff);
    outb(SLAVE_DATA, 0xff);
    let ticks = TIMER_TICKS.load(Ordering::Relaxed);
    if !success {
        serial::write_fmt(format_args!(
            "WOLFOS_TIMER_ERROR no_irq ticks={} required={}\n",
            ticks, REQUIRED_TICKS
        ));
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_TIMER_IRQ_OK vector={} hz={} ticks={}\n",
        TIMER_VECTOR, FREQUENCY_HZ, ticks
    ));
    true
}
