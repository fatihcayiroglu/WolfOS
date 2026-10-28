//! Early x86-64 COM1 serial logging. Single-core P0 only.
use core::{arch::asm, fmt::{self, Write}};

const COM1: u16 = 0x3f8;

#[inline]
unsafe fn port_out(port: u16, value: u8) {
    // SAFETY: caller restricts port I/O to COM1 or QEMU smoke-test port.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)); }
}

#[inline]
unsafe fn port_in(port: u16) -> u8 {
    let out: u8;
    // SAFETY: caller restricts I/O to COM1.
    unsafe { asm!("in al, dx", in("dx") port, out("al") out, options(nomem, nostack, preserves_flags)); }
    out
}

/// Read at most one waiting COM1 byte. BSP polling only: no IRQ, DMA or heap.
pub fn read_byte_nonblocking() -> Option<u8> {
    // SAFETY: COM1 line-status register advertises a ready receiver byte.
    if unsafe { port_in(COM1 + 5) } & 1 == 0 {
        None
    } else {
        // SAFETY: the 16550 UART reports receive-data-ready above.
        Some(unsafe { port_in(COM1) })
    }
}

pub fn init() {
    // SAFETY: 16550-compatible COM1 on QEMU target.
    unsafe {
        port_out(COM1 + 1, 0x00);
        port_out(COM1 + 3, 0x80);
        port_out(COM1, 0x03);
        port_out(COM1 + 1, 0x00);
        port_out(COM1 + 3, 0x03);
        port_out(COM1 + 2, 0xC7);
        port_out(COM1 + 4, 0x0B);
    }
}

fn send_byte(byte: u8) {
    for _ in 0..100_000 {
        // SAFETY: line-status register of COM1.
        if unsafe { port_in(COM1 + 5) } & 0x20 != 0 {
            // SAFETY: COM1 transmitter buffer.
            unsafe { port_out(COM1, byte); }
            return;
        }
        core::hint::spin_loop();
    }
}

pub fn write_line(s: &str) {
    let mut writer = Serial;
    let _ = writeln!(writer, "{s}");
}

struct Serial;
impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' { send_byte(b'\r'); }
            send_byte(if b.is_ascii() { b } else { b'?' });
        }
        Ok(())
    }
}

pub fn write_fmt(args: fmt::Arguments<'_>) {
    let _ = Serial.write_fmt(args);
}

#[cfg(feature = "smoke-exit")]
pub fn qemu_exit_success() -> ! {
    // QEMU returns (0x10 << 1) | 1 == 33.
    // SAFETY: port is provided only in the smoke-test VM.
    unsafe { port_out(0xf4, 0x10); }
    crate::halt_forever()
}
