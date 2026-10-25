//! Opt-in hardware proof: PS/2 keyboard make codes -> Rust text cells ->
//! checked, volatile QEMU framebuffer pixel writes. This is not the normal
//! boot path, a secure input subsystem, or a user-space graphical terminal.

use crate::{
    framebuffer_console::TextConsole,
    framebuffer_text::Layout,
    ps2_keyboard::{Key, Set1Decoder, read_scancode},
    serial,
};

pub fn run(layout: Layout, address: *mut u8, white: u32) -> ! {
    let Some(mut console) = TextConsole::new(layout, 20, 80, 16, 2) else {
        serial::write_line("WOLFOS_PS2_FAILED insufficient_framebuffer");
        crate::halt_forever();
    };
    // This feature only polls the boot processor. Kernel startup has already
    // checked 32-bpp RGB, aligned base address and packed color masks.
    console.render(white, 0, |offset, color| {
        // SAFETY: framebuffer Layout validates every pixel byte offset.
        // Caller supplied Limine-mapped aligned 32-bpp framebuffer.
        unsafe { address.add(offset).cast::<u32>().write_volatile(color); }
    });
    let mut decoder = Set1Decoder::new();
    let mut accepted = 0usize;
    serial::write_line("WOLFOS_PS2_READY mode=polling keyboard=set1 graphical=1");
    loop {
        if let Some(scancode) = read_scancode() {
            if let Some(key) = decoder.feed(scancode) {
                accepted += 1;
                if accepted > 32 {
                    serial::write_line("WOLFOS_PS2_FAILED too_many_events");
                    crate::halt_forever();
                }
                match key {
                    Key::Character(c) => {
                        console.write(core::str::from_utf8(&[c]).unwrap_or("?"));
                    }
                    Key::Backspace => {
                        console.backspace();
                    }
                    Key::Enter => {
                        console.write("\n");
                    }
                }
                console.render(white, 0, |offset, color| {
                    // SAFETY: validated framebuffer offset, aligned 32-bit store.
                    unsafe { address.add(offset).cast::<u32>().write_volatile(color); }
                });
                serial::write_fmt(format_args!("WOLFOS_PS2_EVENT accepted={accepted}\n"));
                if matches!(key, Key::Enter) {
                    let pixel = |x,y| layout.pixel_offset(x,y).map(|offset| {
                        // SAFETY: framebuffer layout verified mapped in-range offset.
                        unsafe { address.add(offset).cast::<u32>().read_volatile() }
                    });
                    if accepted == 6
                        && console.cell(0,0) == Some(b'A')
                        && console.cell(1,0) == Some(b'B')
                        && console.cell(2,0) == Some(b'D')
                        && console.cell(3,0) == Some(b' ')
                        && console.cursor() == (0,1)
                        && pixel(20,80) == Some(0)
                        && pixel(21,80) == Some(white)
                        && pixel(26,80) == Some(white)
                        && pixel(32,80) == Some(white)
                        && pixel(21,88) == Some(0)
                    {
                        serial::write_line("WOLFOS_PS2_GRAPHICS_OK keys=6 text=ABD backspace=1 enter=1 pixels=verified");
                    } else {
                        serial::write_line("WOLFOS_PS2_FAILED keyboard_or_framebuffer_mismatch");
                    }
                    crate::halt_forever();
                }
            }
        } else {
            core::hint::spin_loop();
        }
    }
}
