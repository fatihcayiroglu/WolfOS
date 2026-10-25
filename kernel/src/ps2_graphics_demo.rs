//! Opt-in hardware proof: PS/2 keyboard make codes -> Rust text cells ->
//! checked, volatile QEMU framebuffer pixel writes. This is not the normal
//! boot path, a secure input subsystem, or a user-space graphical terminal.

use crate::{
    framebuffer_console::TextConsole,
    framebuffer_text::Layout,
    graphical_diagnostics,
    graphical_line_editor::LineEditor,
    pci::PciSummary,
    ps2_keyboard::{Key, Set1Decoder, read_scancode},
    serial,
    shell_command::Command,
};

pub fn run(layout: Layout, address: *mut u8, white: u32, pci_summary: PciSummary) -> ! {
    let info_mode = cfg!(feature = "ps2-graphics-info-smoke");
    let edit_mode = cfg!(feature = "ps2-graphics-edit-smoke");
    let columns = if info_mode { 26 } else { 16 };
    let Some(mut console) = TextConsole::new(layout, 20, 80, columns, 2) else {
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
    let mut stage = if cfg!(feature = "ps2-graphics-help-smoke") || info_mode || edit_mode { 1u8 } else { 0u8 };
    let mut editor = LineEditor::<12>::new();
    let mut rejected_overlong = false;
    serial::write_line("WOLFOS_PS2_READY mode=polling keyboard=set1 graphical=1");
    if stage == 1 {
        console.write("> ");
        console.render(white, 0, |offset, color| {
            // SAFETY: bounded mapped framebuffer from validated Layout.
            unsafe { address.add(offset).cast::<u32>().write_volatile(color); }
        });
        serial::write_line("WOLFOS_PS2_PROMPT_READY");
    }
    loop {
        if let Some(scancode) = read_scancode() {
            if let Some(key) = decoder.feed(scancode) {
                accepted += 1;
                if accepted > 256 {
                    serial::write_line("WOLFOS_PS2_FAILED too_many_events");
                    crate::halt_forever();
                }
                match key {
                    Key::Character(c) => {
                        if stage == 0 || editor.push(c) {
                            console.write(core::str::from_utf8(&[c]).unwrap_or("?"));
                        }
                    }
                    Key::Backspace => {
                        if stage == 0 {
                            console.backspace();
                        } else if editor.backspace() {
                            console.backspace();
                        }
                    }
                    Key::Enter => console.write("\n"),
                }
                console.render(white, 0, |offset, color| {
                    // SAFETY: validated framebuffer offset, aligned 32-bit store.
                    unsafe { address.add(offset).cast::<u32>().write_volatile(color); }
                });
                serial::write_fmt(format_args!("WOLFOS_PS2_EVENT accepted={accepted}\n"));
                if stage == 0 && matches!(key, Key::Enter) {
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
                        stage = 1;
                        console.write("> ");
                        console.render(white, 0, |offset, color| {
                            // SAFETY: same bounded, verified 32-bpp framebuffer.
                            unsafe { address.add(offset).cast::<u32>().write_volatile(color); }
                        });
                        serial::write_line("WOLFOS_PS2_PROMPT_READY");
                    } else {
                        serial::write_line("WOLFOS_PS2_FAILED keyboard_or_framebuffer_mismatch");
                        crate::halt_forever();
                    }
                } else if stage != 0 && matches!(key, Key::Enter) {
                    let command = editor.submit();
                    // The shared parser classifies input. Only explicit
                    // read-only diagnostics are granted in this graphical
                    // prototype: PMM snapshot and cached early PCI discovery.
                    let stats = crate::pmm::statistics();
                    let report = graphical_diagnostics::diagnostic(
                        command, stats.free_frames(),
                        pci_summary.displays, pci_summary.networks, pci_summary.storage,
                    );
                    let answer = match command {
                        Command::Help => "HELP ABOUT",
                        Command::About => "WOLFOS RUST",
                        Command::TooLong => "TOO LONG",
                        Command::Empty => "",
                        Command::Unknown => "UNKNOWN",
                        Command::Memory | Command::Pci =>
                            report.as_ref().map(|line| line.as_str()).unwrap_or("DATA TOO LONG"),
                        // Privileged COM1-only actions remain unavailable.
                        _ => "NOT AVAILABLE",
                    };
                    console.write(answer);
                    console.render(white, 0, |offset, color| {
                        // SAFETY: the validated layout clips each 32-bpp pixel.
                        unsafe { address.add(offset).cast::<u32>().write_volatile(color); }
                    });
                    if edit_mode {
                        // Check actual post-Enter framebuffer bytes before any
                        // subsequent prompt erases the response or scrolls.
                        let pixel = |x, y| layout.pixel_offset(x, y).map(|offset| {
                            // SAFETY: Layout checked the mapped 32-bit pixel.
                            unsafe { address.add(offset).cast::<u32>().read_volatile() }
                        });
                        let expected = if rejected_overlong {
                            b"HELP ABOUT".as_slice()
                        } else {
                            b"TOO LONG".as_slice()
                        };
                        let text_matches = expected.iter().enumerate().all(|(i, c)| {
                            console.cell(i, 1) == Some(*c)
                        });
                        let pixels_match = if rejected_overlong {
                            // H top row begins lit, then dark.
                            pixel(20, 88) == Some(white) && pixel(21, 88) == Some(0)
                        } else {
                            // T has five lit pixels on top, then dark spacer.
                            pixel(20, 88) == Some(white) && pixel(24, 88) == Some(white)
                                && pixel(25, 88) == Some(0)
                        };
                        if !text_matches || !pixels_match {
                            serial::write_line("WOLFOS_PS2_EDIT_FAILED incorrect_text_or_pixels");
                            crate::halt_forever();
                        }
                        if !rejected_overlong && command == Command::TooLong {
                            rejected_overlong = true;
                            serial::write_line("WOLFOS_PS2_EDIT_REJECT_OK poisoned=1 pixels=verified");
                        } else if rejected_overlong && command == Command::Help {
                            serial::write_line("WOLFOS_PS2_EDIT_RECOVERY_OK next=HELP pixels=verified");
                            crate::halt_forever();
                        } else {
                            serial::write_line("WOLFOS_PS2_EDIT_FAILED unexpected_command");
                            crate::halt_forever();
                        }
                    }
                    if stage == 1 && command == Command::Help {
                        let pixel = |x, y| layout.pixel_offset(x, y).map(|offset| {
                            // SAFETY: Layout validated this pixel byte offset.
                            unsafe { address.add(offset).cast::<u32>().read_volatile() }
                        });
                        if console.cell(0, 1) == Some(b'H')
                            && console.cell(1, 1) == Some(b'E')
                            && pixel(20, 88) == Some(white)
                            && pixel(21, 88) == Some(0)
                        {
                            serial::write_line("WOLFOS_PS2_HELP_OK source=keyboard edit=backspace output=framebuffer pixels=verified");
                            stage = 2;
                        } else {
                            serial::write_line("WOLFOS_PS2_FAILED help_render");
                            crate::halt_forever();
                        }
                    }
                    if info_mode {
                        // Use real framebuffer readback and exact buffered
                        // diagnostic content, not just a successful log marker.
                        let pixel = |x, y| layout.pixel_offset(x, y).map(|offset| {
                            // SAFETY: Layout validated this mapped 32-bpp pixel.
                            unsafe { address.add(offset).cast::<u32>().read_volatile() }
                        });
                        let expected = if command == Command::Memory {
                            graphical_diagnostics::memory(stats.free_frames())
                        } else if command == Command::Pci {
                            graphical_diagnostics::pci(
                                pci_summary.displays, pci_summary.networks, pci_summary.storage,
                            )
                        } else { None };
                        let text_matches = expected.as_ref().map(|line| {
                            line.as_str().bytes().enumerate().all(|(i, c)| {
                                console.cell(i, 1) == Some(c)
                            })
                        }).unwrap_or(false);
                        let pixels_match = match command {
                            // M starts with a lit pixel followed by a dark one.
                            Command::Memory => pixel(20, 88) == Some(white)
                                && pixel(21, 88) == Some(0),
                            // P's top glyph row is 0b11110: four lit
                            // pixels, followed by a dark pixel.
                            Command::Pci => pixel(20, 88) == Some(white)
                                && pixel(21, 88) == Some(white)
                                && pixel(24, 88) == Some(0),
                            _ => false,
                        };
                        if !text_matches || !pixels_match {
                            serial::write_line("WOLFOS_PS2_INFO_FAILED bad_data_or_pixels");
                            crate::halt_forever();
                        }
                        match command {
                            Command::Memory => serial::write_fmt(format_args!(
                                "WOLFOS_PS2_MEM_OK free_frames={} mib={} pixels=verified\n",
                                stats.free_frames(), stats.free_frames() / 256,
                            )),
                            Command::Pci => serial::write_fmt(format_args!(
                                "WOLFOS_PS2_PCI_OK displays={} networks={} storage={} pixels=verified\n",
                                pci_summary.displays, pci_summary.networks, pci_summary.storage,
                            )),
                            _ => unreachable!(),
                        }
                        crate::halt_forever();
                    }
                    console.write("\n> ");
                    console.render(white, 0, |offset, color| {
                        // SAFETY: same validated mapped framebuffer.
                        unsafe { address.add(offset).cast::<u32>().write_volatile(color); }
                    });
                    if edit_mode && rejected_overlong {
                        serial::write_line("WOLFOS_PS2_EDIT_PROMPT_READY");
                    }
                }
            }
        } else {
            core::hint::spin_loop();
        }
    }
}
