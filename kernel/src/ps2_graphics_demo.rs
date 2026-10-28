//! Opt-in hardware proof: PS/2 keyboard make codes -> Rust text cells ->
//! checked, volatile QEMU framebuffer pixel writes. This is not the normal
//! boot path, a secure input subsystem, or a user-space graphical terminal.

use crate::{
    framebuffer_console::TextConsole,
    framebuffer_text::Layout,
    graphical_diagnostics,
    graphical_line_editor::LineEditor,
    pci::PciSummary,
    ps2_keyboard::{Key, Set1Decoder},
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
    #[cfg(feature = "ps2-graphics-irq-smoke")]
    {
        // Install PIC IRQ1 only after BSP's IDT and mapped framebuffer exist.
        // The actual ISR does not touch TextConsole or other Rust input state.
        crate::ps2_irq::start();
        serial::write_line("WOLFOS_PS2_IRQ_READY vector=33 queue=64");
    }
    serial::write_line("WOLFOS_PS2_READY mode=polling keyboard=set1 graphical=1");
    if stage == 1 {
        console.write("> ");
        console.render(white, 0, |offset, color| {
            // SAFETY: bounded mapped framebuffer from validated Layout.
            unsafe { address.add(offset).cast::<u32>().write_volatile(color); }
        });
        serial::write_line("WOLFOS_PS2_PROMPT_READY");
    }
    #[cfg(feature = "ps2-graphics-overflow-smoke")]
    {
        // After the prompt is fully drawn, leave IF enabled and deliberately
        // pause the foreground consumer. Only actual i8042 IRQ1 bytes may
        // fill the eight-slot hardware ring.
        serial::write_line("WOLFOS_PS2_OVERFLOW_READY capacity=8 foreground=held");
        loop {
            if crate::ps2_irq::evidence().3 {
                x86_64::instructions::interrupts::disable();
                let (irqs, eois, dropped, poisoned) = crate::ps2_irq::evidence();
                if !poisoned || irqs < 9 || eois != irqs || dropped == 0
                    || !matches!(crate::ps2_irq::take(), Err(()))
                {
                    serial::write_line("WOLFOS_PS2_OVERFLOW_FAILED counters_or_poison");
                    crate::halt_forever();
                }
                let first = layout.pixel_offset(20, 80).map(|offset| {
                    // SAFETY: validated mapped framebuffer pixel of '>'.
                    unsafe { address.add(offset).cast::<u32>().read_volatile() }
                });
                let second = layout.pixel_offset(21, 80).map(|offset| {
                    // SAFETY: validated mapped framebuffer pixel of '>'.
                    unsafe { address.add(offset).cast::<u32>().read_volatile() }
                });
                if accepted != 0 || first != Some(white) || second != Some(0) {
                    serial::write_line("WOLFOS_PS2_OVERFLOW_FAILED foreground_or_display");
                    crate::halt_forever();
                }
                serial::write_fmt(format_args!(
                    "WOLFOS_PS2_OVERFLOW_OK capacity=8 irqs={} eois={} dropped={} poison=1 decoded=0 pixels=verified\n",
                    irqs, eois, dropped,
                ));
                crate::halt_forever();
            }
            core::hint::spin_loop();
        }
    }
    #[cfg(not(feature = "ps2-graphics-overflow-smoke"))]
    loop {
        // Foreground input consumer. In the IRQ flavor all hardware 0x60/0x64
        // reads occur exclusively inside IRQ1; the consumer only pops bytes.
        #[cfg(feature = "ps2-graphics-irq-smoke")]
        let next = match crate::ps2_irq::take() {
            Ok(value) => value,
            Err(()) => {
                serial::write_line("WOLFOS_PS2_IRQ_FAILED dropped_raw_scancode");
                crate::halt_forever();
            }
        };
        #[cfg(not(feature = "ps2-graphics-irq-smoke"))]
        let next = crate::ps2_keyboard::read_scancode();
        if let Some(scancode) = next {
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
                    let report = if command == Command::Cpu {
                        let identity = crate::cpu::identify();
                        graphical_diagnostics::cpu(
                            identity.vendor_name(), identity.family, identity.model,
                        )
                    } else {
                        graphical_diagnostics::diagnostic(
                            command, stats.free_frames(),
                            pci_summary.displays, pci_summary.networks, pci_summary.storage,
                        )
                    };
                    let answer = match command {
                        Command::Help => "HELP ABOUT",
                        Command::About => "WOLFOS RUST",
                        Command::TooLong => "TOO LONG",
                        Command::Empty => "",
                        Command::Unknown => "UNKNOWN",
                        Command::Memory | Command::Pci | Command::Cpu =>
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
                            #[cfg(feature = "ps2-graphics-irq-smoke")]
                            {
                                // Freeze BSP IRQ dispatch while sampling a
                                // consistent ISR/EOI snapshot for QEMU proof.
                                x86_64::instructions::interrupts::disable();
                                let (irqs, eois, dropped, poisoned) = crate::ps2_irq::evidence();
                                if irqs < accepted || eois != irqs || dropped != 0 || poisoned {
                                    serial::write_line("WOLFOS_PS2_IRQ_FAILED missing_ack_or_dropped");
                                    crate::halt_forever();
                                }
                                serial::write_fmt(format_args!(
                                    "WOLFOS_PS2_IRQ_OK keys={} irqs={} eois={} drops={} pixels=verified\n",
                                    accepted, irqs, eois, dropped,
                                ));
                                crate::halt_forever();
                            }
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
                        } else if command == Command::Cpu {
                            let identity = crate::cpu::identify();
                            graphical_diagnostics::cpu(
                                identity.vendor_name(), identity.family, identity.model,
                            )
                        } else { None };
                        let text_matches = expected.as_ref().map(|line| {
                            line.as_str().bytes().enumerate().all(|(i, c)| {
                                console.cell(i, 1) == Some(c.to_ascii_uppercase())
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
                            // C top row is 0b01110: dark, three white, dark.
                            Command::Cpu => pixel(20, 88) == Some(0)
                                && pixel(21, 88) == Some(white)
                                && pixel(23, 88) == Some(white)
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
                            Command::Cpu => {
                                let identity = crate::cpu::identify();
                                let (Some(family), Some(model)) = (identity.family, identity.model) else {
                                    serial::write_line("WOLFOS_PS2_CPU_FAILED missing_feature_leaf");
                                    crate::halt_forever();
                                };
                                serial::write_fmt(format_args!(
                                    "WOLFOS_PS2_CPU_OK vendor={} family={} model={} pixels=verified\n",
                                    identity.vendor_name(), family, model,
                                ));
                            }
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
