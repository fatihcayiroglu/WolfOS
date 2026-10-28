//! Standalone rustc --test host wrapper for the shared Bochs VBE observation
//! and the no-I/O Limine framebuffer attestation policy.
#[path = "qemu_dispi_contract.rs"]
mod qemu_dispi_contract;
#[path = "qemu_display_attestation.rs"]
mod qemu_display_attestation;

#[path = "qemu_vbe_transaction_contract.rs"]
mod qemu_vbe_transaction_contract;

#[path = "qemu_vbe_full_state_contract.rs"]
mod qemu_vbe_full_state_contract;
