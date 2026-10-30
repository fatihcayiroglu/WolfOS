//! One host test binary for the exact display mode selection policy AND
//! EDID base-block parser, so prior tests are not run/count twice.
#[path = "display_mode_policy.rs"]
mod display_mode_policy;
#[path = "display_edid_base.rs"]
mod display_edid_base;
#[path = "display_edid_cta.rs"]
mod display_edid_cta;
#[path = "virtio_gpu_edid_wire.rs"]
mod virtio_gpu_edid_wire;
#[path = "display_mode_catalog.rs"]
mod display_mode_catalog;
#[path = "display_mode_transaction.rs"]
mod display_mode_transaction;
