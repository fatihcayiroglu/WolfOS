//! Pure contract for QEMU-only VirtIO 1.2 feature handshake + reset.
//! No DRIVER_OK, queue provisioning, notification, DMA or physical GPU.
pub const DRIVER_SELECT: u64 = 8;
pub const DRIVER_FEATURE: u64 = 12;
pub const DEVICE_STATUS: u64 = 20;
pub const QUEUE_ENABLE: u64 = 28;
pub const VERSION_ONE: u32 = 1;
pub const ACK: u8 = 1;
pub const DRIVER: u8 = 3;
pub const FEATURES_OK: u8 = 11;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub before: u8,
    pub initial_reset: u8,
    pub ack: u8,
    pub driver: u8,
    pub features_ok: u8,
    pub final_reset: u8,
    pub reset_completed: bool,
    pub driver_select_before: u32,
    pub driver_select_during: u32,
    pub driver_select_after: u32,
    pub accepted_bank1: u32,
    pub queue_before: u16,
    pub queue_after: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Active, FirstReset, Ack, Driver, Selector, Version,
    FeaturesRefused, FinalReset, QueueActive,
}
pub fn verify(o: Observation) -> Result<(), Error> {
    if o.before != 0 { return Err(Error::Active); }
    if o.initial_reset != 0 { return Err(Error::FirstReset); }
    if o.ack != ACK { return Err(Error::Ack); }
    if o.driver != DRIVER { return Err(Error::Driver); }
    if o.driver_select_before != 0 || o.driver_select_during != 1 ||
        o.driver_select_after != 0 { return Err(Error::Selector); }
    if o.accepted_bank1 != VERSION_ONE { return Err(Error::Version); }
    if o.features_ok != FEATURES_OK { return Err(Error::FeaturesRefused); }
    if !o.reset_completed || o.final_reset != 0 { return Err(Error::FinalReset); }
    if o.queue_before != 0 || o.queue_after != 0 { return Err(Error::QueueActive); }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Observation {
        Observation { before:0,initial_reset:0,ack:1,driver:3,
            features_ok:11,final_reset:0,reset_completed:true,
            driver_select_before:0,driver_select_during:1,driver_select_after:0,
            accepted_bank1:1,queue_before:0,queue_after:0 }
    }
    #[test] fn exact_roundtrip() { assert_eq!(verify(good()),Ok(())); }
    #[test] fn active_rejected() { let mut o=good();o.before=1;assert_eq!(verify(o),Err(Error::Active)); }
    #[test] fn first_reset_required() { let mut o=good();o.initial_reset=3;assert_eq!(verify(o),Err(Error::FirstReset)); }
    #[test] fn ack_exact() { let mut o=good();o.ack=3;assert_eq!(verify(o),Err(Error::Ack)); }
    #[test] fn driver_exact() { let mut o=good();o.driver=1;assert_eq!(verify(o),Err(Error::Driver)); }
    #[test] fn selector_before_zero() { let mut o=good();o.driver_select_before=1;assert_eq!(verify(o),Err(Error::Selector)); }
    #[test] fn selector_during_one() { let mut o=good();o.driver_select_during=0;assert_eq!(verify(o),Err(Error::Selector)); }
    #[test] fn selector_after_zero() { let mut o=good();o.driver_select_after=1;assert_eq!(verify(o),Err(Error::Selector)); }
    #[test] fn version_one_required() { let mut o=good();o.accepted_bank1=0;assert_eq!(verify(o),Err(Error::Version)); }
    #[test] fn features_ok_required() { let mut o=good();o.features_ok=3;assert_eq!(verify(o),Err(Error::FeaturesRefused)); }
    #[test] fn final_reset_required() { let mut o=good();o.reset_completed=false;assert_eq!(verify(o),Err(Error::FinalReset)); }
    #[test] fn status_zero_required() { let mut o=good();o.final_reset=11;assert_eq!(verify(o),Err(Error::FinalReset)); }
    #[test] fn queue_never_enabled() { let mut o=good();o.queue_after=1;assert_eq!(verify(o),Err(Error::QueueActive)); }
    #[test] fn constants_are_spec_offsets() { assert_eq!((DRIVER_SELECT,DRIVER_FEATURE,DEVICE_STATUS,QUEUE_ENABLE),(8,12,20,28)); }
}
