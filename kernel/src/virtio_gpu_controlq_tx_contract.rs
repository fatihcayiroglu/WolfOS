//! Pure QEMU VirtIO 1.2 split controlq0 register/reset observation contract.
//! A successful observation proves registration AND reset; no DRIVER_OK, no notify.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub status_before: u8,
    pub enabled_before: u16,
    pub size_before: u16,
    pub driver_selector_before: u32,
    pub initial_reset: u8,
    pub ack: u8,
    pub driver: u8,
    pub driver_selector_during: u32,
    pub accepted_version1: u32,
    pub driver_selector_after: u32,
    pub features_ok: u8,
    pub size_written: u16,
    pub desc_written: u64,
    pub avail_written: u64,
    pub used_written: u64,
    pub enabled_written: u16,
    pub final_status: u8,
    pub final_enabled: u16,
    pub reset_confirmed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InitialState, Handshake, QueueAddresses, QueueEnable, ResetUnconfirmed,
}
pub fn validate(
    s: Observation, selected: u16, desc: u64, avail: u64, used: u64,
) -> Result<(), Error> {
    if s.status_before != 0 || s.enabled_before != 0
        || s.size_before < selected || s.driver_selector_before != 0
    { return Err(Error::InitialState); }
    if s.initial_reset != 0 || s.ack != 1 || s.driver != 3
        || s.driver_selector_during != 1 || s.accepted_version1 != 1
        || s.driver_selector_after != 0 || s.features_ok != 11
    { return Err(Error::Handshake); }
    if s.size_written != selected || s.desc_written != desc
        || s.avail_written != avail || s.used_written != used
    { return Err(Error::QueueAddresses); }
    if s.enabled_written != 1 { return Err(Error::QueueEnable); }
    if !s.reset_confirmed || s.final_status != 0 || s.final_enabled != 0
    { return Err(Error::ResetUnconfirmed); }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Observation {
        Observation {
            status_before:0, enabled_before:0, size_before:256,
            driver_selector_before:0, initial_reset:0, ack:1, driver:3,
            driver_selector_during:1, accepted_version1:1,
            driver_selector_after:0, features_ok:11, size_written:256,
            desc_written:0x1000, avail_written:0x2000, used_written:0x3000,
            enabled_written:1, final_status:0, final_enabled:0,
            reset_confirmed:true,
        }
    }
    fn check(s:Observation)->Result<(),Error>{
        validate(s,256,0x1000,0x2000,0x3000)
    }
    #[test] fn good_transaction_reset() { assert_eq!(check(good()),Ok(())); }
    #[test] fn reject_active_before() {
        let mut s=good();s.status_before=3;
        assert_eq!(check(s),Err(Error::InitialState));
        let mut s=good();s.enabled_before=1;
        assert_eq!(check(s),Err(Error::InitialState));
        let mut s=good();s.size_before=128;
        assert_eq!(check(s),Err(Error::InitialState));
        let mut s=good();s.driver_selector_before=1;
        assert_eq!(check(s),Err(Error::InitialState));
    }
    #[test] fn reject_bad_handshake() {
        let mut s=good();s.ack=0;
        assert_eq!(check(s),Err(Error::Handshake));
        let mut s=good();s.driver=2;
        assert_eq!(check(s),Err(Error::Handshake));
        let mut s=good();s.features_ok=3;
        assert_eq!(check(s),Err(Error::Handshake));
        let mut s=good();s.accepted_version1=0;
        assert_eq!(check(s),Err(Error::Handshake));
        let mut s=good();s.driver_selector_after=1;
        assert_eq!(check(s),Err(Error::Handshake));
    }
    #[test] fn reject_wrong_size_or_addresses() {
        let mut s=good();s.size_written=128;
        assert_eq!(check(s),Err(Error::QueueAddresses));
        let mut s=good();s.desc_written=0x4000;
        assert_eq!(check(s),Err(Error::QueueAddresses));
        let mut s=good();s.avail_written=0;
        assert_eq!(check(s),Err(Error::QueueAddresses));
        let mut s=good();s.used_written=0;
        assert_eq!(check(s),Err(Error::QueueAddresses));
    }
    #[test] fn reject_queue_not_enabled() {
        let mut s=good();s.enabled_written=0;
        assert_eq!(check(s),Err(Error::QueueEnable));
    }
    #[test] fn reject_unsafe_free_before_reset() {
        let mut s=good();s.reset_confirmed=false;
        assert_eq!(check(s),Err(Error::ResetUnconfirmed));
        let mut s=good();s.final_status=11;
        assert_eq!(check(s),Err(Error::ResetUnconfirmed));
        let mut s=good();s.final_enabled=1;
        assert_eq!(check(s),Err(Error::ResetUnconfirmed));
    }
}
