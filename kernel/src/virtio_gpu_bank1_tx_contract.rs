//! Pure state/rollback contract for a QEMU-only selector transaction.
//! VirtIO 1.2: device_feature_select chooses 32-bit banks; VERSION_1 is bit32.
//! No driver features, queue addresses, status or notifications are modified.

pub const VERSION_1_BANK1_MASK:u32=1;
pub const FEATURE_SELECTOR:u64=0;
pub const FEATURE_WORD:u64=4;
pub const DEVICE_STATUS:u64=0x14;
pub const QUEUE_ENABLE:u64=0x1c;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Readback {
    pub selector_before:u32,
    pub selector_during:u32,
    pub selector_after:u32,
    pub bank0_before:u32,
    pub bank0_after:u32,
    pub bank1:u32,
    pub status_before:u8,
    pub status_after:u8,
    pub queue_enabled_before:u16,
    pub queue_enabled_after:u16,
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum TransactionError {
    InitiallySelectedOtherBank,
    BankSwitchFailed,
    SelectorNotRestored,
    BankZeroChanged,
    DeviceWasOrBecameActive,
    QueueWasOrBecameEnabled,
    MissingVirtioVersionOne,
}

pub fn verify(read:Readback)->Result<(),TransactionError> {
    if read.selector_before!=0 {return Err(TransactionError::InitiallySelectedOtherBank);}
    if read.selector_during!=1 {return Err(TransactionError::BankSwitchFailed);}
    if read.selector_after!=read.selector_before {
        return Err(TransactionError::SelectorNotRestored);
    }
    if read.bank0_after!=read.bank0_before {
        return Err(TransactionError::BankZeroChanged);
    }
    if read.status_before!=0 || read.status_after!=0 {
        return Err(TransactionError::DeviceWasOrBecameActive);
    }
    if read.queue_enabled_before!=0 || read.queue_enabled_after!=0 {
        return Err(TransactionError::QueueWasOrBecameEnabled);
    }
    if read.bank1 & VERSION_1_BANK1_MASK == 0 {
        return Err(TransactionError::MissingVirtioVersionOne);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good()->Readback {
        Readback{selector_before:0,selector_during:1,selector_after:0,
                 bank0_before:2,bank0_after:2,bank1:1,
                 status_before:0,status_after:0,
                 queue_enabled_before:0,queue_enabled_after:0}
    }
    #[test] fn exact_two_bank_roundtrip_succeeds() {
        assert_eq!(verify(good()),Ok(()));
    }
    #[test] fn other_bank_preselected_is_not_touched() {
        let mut x=good();x.selector_before=1;
        assert_eq!(verify(x),Err(TransactionError::InitiallySelectedOtherBank));
    }
    #[test] fn selector_write_must_take_effect() {
        let mut x=good();x.selector_during=0;
        assert_eq!(verify(x),Err(TransactionError::BankSwitchFailed));
    }
    #[test] fn selector_must_be_restored() {
        let mut x=good();x.selector_after=1;
        assert_eq!(verify(x),Err(TransactionError::SelectorNotRestored));
    }
    #[test] fn bank0_must_be_identical_after_rollback() {
        let mut x=good();x.bank0_after=3;
        assert_eq!(verify(x),Err(TransactionError::BankZeroChanged));
    }
    #[test] fn prior_device_status_is_not_allowed() {
        let mut x=good();x.status_before=1;
        assert_eq!(verify(x),Err(TransactionError::DeviceWasOrBecameActive));
    }
    #[test] fn newly_started_device_state_is_rejected() {
        let mut x=good();x.status_after=4;
        assert_eq!(verify(x),Err(TransactionError::DeviceWasOrBecameActive));
    }
    #[test] fn prior_or_new_queue_enable_is_rejected() {
        let mut x=good();x.queue_enabled_before=1;
        assert_eq!(verify(x),Err(TransactionError::QueueWasOrBecameEnabled));
        let mut x=good();x.queue_enabled_after=1;
        assert_eq!(verify(x),Err(TransactionError::QueueWasOrBecameEnabled));
    }
    #[test] fn version_one_must_be_advertised_in_bank_one() {
        let mut x=good();x.bank1=2;
        assert_eq!(verify(x),Err(TransactionError::MissingVirtioVersionOne));
    }
    #[test] fn other_feature_bits_are_allowed() {
        let mut x=good();x.bank1=0xffff_ffff;
        assert_eq!(verify(x),Ok(()));
    }
    #[test] fn constants_match_spec() {
        assert_eq!((FEATURE_SELECTOR,FEATURE_WORD,DEVICE_STATUS,
                    QUEUE_ENABLE,VERSION_1_BANK1_MASK),(0,4,20,28,1));
    }
}
