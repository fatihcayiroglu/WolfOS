//! Transactional display-mode change (pure policy: no I/O, no allocation).
//!
//! A mode change is not a function call that returns "ok". It is a windowed
//! transaction with a known-good previous mode, a real device readback, an
//! independent confirmation and a mandatory, verifiable rollback when any step
//! does not hold. This module owns that state machine so the driver cannot
//! decide the outcome ad hoc:
//!
//! ```text
//!  begin ──> Pending ──apply+readback──> Pending(readback)
//!              │                              │
//!              │ host attestation at the      ├─ confirm  ──> Confirmed
//!              │ requested geometry           │
//!              │                              └─ expiry   ──> RollingBack
//!              ├─ readback mismatch ───────────────────────> RollingBack
//!              └─ peer refusal ────────────────────────────> RollingBack
//!                                            RollingBack ──verified restore──> RolledBack
//!                                            RollingBack ──unverified────────> Unreconciled
//! ```
//!
//! Hard rules enforced here, each with a host test:
//!
//! * Nothing is confirmed before a readback and a *host-attested* observation
//!   exist. A driver that only asks the device "did you apply it?" cannot
//!   confirm its own switch.
//! * The deadline is checked by the state machine; an early expiry claim is
//!   refused instead of being obeyed.
//! * A rollback is complete only when the restored geometry is again proven by
//!   an independent observation. Otherwise the transaction is `Unreconciled`
//!   and the pinned resources may NOT be released.
//! * `ModeChangePlan` still supplies the proven previous/requested entries, so
//!   the rollback target can never be a device claim or an EDID mode.

use crate::display_mode_catalog::{
    CatalogError, ModeCatalog, ModeChangePlan, ModeEntry, RefreshEvidence,
};
use crate::display_mode_policy::UserChoice;

/// One confirmation window, shared with the catalog so the two can never
/// disagree about how long a user has to keep a new mode.
pub const CONFIRM_WINDOW_MS: u64 = crate::display_mode_catalog::CONFIRM_WINDOW_MS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Applied (or being applied) and waiting for the user's verdict.
    Pending,
    /// The switch is abandoned; the previous mode must be restored and proven.
    RollingBack,
    /// Confirmed by a host-attested observation inside the window.
    Confirmed,
    /// Restored to the previous proven mode and verified.
    RolledBack,
    /// Restoration could not be verified. Resources stay pinned until reset.
    Unreconciled,
}

impl State {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::RollingBack => "rolling_back",
            Self::Confirmed => "confirmed",
            Self::RolledBack => "rolled_back",
            Self::Unreconciled => "unreconciled",
        }
    }

    /// An open transaction keeps its scanout resources owned.
    pub const fn open(self) -> bool {
        matches!(self, Self::Pending | Self::RollingBack)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    Catalog(CatalogError),
    /// The device readback was already recorded for this transaction.
    AlreadyApplied,
    /// A confirmation arrived without any device readback.
    NotApplied,
    /// The device did not show the requested geometry.
    DeviceDidNotApply,
    /// A confirmation needs an independent host-attested observation.
    ConfirmationUnverified,
    /// The transaction already reached a final state.
    AlreadySettled,
    /// No rollback is in progress.
    NotRollingBack,
    /// The claimed expiry is earlier than the real deadline.
    DeadlineNotReached,
    /// The restored observation is not a proven mode at the previous geometry.
    RollbackUnverified,
}

impl TxError {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Catalog(error) => error.label(),
            Self::AlreadyApplied => "already_applied",
            Self::NotApplied => "not_applied",
            Self::DeviceDidNotApply => "device_did_not_apply",
            Self::ConfirmationUnverified => "confirmation_unverified",
            Self::AlreadySettled => "already_settled",
            Self::NotRollingBack => "not_rolling_back",
            Self::DeadlineNotReached => "deadline_not_reached",
            Self::RollbackUnverified => "rollback_unverified",
        }
    }
}

/// One in-flight mode change. Owning this value is what keeps the scanout
/// resources pinned; it has no `Copy` so a transaction cannot be silently
/// duplicated into two disagreeing decisions.
/// What the device itself reported after the driver applied the request.
///
/// Some devices (QEMU's virtio-vga among them) answer `GET_DISPLAY_INFO` with
/// the console geometry rather than the scanout rectangle the driver set, so
/// they can only prove that the scanout is enabled and attached. That weaker
/// signal is a named state, never a silent substitution: the geometry and pixel
/// authority stays the independent host capture, and a device that reports a
/// *contradicting* geometry still forces a rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The device reports exactly the requested rectangle.
    Geometry(ModeEntry),
    /// The device reports scanout enabled but cannot report our rectangle.
    ScanoutEnabled,
}

impl Applied {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Geometry(_) => "device",
            Self::ScanoutEnabled => "console_enabled",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ModeChangeTransaction {
    plan: ModeChangePlan,
    state: State,
    readback: Option<Applied>,
    settled: Option<ModeEntry>,
}

impl ModeChangeTransaction {
    /// Plans a change against the host-verified catalog, or `Ok(None)` when the
    /// requested mode is already the current one (no window may be opened for
    /// a switch that never happens).
    pub fn begin(
        catalog: &ModeCatalog,
        current_generation: u64,
        current: ModeEntry,
        choice: UserChoice,
        confirmation_token: u64,
        now_ms: u64,
    ) -> Result<Option<Self>, TxError> {
        match catalog.plan_change(
            current_generation,
            current,
            choice,
            confirmation_token,
            now_ms,
        ) {
            Ok(None) => Ok(None),
            Ok(Some(plan)) => Ok(Some(Self {
                plan,
                state: State::Pending,
                readback: None,
                settled: None,
            })),
            Err(error) => Err(TxError::Catalog(error)),
        }
    }

    pub const fn plan(&self) -> ModeChangePlan {
        self.plan
    }

    pub const fn state(&self) -> State {
        self.state
    }

    pub const fn requested(&self) -> ModeEntry {
        self.plan.requested
    }

    pub const fn previous(&self) -> ModeEntry {
        self.plan.previous
    }

    pub const fn token(&self) -> u64 {
        self.plan.confirmation_token
    }

    pub const fn deadline_ms(&self) -> u64 {
        self.plan.confirmation_deadline_ms
    }

    /// The mode the driver may present as current, and only once settled.
    pub const fn settled_mode(&self) -> Option<ModeEntry> {
        self.settled
    }

    /// The scanout geometry the device itself reported, when it reports one.
    pub const fn readback(&self) -> Option<ModeEntry> {
        match self.readback {
            Some(Applied::Geometry(entry)) => Some(entry),
            _ => None,
        }
    }

    /// `device` / `console_enabled` / `none` for serial evidence.
    pub const fn applied_label(&self) -> &'static str {
        match self.readback {
            Some(applied) => applied.label(),
            None => "none",
        }
    }

    /// `confirmed` / `rolled_back` / `open` / `unreconciled` for serial
    /// evidence. Derived from the state, never supplied by the caller.
    pub const fn outcome(&self) -> &'static str {
        match self.state {
            State::Confirmed => "confirmed",
            State::RolledBack => "rolled_back",
            State::Unreconciled => "unreconciled",
            State::Pending | State::RollingBack => "open",
        }
    }

    /// Pinned backing/scanout resources may be released only after a verified
    /// confirmation or a verified restoration.
    pub const fn resources_may_be_released(&self) -> bool {
        matches!(self.state, State::Confirmed | State::RolledBack)
    }

    /// Records the device's own readback of the scanout rectangle after the
    /// driver applied the request. It proves the device switched; it proves
    /// nothing about the pixels, so it is stored as a non-selectable claim.
    pub fn observe_applied(&mut self, observed: ModeEntry) -> Result<ModeEntry, TxError> {
        match self.state {
            State::Pending => {}
            State::RollingBack => return Err(TxError::DeviceDidNotApply),
            _ => return Err(TxError::AlreadySettled),
        }
        if self.readback.is_some() {
            return Err(TxError::AlreadyApplied);
        }
        if !observed.same_geometry(self.plan.requested) {
            // A device that kept the old geometry (or reports another one) must
            // never be confirmed: the switch simply did not happen.
            self.state = State::RollingBack;
            return Err(TxError::DeviceDidNotApply);
        }
        self.readback = Some(Applied::Geometry(ModeEntry::device_reported(
            self.plan.requested.scanout,
            observed.width,
            observed.height,
            RefreshEvidence::Unavailable,
        )));
        Ok(self.plan.requested)
    }

    /// Records that the device reports its scanout as enabled and attached,
    /// without reporting our rectangle. Used only when the driver has already
    /// established that this device answers `GET_DISPLAY_INFO` with a stable
    /// console geometry; it proves the scanout is live, never its size, and a
    /// disabled scanout aborts the change immediately.
    pub fn observe_scanout_enabled(&mut self, enabled: bool) -> Result<(), TxError> {
        match self.state {
            State::Pending => {}
            State::RollingBack => return Err(TxError::DeviceDidNotApply),
            _ => return Err(TxError::AlreadySettled),
        }
        if self.readback.is_some() {
            return Err(TxError::AlreadyApplied);
        }
        if !enabled {
            self.state = State::RollingBack;
            return Err(TxError::DeviceDidNotApply);
        }
        self.readback = Some(Applied::ScanoutEnabled);
        Ok(())
    }

    /// Accepts the user's verdict inside the window. `observed` must be a
    /// host-attested entry at the requested geometry: the confirmation of a
    /// mode change is independent evidence, not the driver's own claim.
    pub fn confirm(
        &mut self,
        token: u64,
        connector_generation: u64,
        observed: ModeEntry,
        now_ms: u64,
    ) -> Result<ModeEntry, TxError> {
        if self.state != State::Pending {
            return Err(TxError::AlreadySettled);
        }
        if self.readback.is_none() {
            return Err(TxError::NotApplied);
        }
        if !observed.selectable() {
            return Err(TxError::ConfirmationUnverified);
        }
        match self
            .plan
            .confirm(token, connector_generation, observed, now_ms)
        {
            Ok(applied) => {
                self.state = State::Confirmed;
                self.settled = Some(self.plan.requested);
                Ok(applied)
            }
            Err(CatalogError::ConfirmationExpired) => {
                self.state = State::RollingBack;
                Err(TxError::Catalog(CatalogError::ConfirmationExpired))
            }
            Err(CatalogError::DeviceDidNotApply) => {
                self.state = State::RollingBack;
                Err(TxError::Catalog(CatalogError::DeviceDidNotApply))
            }
            Err(error) => Err(TxError::Catalog(error)),
        }
    }

    /// Closes an open transaction because the window really passed. Early
    /// expiry claims are refused, so a peer cannot shorten the window to force
    /// a rollback the user never asked for.
    pub fn expire(&mut self, now_ms: u64) -> Result<ModeEntry, TxError> {
        if self.state != State::Pending {
            return Err(TxError::AlreadySettled);
        }
        if !self.plan.timed_out(now_ms) {
            return Err(TxError::DeadlineNotReached);
        }
        self.state = State::RollingBack;
        Ok(self.plan.rollback_target())
    }

    /// Abandons the change for a reason the state machine does not grade
    /// (peer refusal, hotplug, readback mismatch) and returns the proven
    /// previous mode that must be restored.
    pub fn rollback(&mut self) -> Result<ModeEntry, TxError> {
        match self.state {
            State::Pending => {}
            State::RollingBack => return Ok(self.plan.rollback_target()),
            _ => return Err(TxError::AlreadySettled),
        }
        self.state = State::RollingBack;
        Ok(self.plan.rollback_target())
    }

    /// The restoration is complete only when an independent observation again
    /// proves the previous mode. Anything else leaves the transaction
    /// `Unreconciled`, which forbids releasing the pinned resources.
    pub fn complete_rollback(&mut self, observed: ModeEntry) -> Result<ModeEntry, TxError> {
        if self.state != State::RollingBack {
            return Err(TxError::NotRollingBack);
        }
        if !observed.selectable() || !observed.same_geometry(self.plan.previous) {
            self.state = State::Unreconciled;
            return Err(TxError::RollbackUnverified);
        }
        self.state = State::RolledBack;
        self.settled = Some(self.plan.previous);
        Ok(self.plan.previous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display_mode_catalog::{Attestation, ModeCatalog};
    use crate::display_mode_policy::{RefreshChoice, ResolutionChoice};

    /// Only `decode_attestation_reply` (or, in tests, `Attestation::for_test`)
    /// can produce these: the proof field is private to the catalog module.
    fn attested(scanout: u8, width: u32, height: u32, nonce: u64) -> ModeEntry {
        Attestation::for_test(nonce, width, height, 0x5a5a_1234).entry(scanout)
    }
    fn desktop() -> ModeEntry {
        attested(0, 1024, 768, 0x574f_4445_534b_0004)
    }
    fn reduced() -> ModeEntry {
        attested(0, 1024, 384, 0x574f_4445_534b_0005)
    }
    const DEVICE_1280: ModeEntry = ModeEntry::device_reported(
        0,
        1280,
        800,
        RefreshEvidence::Unavailable,
    );
    const GENERATION: u64 = 3;
    const TOKEN: u64 = 0x574f_4c46_5458_0001;

    fn catalog() -> ModeCatalog {
        let mut modes = ModeCatalog::new(GENERATION).unwrap();
        modes.record(desktop()).unwrap();
        modes.record(reduced()).unwrap();
        modes.record(DEVICE_1280).unwrap();
        modes
    }

    fn request(width: u32, height: u32) -> UserChoice {
        UserChoice {
            resolution: ResolutionChoice::Exact { width, height },
            refresh: RefreshChoice::Automatic,
        }
    }

    /// A device that really applied the switch reports the new rectangle.
    fn applied(height: u32) -> ModeEntry {
        ModeEntry::device_reported(0, 1024, height, RefreshEvidence::Unavailable)
    }

    fn begin_reduced() -> ModeChangeTransaction {
        ModeChangeTransaction::begin(
            &catalog(),
            GENERATION,
            desktop(),
            request(1024, 384),
            TOKEN,
            1_000,
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn begin_targets_only_host_verified_entries() {
        let tx = begin_reduced();
        assert_eq!(tx.requested(), reduced());
        assert_eq!(tx.previous(), desktop());
        assert!(tx.requested().selectable());
        assert!(tx.previous().selectable());
        assert_eq!(tx.deadline_ms(), 1_000 + CONFIRM_WINDOW_MS);
        assert_eq!(tx.state(), State::Pending);
        assert!(tx.state().open());
        assert!(!tx.resources_may_be_released());
    }

    #[test]
    fn already_applied_mode_opens_no_window() {
        let modes = catalog();
        assert_eq!(
            ModeChangeTransaction::begin(
                &modes,
                GENERATION,
                desktop(),
                UserChoice::AUTOMATIC,
                TOKEN,
                1_000
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn unproven_or_malformed_requests_are_refused_by_the_catalog() {
        let modes = catalog();
        for outcome in [
            ModeChangeTransaction::begin(
                &modes,
                GENERATION,
                desktop(),
                request(1280, 800),
                TOKEN,
                1_000,
            )
            .err(),
            ModeChangeTransaction::begin(
                &modes,
                GENERATION,
                DEVICE_1280,
                request(1024, 384),
                TOKEN,
                1_000,
            )
            .err(),
            ModeChangeTransaction::begin(
                &modes,
                GENERATION + 1,
                desktop(),
                request(1024, 384),
                TOKEN,
                1_000,
            )
            .err(),
            ModeChangeTransaction::begin(
                &modes,
                GENERATION,
                desktop(),
                request(1024, 384),
                0,
                1_000,
            )
            .err(),
        ] {
            assert!(matches!(outcome, Some(TxError::Catalog(_))));
        }
    }

    #[test]
    fn confirmation_before_a_readback_is_refused() {
        let mut tx = begin_reduced();
        assert_eq!(
            tx.confirm(TOKEN, GENERATION, reduced(), 2_000),
            Err(TxError::NotApplied)
        );
        assert_eq!(tx.state(), State::Pending);
        assert_eq!(tx.settled_mode(), None);
    }

    #[test]
    fn a_device_readback_alone_cannot_confirm_the_switch() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        // The device's own claim is a non-selectable entry: no matter how many
        // times it is offered, it cannot close the transaction.
        assert_eq!(
            tx.confirm(TOKEN, GENERATION, applied(384), 2_000),
            Err(TxError::ConfirmationUnverified)
        );
        assert_eq!(tx.state(), State::Pending);
    }

    #[test]
    fn host_attested_observation_confirms_inside_the_window() {
        let mut tx = begin_reduced();
        assert_eq!(tx.observe_applied(applied(384)), Ok(reduced()));
        assert_eq!(tx.confirm(TOKEN, GENERATION, reduced(), 15_999), Ok(reduced()));
        assert_eq!(tx.state(), State::Confirmed);
        assert_eq!(tx.outcome(), "confirmed");
        assert_eq!(tx.settled_mode(), Some(reduced()));
        assert!(tx.resources_may_be_released());
    }

    #[test]
    fn readback_of_the_old_geometry_forces_a_rollback() {
        let mut tx = begin_reduced();
        assert_eq!(
            tx.observe_applied(applied(768)),
            Err(TxError::DeviceDidNotApply)
        );
        assert_eq!(tx.state(), State::RollingBack);
        assert!(!tx.resources_may_be_released());
        assert_eq!(tx.expire(u64::MAX), Err(TxError::AlreadySettled));
        assert_eq!(tx.confirm(TOKEN, GENERATION, reduced(), 2_000), Err(TxError::AlreadySettled));
    }

    #[test]
    fn a_second_readback_is_refused() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        assert_eq!(tx.observe_applied(applied(384)), Err(TxError::AlreadyApplied));
    }

    #[test]
    fn confirmation_at_or_after_the_deadline_rolls_back() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        assert_eq!(
            tx.confirm(TOKEN, GENERATION, reduced(), 16_000),
            Err(TxError::Catalog(CatalogError::ConfirmationExpired))
        );
        assert_eq!(tx.state(), State::RollingBack);
        assert_eq!(tx.settled_mode(), None);
    }

    #[test]
    fn a_wrong_token_or_generation_keeps_the_transaction_pending() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        assert_eq!(
            tx.confirm(TOKEN + 1, GENERATION, reduced(), 2_000),
            Err(TxError::Catalog(CatalogError::InvalidTransaction))
        );
        assert_eq!(
            tx.confirm(TOKEN, GENERATION + 1, reduced(), 2_000),
            Err(TxError::Catalog(CatalogError::StaleConnector))
        );
        assert_eq!(tx.state(), State::Pending);
    }

    #[test]
    fn an_early_expiry_claim_is_refused() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        for now in [0, 1_000, 15_999] {
            assert_eq!(tx.expire(now), Err(TxError::DeadlineNotReached));
            assert_eq!(tx.state(), State::Pending);
        }
        assert_eq!(tx.expire(16_000), Ok(desktop()));
        assert_eq!(tx.state(), State::RollingBack);
        assert_eq!(tx.settled_mode(), None);
        assert!(!tx.resources_may_be_released());
    }

    #[test]
    fn rollback_target_is_the_proven_previous_mode() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        assert_eq!(tx.rollback(), Ok(desktop()));
        assert!(tx.previous().selectable());
        assert_eq!(tx.rollback(), Ok(desktop()));
        assert_eq!(tx.state(), State::RollingBack);
    }

    #[test]
    fn a_restored_mode_must_be_host_proven_at_the_previous_geometry() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        tx.rollback().unwrap();
        // A device claim is not restoration proof.
        assert_eq!(
            tx.complete_rollback(ModeEntry::device_reported(
                0,
                1024,
                768,
                RefreshEvidence::Unavailable
            )),
            Err(TxError::RollbackUnverified)
        );
        assert_eq!(tx.state(), State::Unreconciled);
        assert!(!tx.resources_may_be_released());
    }

    #[test]
    fn restoration_proven_at_the_wrong_geometry_is_unreconciled() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        tx.rollback().unwrap();
        assert_eq!(tx.complete_rollback(reduced()), Err(TxError::RollbackUnverified));
        assert_eq!(tx.state(), State::Unreconciled);
        assert_eq!(tx.outcome(), "unreconciled");
    }

    #[test]
    fn verified_restoration_closes_the_transaction() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        assert_eq!(tx.expire(16_000), Ok(desktop()));
        assert_eq!(tx.complete_rollback(desktop()), Ok(desktop()));
        assert_eq!(tx.state(), State::RolledBack);
        assert_eq!(tx.outcome(), "rolled_back");
        assert_eq!(tx.settled_mode(), Some(desktop()));
        assert!(tx.resources_may_be_released());
    }

    #[test]
    fn a_confirmed_transaction_cannot_be_rolled_back() {
        let mut tx = begin_reduced();
        tx.observe_applied(applied(384)).unwrap();
        tx.confirm(TOKEN, GENERATION, reduced(), 2_000).unwrap();
        assert_eq!(tx.rollback(), Err(TxError::AlreadySettled));
        assert_eq!(tx.expire(u64::MAX), Err(TxError::AlreadySettled));
        assert_eq!(tx.complete_rollback(desktop()), Err(TxError::NotRollingBack));
        assert_eq!(tx.state(), State::Confirmed);
    }

    #[test]
    fn settlement_never_exposes_an_unproven_mode() {
        let mut confirmed = begin_reduced();
        confirmed.observe_applied(applied(384)).unwrap();
        confirmed.confirm(TOKEN, GENERATION, reduced(), 2_000).unwrap();
        assert!(confirmed.settled_mode().unwrap().selectable());
        let mut rolled = begin_reduced();
        rolled.observe_applied(applied(384)).unwrap();
        rolled.expire(16_000).unwrap();
        rolled.complete_rollback(desktop()).unwrap();
        assert!(rolled.settled_mode().unwrap().selectable());
        assert_eq!(rolled.readback().unwrap().width, 1024);
        assert!(!rolled.readback().unwrap().selectable());
    }

    #[test]
    fn console_geometry_device_still_needs_host_pixels_to_confirm() {
        let mut tx = begin_reduced();
        assert_eq!(tx.observe_scanout_enabled(true), Ok(()));
        assert_eq!(tx.applied_label(), "console_enabled");
        // The device proved only that the scanout is live, never its size.
        assert_eq!(tx.readback(), None);
        assert_eq!(
            tx.confirm(TOKEN, GENERATION, applied(384), 2_000),
            Err(TxError::ConfirmationUnverified)
        );
        assert_eq!(tx.state(), State::Pending);
        assert_eq!(tx.confirm(TOKEN, GENERATION, reduced(), 2_000), Ok(reduced()));
        assert_eq!(tx.state(), State::Confirmed);
    }

    #[test]
    fn a_disabled_scanout_aborts_the_change() {
        let mut tx = begin_reduced();
        assert_eq!(
            tx.observe_scanout_enabled(false),
            Err(TxError::DeviceDidNotApply)
        );
        assert_eq!(tx.state(), State::RollingBack);
        assert_eq!(tx.applied_label(), "none");
        assert!(!tx.resources_may_be_released());
    }

    #[test]
    fn the_applied_signal_is_recorded_once() {
        let mut tx = begin_reduced();
        tx.observe_scanout_enabled(true).unwrap();
        assert_eq!(tx.observe_scanout_enabled(true), Err(TxError::AlreadyApplied));
        let mut other = begin_reduced();
        other.observe_applied(applied(384)).unwrap();
        assert_eq!(other.observe_scanout_enabled(true), Err(TxError::AlreadyApplied));
        assert_eq!(other.applied_label(), "device");
    }

    #[test]
    fn labels_are_stable_for_serial_evidence() {
        for (error, label) in [
            (TxError::DeviceDidNotApply, "device_did_not_apply"),
            (TxError::ConfirmationUnverified, "confirmation_unverified"),
            (TxError::DeadlineNotReached, "deadline_not_reached"),
            (TxError::RollbackUnverified, "rollback_unverified"),
            (TxError::NotApplied, "not_applied"),
            (TxError::AlreadyApplied, "already_applied"),
        ] {
            assert_eq!(error.label(), label);
        }
        for (state, label) in [
            (State::Pending, "pending"),
            (State::RollingBack, "rolling_back"),
            (State::Confirmed, "confirmed"),
            (State::RolledBack, "rolled_back"),
            (State::Unreconciled, "unreconciled"),
        ] {
            assert_eq!(state.label(), label);
        }
    }

    #[test]
    fn the_window_is_exactly_fifteen_seconds() {
        assert_eq!(CONFIRM_WINDOW_MS, 15_000);
        let tx = begin_reduced();
        assert_eq!(tx.deadline_ms() - 1_000, CONFIRM_WINDOW_MS);
    }
}
