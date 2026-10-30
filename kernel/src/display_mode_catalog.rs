//! WolfOS verified display-mode catalog (pure, allocation-free, no I/O).
//!
//! A monitor's EDID describes the *monitor*. `GET_DISPLAY_INFO` describes the
//! scanout rectangle the *device* currently has configured. Neither is proof
//! that this GPU can drive a mode, and neither is proof the host really shows
//! it. Only a scanout that the driver actually applied AND that an independent
//! host capture verified at exactly that geometry becomes selectable here.
//!
//! Refresh is never inferred. A connector's EDID millihertz value is monitor
//! data; VirtIO-GPU exposes no pixel-clock programming, so an unproven rate
//! stays `RefreshEvidence::Unavailable` instead of being presented as a
//! supported refresh rate.
//!
//! `ModeEntry::proof` is private and `Attestation` has no public constructor,
//! so code outside this module can only express `DeviceReportedConfigured`
//! entries. A host-verified claim cannot be written down by a driver even by
//! mistake: it can only be the result of `decode_attestation_reply`.
//!
//! The graphical settings consumer is not wired into the boot path yet, so
//! these entry points are currently exercised by the host unit tests and the
//! QEMU native-rollback scenario only; dead-code warnings would otherwise
//! report this staged API as broken.
#![allow(dead_code)]

use crate::display_mode_policy::{RefreshChoice, ResolutionChoice, UserChoice};

/// Bounded so a broken or hostile device cannot exhaust kernel memory.
pub const MAX_CATALOG_ENTRIES: usize = 16;
/// VirtIO-GPU exposes at most sixteen scanouts.
pub const MAX_SCANOUTS: u8 = 16;
pub const CONFIRM_WINDOW_MS: u64 = 15_000;

/// A late *decision* has exactly two fields: X/E and decimal elapsed ms.
/// Do not confuse the E-stage pixel attestation (four fields) with an expiry.
/// This classifier never accepts an attestation, even one beginning with E.
pub fn is_elapsed_verdict_line(input: &[u8]) -> bool {
    let line = input.strip_suffix(b"\n").unwrap_or(input);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.len() < 3 || !matches!(line[0], b'X' | b'E') || line[1] != b' ' {
        return false;
    }
    let elapsed = &line[2..];
    elapsed.len() <= 12 && elapsed.iter().all(u8::is_ascii_digit)
}


/// What actually happened, not what a device claims it can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanoutProof {
    /// The driver created a resource, set this scanout geometry, and an
    /// independent host capture verified every pixel at exactly this geometry.
    HostVerifiedApplied,
    /// `GET_DISPLAY_INFO` reports this scanout geometry as configured, but no
    /// host-verified switch was performed by this driver. Never selectable.
    DeviceReportedConfigured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshEvidence {
    /// No pixel clock can be programmed or measured through this device, so no
    /// hertz value may be reported to the user for this mode.
    Unavailable,
    /// Integer millihertz that a driver independently programmed/measured.
    VerifiedMilliHz(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeEntry {
    pub scanout: u8,
    pub width: u32,
    pub height: u32,
    /// Private on purpose. See the module docs: only a host attestation may
    /// produce `HostVerifiedApplied`.
    proof: ScanoutProof,
    pub refresh: RefreshEvidence,
}

impl ModeEntry {
    pub const EMPTY: Self = Self {
        scanout: 0,
        width: 0,
        height: 0,
        proof: ScanoutProof::DeviceReportedConfigured,
        refresh: RefreshEvidence::Unavailable,
    };

    /// The only entry a device or EDID reading may produce. Never selectable.
    pub const fn device_reported(
        scanout: u8,
        width: u32,
        height: u32,
        refresh: RefreshEvidence,
    ) -> Self {
        Self {
            scanout,
            width,
            height,
            proof: ScanoutProof::DeviceReportedConfigured,
            refresh,
        }
    }

    pub const fn selectable(self) -> bool {
        matches!(self.proof, ScanoutProof::HostVerifiedApplied)
    }

    pub const fn area(self) -> u64 {
        self.width as u64 * self.height as u64
    }

    pub fn same_geometry(self, other: Self) -> bool {
        self.scanout == other.scanout
            && self.width == other.width
            && self.height == other.height
    }

    pub fn same_timing(self, other: Self) -> bool {
        self.same_geometry(other)
            && self.refresh == other.refresh
            && self.proof == other.proof
    }

    pub const fn refresh_label(self) -> &'static str {
        self.refresh.label()
    }
}

impl RefreshEvidence {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::VerifiedMilliHz(_) => "verified",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogError {
    InvalidGeneration,
    StaleConnector,
    InvalidEntry,
    ConflictingProof,
    CatalogOverflow,
    NoSelectableMode,
    /// The requested geometry has no host-verified scanout on this device.
    UnprovenGpuTiming,
    /// The requested rate cannot be programmed or measured on this device.
    RefreshNotProgrammable,
    UnsupportedSelection,
    InvalidTransaction,
    DeviceDidNotApply,
    ConfirmationExpired,
}

impl CatalogError {
    pub const fn label(self) -> &'static str {
        match self {
            Self::InvalidGeneration => "invalid_generation",
            Self::StaleConnector => "stale_connector",
            Self::InvalidEntry => "invalid_entry",
            Self::ConflictingProof => "conflicting_proof",
            Self::CatalogOverflow => "catalog_overflow",
            Self::NoSelectableMode => "no_selectable_mode",
            Self::UnprovenGpuTiming => "unproven_gpu_timing",
            Self::RefreshNotProgrammable => "refresh_not_programmable",
            Self::UnsupportedSelection => "unsupported_selection",
            Self::InvalidTransaction => "invalid_transaction",
            Self::DeviceDidNotApply => "device_did_not_apply",
            Self::ConfirmationExpired => "confirmation_expired",
        }
    }
}

/// A rollback *plan*, not an assertion that the device already switched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeChangePlan {
    pub previous: ModeEntry,
    pub requested: ModeEntry,
    pub connector_generation: u64,
    pub confirmation_token: u64,
    pub confirmation_deadline_ms: u64,
}

impl ModeChangePlan {
    pub fn rollback_target(self) -> ModeEntry {
        self.previous
    }

    pub fn timed_out(self, now_ms: u64) -> bool {
        now_ms >= self.confirmation_deadline_ms
    }

    /// Only an actual observed scanout readback for the matching connector
    /// before the deadline acknowledges the switch. Anything else keeps the
    /// previous mode as the rollback target.
    pub fn confirm(
        self,
        token: u64,
        connector_generation: u64,
        observed: ModeEntry,
        now_ms: u64,
    ) -> Result<ModeEntry, CatalogError> {
        if token != self.confirmation_token || token == 0 {
            return Err(CatalogError::InvalidTransaction);
        }
        if connector_generation != self.connector_generation {
            return Err(CatalogError::StaleConnector);
        }
        if self.timed_out(now_ms) {
            return Err(CatalogError::ConfirmationExpired);
        }
        if !observed.same_geometry(self.requested) {
            return Err(CatalogError::DeviceDidNotApply);
        }
        Ok(observed)
    }
}

#[derive(Clone, Copy)]
pub struct ModeCatalog {
    generation: u64,
    len: usize,
    entries: [ModeEntry; MAX_CATALOG_ENTRIES],
}

impl ModeCatalog {
    pub fn new(generation: u64) -> Result<Self, CatalogError> {
        if generation == 0 {
            return Err(CatalogError::InvalidGeneration);
        }
        Ok(Self {
            generation,
            len: 0,
            entries: [ModeEntry::EMPTY; MAX_CATALOG_ENTRIES],
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub fn entries(&self) -> &[ModeEntry] {
        &self.entries[..self.len]
    }

    pub fn selectable_count(self) -> usize {
        self.entries().iter().filter(|e| e.selectable()).count()
    }

    pub fn device_reported_count(self) -> usize {
        self.len - self.selectable_count()
    }

    /// Records one observation. A later host-verified proof may upgrade a
    /// device-reported claim, but a claim never overwrites a proven scanout,
    /// and two different proofs for one geometry are refused.
    pub fn record(&mut self, entry: ModeEntry) -> Result<(), CatalogError> {
        if entry.width == 0
            || entry.height == 0
            || entry.scanout >= MAX_SCANOUTS
            || (entry.width as u64) * (entry.height as u64) > u32::MAX as u64
        {
            return Err(CatalogError::InvalidEntry);
        }
        if let RefreshEvidence::VerifiedMilliHz(hz) = entry.refresh {
            if hz == 0 {
                return Err(CatalogError::InvalidEntry);
            }
        }
        for slot in self.entries[..self.len].iter_mut() {
            if !slot.same_geometry(entry) {
                continue;
            }
            return match (slot.proof, entry.proof) {
                (ScanoutProof::DeviceReportedConfigured, ScanoutProof::HostVerifiedApplied) => {
                    *slot = entry;
                    Ok(())
                }
                (ScanoutProof::HostVerifiedApplied, ScanoutProof::DeviceReportedConfigured) => {
                    Err(CatalogError::ConflictingProof)
                }
                _ if slot.refresh != entry.refresh => Err(CatalogError::ConflictingProof),
                _ => Ok(()),
            };
        }
        if self.len == MAX_CATALOG_ENTRIES {
            return Err(CatalogError::CatalogOverflow);
        }
        self.entries[self.len] = entry;
        self.len += 1;
        Ok(())
    }

    fn check_generation(self, current_generation: u64) -> Result<(), CatalogError> {
        if current_generation == 0 || self.generation == 0 {
            return Err(CatalogError::InvalidGeneration);
        }
        if current_generation != self.generation {
            return Err(CatalogError::StaleConnector);
        }
        Ok(())
    }

    /// Selects one entry from host-verified scanouts only. The caller may pass
    /// EDID-derived geometry and rate; nothing unproven is ever returned.
    pub fn choose(
        &self,
        current_generation: u64,
        choice: UserChoice,
    ) -> Result<ModeEntry, CatalogError> {
        self.check_generation(current_generation)?;
        let exact_geometry = match choice.resolution {
            ResolutionChoice::Exact { width, height } => Some((width, height)),
            ResolutionChoice::Automatic => None,
        };
        let exact_refresh = match choice.refresh {
            RefreshChoice::ExactMilliHz(rate) => Some(rate),
            RefreshChoice::Automatic => None,
        };
        let mut geometry_in_catalog = false;
        let mut selectable_geometry = false;
        let mut unverifiable_refresh = false;
        let mut best: Option<ModeEntry> = None;
        for entry in self.entries().iter().copied() {
            if let Some((width, height)) = exact_geometry {
                if entry.width != width || entry.height != height {
                    continue;
                }
                geometry_in_catalog = true;
                if !entry.selectable() {
                    continue;
                }
                selectable_geometry = true;
            }
            if !entry.selectable() {
                continue;
            }
            if let Some(rate) = exact_refresh {
                match entry.refresh {
                    RefreshEvidence::VerifiedMilliHz(hz) if hz == rate => {}
                    RefreshEvidence::Unavailable => {
                        unverifiable_refresh = true;
                        continue;
                    }
                    _ => continue,
                }
            }
            let better = match best {
                None => true,
                // Largest proven area, then highest proven refresh, then the
                // lowest scanout index so the result is deterministic.
                Some(current) => {
                    (entry.area(), refresh_rank(entry.refresh), u8::MAX - entry.scanout)
                        > (current.area(), refresh_rank(current.refresh), u8::MAX - current.scanout)
                }
            };
            if better {
                best = Some(entry);
            }
        }
        if let Some(selected) = best {
            return Ok(selected);
        }
        if exact_geometry.is_some() {
            if !geometry_in_catalog || !selectable_geometry {
                // EDID-only or device-reported-only geometry: unproven.
                return Err(CatalogError::UnprovenGpuTiming);
            }
            if exact_refresh.is_some() && unverifiable_refresh {
                return Err(CatalogError::RefreshNotProgrammable);
            }
            return Err(CatalogError::UnsupportedSelection);
        }
        if exact_refresh.is_some() {
            if self.selectable_count() == 0 {
                return Err(CatalogError::NoSelectableMode);
            }
            return if unverifiable_refresh {
                Err(CatalogError::RefreshNotProgrammable)
            } else {
                Err(CatalogError::UnsupportedSelection)
            };
        }
        Err(CatalogError::NoSelectableMode)
    }

    /// A plan only. The display manager must really apply the requested
    /// geometry, read the scanout back, and restore `previous` on failed
    /// readback, hotplug or an expired user confirmation.
    pub fn plan_change(
        &self,
        current_generation: u64,
        current: ModeEntry,
        choice: UserChoice,
        confirmation_token: u64,
        now_ms: u64,
    ) -> Result<Option<ModeChangePlan>, CatalogError> {
        self.check_generation(current_generation)?;
        if confirmation_token == 0 {
            return Err(CatalogError::InvalidTransaction);
        }
        // Never plan from a mode that is not a proven mode of this device.
        if !self
            .entries()
            .iter()
            .any(|e| e.same_timing(current) && e.selectable())
        {
            return Err(CatalogError::UnprovenGpuTiming);
        }
        let selected = self.choose(current_generation, choice)?;
        if selected.same_geometry(current) {
            // VirtIO-GPU cannot reprogram a pixel clock, so a same-geometry
            // request is a no-op rather than a timing change.
            return Ok(None);
        }
        let deadline = now_ms
            .checked_add(CONFIRM_WINDOW_MS)
            .ok_or(CatalogError::InvalidTransaction)?;
        Ok(Some(ModeChangePlan {
            previous: current,
            requested: selected,
            connector_generation: current_generation,
            confirmation_token,
            confirmation_deadline_ms: deadline,
        }))
    }
}

const fn refresh_rank(refresh: RefreshEvidence) -> u32 {
    match refresh {
        RefreshEvidence::Unavailable => 0,
        RefreshEvidence::VerifiedMilliHz(hz) => hz,
    }
}

// ---------------------------------------------------------------------------
// Host attestation channel
// ---------------------------------------------------------------------------
//
// `ScanoutProof::HostVerifiedApplied` is a strong claim: an independent host
// really looked at the pixels at exactly this geometry. The driver alone must
// never be able to assert it, because that would be exactly the fabricated
// "the GPU supports this mode" claim this project forbids.
//
// So the claim is a challenge/response. Before each capture the driver prints a
// per-stage nonce together with its **own** digest of the exact source pixels it
// placed in the resource. The host captures the screen, verifies every pixel, and
// echoes the nonce, the observed geometry and the digest of the pixels it really
// saw. Only a reply that matches the nonce, the geometry the driver applied and
// the driver's source digest produces an `Attestation` that may create an entry.
//
// A corrupted transfer, a wrong stride, wrong channel order, a resized scanout or
// a replayed/stale reply all break the match, so no entry appears and automatic
// selection fails closed instead of silently trusting the driver.

/// Offset basis of FNV-1a over the canonical RGB bytes.
pub const DIGEST_SEED: u32 = 0x811c_9dc5;
/// A hostile or broken peer must not be able to stall the driver forever.
pub const MAX_REPLY_BYTES: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationError {
    EmptyReply,
    ReplyTooLong,
    UnexpectedStageToken,
    MalformedReply,
    BadNonce,
    WrongGeometry,
    DigestMismatch,
    InvalidRequest,
}

impl AttestationError {
    pub const fn label(self) -> &'static str {
        match self {
            Self::EmptyReply => "empty_reply",
            Self::ReplyTooLong => "reply_too_long",
            Self::UnexpectedStageToken => "unexpected_stage_token",
            Self::MalformedReply => "malformed_reply",
            Self::BadNonce => "bad_nonce",
            Self::WrongGeometry => "wrong_geometry",
            Self::DigestMismatch => "digest_mismatch",
            Self::InvalidRequest => "invalid_request",
        }
    }
}

/// Evidence that a host capture really matched this exact scanout.
///
/// Fields stay private: `decode_attestation_reply` is the only producer, so a
/// driver cannot fabricate the evidence that makes a mode selectable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attestation {
    nonce: u64,
    width: u32,
    height: u32,
    digest: u32,
}

impl Attestation {
    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    pub const fn width(self) -> u32 {
        self.width
    }

    pub const fn height(self) -> u32 {
        self.height
    }

    pub const fn digest(self) -> u32 {
        self.digest
    }

    pub const fn entry(self, scanout: u8) -> ModeEntry {
        ModeEntry {
            scanout,
            width: self.width,
            height: self.height,
            // The host saw these exact pixels at this exact geometry. Refresh
            // stays unavailable: capturing geometry proves no pixel clock.
            proof: ScanoutProof::HostVerifiedApplied,
            refresh: RefreshEvidence::Unavailable,
        }
    }
}

#[cfg(test)]
impl Attestation {
    /// Test-only: a synthetic accepted attestation for policy tests. Only the
    /// `#[cfg(test)]` build has this constructor; the kernel binary can still
    /// obtain an `Attestation` exclusively from `decode_attestation_reply`.
    pub fn for_test(nonce: u64, width: u32, height: u32, digest: u32) -> Self {
        Self { nonce, width, height, digest }
    }
}

/// FNV-1a over width*height canonical `(r, g, b)` triples in scanline order.
/// Both the driver (over its source pixels) and the host (over the captured
/// screenshot) compute this same value, so any corruption diverges.
pub fn rgb_digest(width: u32, height: u32, pixel: &dyn Fn(u32, u32) -> [u8; 3]) -> u32 {
    let mut hash = DIGEST_SEED;
    for y in 0..height {
        for x in 0..width {
            for byte in pixel(x, y) {
                hash ^= u32::from(byte);
                hash = hash.wrapping_mul(0x0100_0193);
            }
        }
    }
    hash
}
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
fn parse_hex(bytes: &[u8], max_digits: usize) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > max_digits {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes.iter().copied() {
        value = value.checked_mul(16)?.checked_add(u64::from(hex_nibble(byte)?))?;
    }
    Some(value)
}
/// Geometry is decimal in the attestation line; nonce and digest are hex.
fn parse_dec(bytes: &[u8], max_digits: usize) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > max_digits {
        return None;
    }
    let mut value = 0u32;
    for byte in bytes.iter().copied() {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}
fn parse_geometry(bytes: &[u8]) -> Option<(u32, u32)> {
    let split = bytes.iter().position(|b| *b == b'x')?;
    let width = parse_dec(&bytes[..split], 5)?;
    let height = parse_dec(&bytes[split + 1..], 5)?;
    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        return None;
    }
    Some((width as u32, height as u32))
}

/// The line the driver prints before waiting for a capture. It carries the
/// nonce and the driver's own source digest so the reply can be bound to this
/// exact stage instead of being replayed from an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageChallenge {
    pub token: u8,
    pub nonce: u64,
    pub width: u32,
    pub height: u32,
    pub source_digest: u32,
}

impl StageChallenge {
    pub fn new(
        token: u8,
        nonce: u64,
        width: u32,
        height: u32,
        source_digest: u32,
    ) -> Result<Self, AttestationError> {
        if nonce == 0 || width == 0 || height == 0 || !token.is_ascii_alphabetic() {
            return Err(AttestationError::InvalidRequest);
        }
        Ok(Self { token, nonce, width, height, source_digest })
    }

    pub fn stage_label(&self) -> &'static str {
        match self.token {
            b'A' => "active",
            b'M' => "reduced",
            b'E' => "reexpanded",
            b'P' => "desktop",
            b'S' => "reduced",
            b'T' => "applied",
            b'R' => "rollback",
            _ => "unknown",
        }
    }
}

/// `"<token> <w>x<h> <nonce-hex> <digest-hex>"`, one line, ASCII only.
/// Rejects anything else: extra fields, wrong token, wrong nonce, wrong
/// geometry, wrong digest, trailing garbage or oversized input.
pub fn decode_attestation_reply(
    line: &[u8],
    challenge: StageChallenge,
) -> Result<Attestation, AttestationError> {
    let line = match line.last() {
        Some(b'\n') => &line[..line.len() - 1],
        _ => line,
    };
    let line = match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    };
    if line.is_empty() {
        return Err(AttestationError::EmptyReply);
    }
    if line.len() > MAX_REPLY_BYTES {
        return Err(AttestationError::ReplyTooLong);
    }
    for byte in line.iter().copied() {
        if !byte.is_ascii_graphic() && byte != b' ' {
            return Err(AttestationError::MalformedReply);
        }
    }
    let mut fields = line.split(|b| *b == b' ');
    let token = fields.next().ok_or(AttestationError::MalformedReply)?;
    let geometry = fields.next().ok_or(AttestationError::MalformedReply)?;
    let nonce = fields.next().ok_or(AttestationError::MalformedReply)?;
    let digest = fields.next().ok_or(AttestationError::MalformedReply)?;
    if fields.next().is_some() {
        return Err(AttestationError::MalformedReply);
    }
    if token.len() != 1 || token[0] != challenge.token {
        return Err(AttestationError::UnexpectedStageToken);
    }
    let (width, height) = parse_geometry(geometry).ok_or(AttestationError::MalformedReply)?;
    let got_nonce = parse_hex(nonce, 16).ok_or(AttestationError::MalformedReply)?;
    let got_digest = parse_hex(digest, 8).ok_or(AttestationError::MalformedReply)? as u32;
    if got_nonce == 0 || got_nonce != challenge.nonce {
        return Err(AttestationError::BadNonce);
    }
    if width != challenge.width || height != challenge.height {
        return Err(AttestationError::WrongGeometry);
    }
    if got_digest != challenge.source_digest {
        return Err(AttestationError::DigestMismatch);
    }
    Ok(Attestation {
        nonce: got_nonce,
        width,
        height,
        digest: got_digest,
    })
}

/// Stable summary of the attested-desktop selection proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopSelection {
    /// The geometry the primary attestation proved.
    pub width: u32,
    pub height: u32,
    /// What automatic selection really picked (the largest proven geometry).
    pub automatic_width: u32,
    pub automatic_height: u32,
    /// The second proven geometry, or zeroes when only one was attested.
    pub second_width: u32,
    pub second_height: u32,
    pub entries: usize,
    pub selectable: usize,
    pub device_reported: usize,
    /// How the device's own `GET_DISPLAY_INFO` claim was handled.
    pub device_claim: &'static str,
    pub refresh: RefreshEvidence,
}

/// The catalog's own transaction token for "this mode is already applied".
pub const APPLIED_CHANGE_TOKEN: u64 = 0x574f_4c46_4d4f_4446;

fn exact_geometry(width: u32, height: u32) -> UserChoice {
    UserChoice {
        resolution: ResolutionChoice::Exact { width, height },
        refresh: RefreshChoice::Automatic,
    }
}

/// Turns ONE accepted host attestation into the catalog's automatic choice and
/// re-proves, every boot, the refusals that keep unproven modes out of the
/// settings UI.
///
/// Production ordering: attest first, catalog second. Nothing here can be
/// called with a driver-asserted geometry because `Attestation` has no public
/// constructor, and device/EDID data only enters through
/// `ModeEntry::device_reported`, which is never selectable. A rejected
/// attestation therefore leaves the catalog empty and automatic selection
/// fails closed instead of silently falling back to a claimed mode.
pub fn prove_desktop_selection(
    generation: u64,
    scanout: u8,
    attestation: Attestation,
    second: Option<Attestation>,
    device: Option<(u32, u32)>,
    edid_rate_millihz: u32,
) -> Result<DesktopSelection, &'static str> {
    // Without a real monitor rate the EDID-refusal proof would be vacuous.
    if edid_rate_millihz == 0 {
        return Err("missing_edid_rate");
    }
    let mut modes = ModeCatalog::new(generation).map_err(|_| "catalog_generation")?;
    let attested = attestation.entry(scanout);
    modes
        .record(attested)
        .map_err(|_| "catalog_record_attested")?;
    // A second geometry is only ever a *second* mode: same-geometry evidence
    // with different metadata must conflict instead of silently replacing it.
    let mut proven = [attested; 2];
    let mut proven_len = 1usize;
    if let Some(second) = second {
        let entry = second.entry(scanout);
        if entry.same_geometry(attested) {
            return Err("catalog_second_not_distinct");
        }
        modes
            .record(entry)
            .map_err(|_| "catalog_record_second")?;
        proven[1] = entry;
        proven_len = 2;
    }
    // An unattested catalog must remain non-selectable. This is checked against
    // a fresh catalog so it cannot be satisfied by the entry above.
    let empty = ModeCatalog::new(generation).map_err(|_| "catalog_generation")?;
    if empty.choose(generation, UserChoice::AUTOMATIC) != Err(CatalogError::NoSelectableMode) {
        return Err("catalog_selectable_without_attestation");
    }
    let mut device_reported = 0usize;
    let mut device_claim = "not_present";
    if let Some((width, height)) = device {
        let claim = ModeEntry::device_reported(scanout, width, height, RefreshEvidence::Unavailable);
        if (width, height) == (attested.width, attested.height) {
            // A weaker claim for an already proven geometry must never
            // downgrade it, and needs no separate entry.
            if modes.record(claim) != Err(CatalogError::ConflictingProof) {
                return Err("catalog_device_downgraded_proven_mode");
            }
            device_claim = "refused:conflicting_proof";
        } else {
            modes.record(claim).map_err(|_| "catalog_record_device")?;
            device_reported += 1;
            // However large the claimed area is, it must never be selectable.
            if modes.choose(generation, exact_geometry(width, height))
                != Err(CatalogError::UnprovenGpuTiming)
            {
                return Err("catalog_device_reported_accepted");
            }
            device_claim = "rejected:unproven_gpu_timing";
        }
    }
    let automatic = modes
        .choose(generation, UserChoice::AUTOMATIC)
        .map_err(|_| "catalog_automatic")?;
    // Automatic selection must be the largest *proven* geometry, recomputed
    // from the entries themselves rather than assumed from the call order.
    let mut largest = proven[0];
    for entry in proven[..proven_len].iter().copied() {
        if (entry.area(), u8::MAX - entry.scanout)
            > (largest.area(), u8::MAX - largest.scanout)
        {
            largest = entry;
        }
    }
    if automatic != largest {
        return Err("catalog_automatic_not_attested");
    }
    if automatic.refresh != RefreshEvidence::Unavailable {
        return Err("catalog_invented_refresh");
    }
    for entry in proven[..proven_len].iter().copied() {
        if modes
            .choose(generation, exact_geometry(entry.width, entry.height))
            .map_err(|_| "catalog_manual_attested")?
            != entry
        {
            return Err("catalog_manual_geometry");
        }
    }
    // A monitor's EDID rate is not a programmable GPU rate, for the exact
    // geometry as much as for automatic selection.
    for choice in [
        UserChoice {
            resolution: ResolutionChoice::Exact {
                width: attested.width,
                height: attested.height,
            },
            refresh: RefreshChoice::ExactMilliHz(edid_rate_millihz),
        },
        UserChoice {
            resolution: ResolutionChoice::Automatic,
            refresh: RefreshChoice::ExactMilliHz(edid_rate_millihz),
        },
    ] {
        if modes.choose(generation, choice) != Err(CatalogError::RefreshNotProgrammable) {
            return Err("catalog_edid_refresh_accepted");
        }
    }
    // The mode the catalog presents as current is already applied, so asking
    // for it again must not open a rollback window for a switch that never
    // happens.
    if modes.plan_change(
        generation,
        automatic,
        UserChoice::AUTOMATIC,
        APPLIED_CHANGE_TOKEN,
        1_000,
    ) != Ok(None)
    {
        return Err("catalog_attested_change_not_noop");
    }
    // With two proven geometries a real change plan must exist, keep the
    // current mode as the rollback target and open exactly one window.
    if proven_len == 2 {
        let other = if proven[0].same_geometry(automatic) { proven[1] } else { proven[0] };
        let plan = modes
            .plan_change(
                generation,
                automatic,
                exact_geometry(other.width, other.height),
                APPLIED_CHANGE_TOKEN,
                1_000,
            )
            .map_err(|_| "catalog_second_change_refused")?
            .ok_or("catalog_second_change_missing")?;
        if plan.previous != automatic
            || plan.requested != other
            || plan.rollback_target() != automatic
            || plan.confirmation_deadline_ms != 1_000 + CONFIRM_WINDOW_MS
        {
            return Err("catalog_second_change_plan");
        }
    }
    Ok(DesktopSelection {
        width: attested.width,
        height: attested.height,
        automatic_width: automatic.width,
        automatic_height: automatic.height,
        second_width: if proven_len == 2 { proven[1].width } else { 0 },
        second_height: if proven_len == 2 { proven[1].height } else { 0 },
        entries: modes.entries().len(),
        selectable: modes.selectable_count(),
        device_reported,
        device_claim,
        refresh: automatic.refresh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_numeric_two_field_verdict_lines_can_be_discarded() {
        for valid in [b"X 0\n".as_slice(), b"E 15000\n", b"X 15200\r\n",
                      b"E 999999999999", b"X 1"] {
            assert!(is_elapsed_verdict_line(valid), "valid verdict {valid:?}");
        }
        for other in [
            b"E 64x64 0000574f41580003 171cbca5\n".as_slice(),
            b"A 64x64 0000574f41540001 171cbca5\n",
            b"E 32x32 0000574f41520002 53ec77a5\n",
            b"E 1 2", b"X 15000 extra", b"E ", b"X ",
            b"E 15x00", b"E -1", b"E 1000000000000",
            b"Z 15000", b"x 15000", b"E\t15000",
            b"E 15000\nE 16000", b"X 7\x00",
        ] {
            assert!(!is_elapsed_verdict_line(other), "not a verdict: {other:?}");
        }
    }


    const APPLIED_64: ModeEntry = ModeEntry {
        scanout: 0,
        width: 64,
        height: 64,
        proof: ScanoutProof::HostVerifiedApplied,
        refresh: RefreshEvidence::Unavailable,
    };
    const APPLIED_32: ModeEntry = ModeEntry {
        width: 32,
        height: 32,
        ..APPLIED_64
    };
    /// The geometry the device itself reports as configured (QEMU: 1280x800).
    const DEVICE_1280: ModeEntry = ModeEntry {
        width: 1280,
        height: 800,
        proof: ScanoutProof::DeviceReportedConfigured,
        ..APPLIED_64
    };

    fn catalog() -> ModeCatalog {
        let mut c = ModeCatalog::new(7).unwrap();
        c.record(APPLIED_64).unwrap();
        c.record(APPLIED_32).unwrap();
        c.record(DEVICE_1280).unwrap();
        c
    }

    fn exact(width: u32, height: u32) -> UserChoice {
        UserChoice {
            resolution: ResolutionChoice::Exact { width, height },
            refresh: RefreshChoice::Automatic,
        }
    }

    fn exact_hz(width: u32, height: u32, rate: u32) -> UserChoice {
        UserChoice {
            resolution: ResolutionChoice::Exact { width, height },
            refresh: RefreshChoice::ExactMilliHz(rate),
        }
    }

    #[test]
    fn generation_must_be_nonzero_and_current() {
        assert_eq!(ModeCatalog::new(0).err(), Some(CatalogError::InvalidGeneration));
        let c = catalog();
        assert_eq!(c.generation(), 7);
        assert_eq!(c.choose(0, UserChoice::AUTOMATIC), Err(CatalogError::InvalidGeneration));
        assert_eq!(c.choose(8, UserChoice::AUTOMATIC), Err(CatalogError::StaleConnector));
        assert_eq!(c.choose(7, UserChoice::AUTOMATIC), Ok(APPLIED_64));
    }

    #[test]
    fn record_rejects_zero_geometry_absurd_scanout_and_zero_rate() {
        let mut c = ModeCatalog::new(1).unwrap();
        for bad in [
            ModeEntry { width: 0, ..APPLIED_64 },
            ModeEntry { height: 0, ..APPLIED_64 },
            ModeEntry { scanout: 16, ..APPLIED_64 },
            ModeEntry { scanout: 255, ..APPLIED_64 },
            ModeEntry {
                refresh: RefreshEvidence::VerifiedMilliHz(0),
                ..APPLIED_64
            },
        ] {
            assert_eq!(c.record(bad), Err(CatalogError::InvalidEntry));
        }
        assert!(c.entries().is_empty());
    }

    #[test]
    fn catalog_overflow_is_bounded_and_loses_nothing() {
        let mut c = ModeCatalog::new(1).unwrap();
        for n in 1..=MAX_CATALOG_ENTRIES as u32 {
            let entry = ModeEntry { width: n, height: n, ..APPLIED_64 };
            assert_eq!(c.record(entry), Ok(()));
        }
        assert_eq!(c.entries().len(), MAX_CATALOG_ENTRIES);
        assert_eq!(
            c.record(ModeEntry { width: 99, height: 99, ..APPLIED_64 }),
            Err(CatalogError::CatalogOverflow)
        );
        assert_eq!(c.entries().len(), MAX_CATALOG_ENTRIES);
    }

    #[test]
    fn device_reported_geometry_is_never_selectable() {
        let c = catalog();
        assert_eq!(c.selectable_count(), 2);
        assert_eq!(c.device_reported_count(), 1);
        assert_eq!(c.choose(7, exact(1280, 800)), Err(CatalogError::UnprovenGpuTiming));
    }

    #[test]
    fn edid_only_geometry_is_refused_as_unproven() {
        let c = catalog();
        for (width, height) in [(1920, 1080), (1024, 768), (1440, 900), (800, 600)] {
            assert_eq!(
                c.choose(7, exact(width, height)),
                Err(CatalogError::UnprovenGpuTiming)
            );
        }
        assert_eq!(c.choose(7, exact(65, 64)), Err(CatalogError::UnprovenGpuTiming));
    }

    #[test]
    fn automatic_prefers_largest_proven_scanout_not_device_claim() {
        let c = catalog();
        // 1280x800 has far more pixels but is only device-reported.
        assert_eq!(c.choose(7, UserChoice::AUTOMATIC), Ok(APPLIED_64));
    }

    #[test]
    fn automatic_fails_closed_without_any_host_verified_mode() {
        let mut c = ModeCatalog::new(3).unwrap();
        c.record(DEVICE_1280).unwrap();
        assert_eq!(c.choose(3, UserChoice::AUTOMATIC), Err(CatalogError::NoSelectableMode));
        assert_eq!(c.choose(3, exact(1280, 800)), Err(CatalogError::UnprovenGpuTiming));
        let empty = ModeCatalog::new(3).unwrap();
        assert_eq!(empty.choose(3, UserChoice::AUTOMATIC), Err(CatalogError::NoSelectableMode));
    }

    #[test]
    fn manual_proven_geometry_is_accepted_with_unknown_refresh() {
        let c = catalog();
        let selected = c.choose(7, exact(32, 32)).unwrap();
        assert_eq!(selected, APPLIED_32);
        assert_eq!(selected.refresh, RefreshEvidence::Unavailable);
        assert_eq!(selected.refresh_label(), "unavailable");
        assert_eq!(c.choose(7, exact(64, 64)), Ok(APPLIED_64));
    }

    #[test]
    fn edid_refresh_never_becomes_a_programmable_rate() {
        let c = catalog();
        // QEMU's EDID advertises 74.994 Hz for 1280x800; that is monitor data.
        assert_eq!(
            c.choose(7, exact_hz(1280, 800, 74_994)),
            Err(CatalogError::UnprovenGpuTiming)
        );
        assert_eq!(
            c.choose(7, exact_hz(64, 64, 74_994)),
            Err(CatalogError::RefreshNotProgrammable)
        );
        assert_eq!(
            c.choose(
                7,
                UserChoice {
                    resolution: ResolutionChoice::Automatic,
                    refresh: RefreshChoice::ExactMilliHz(74_994),
                }
            ),
            Err(CatalogError::RefreshNotProgrammable)
        );
    }

    #[test]
    fn verified_refresh_is_honoured_when_a_driver_really_measured_it() {
        let mut c = ModeCatalog::new(9).unwrap();
        let natively_verified = ModeEntry {
            refresh: RefreshEvidence::VerifiedMilliHz(60_000),
            ..APPLIED_64
        };
        c.record(natively_verified).unwrap();
        assert_eq!(c.choose(9, exact_hz(64, 64, 60_000)), Ok(natively_verified));
        assert_eq!(c.choose(9, exact_hz(64, 64, 60_001)), Err(CatalogError::UnsupportedSelection));
        assert_eq!(c.choose(9, exact(64, 64)), Ok(natively_verified));
    }

    #[test]
    fn proof_upgrade_replaces_claim_but_never_downgrades_proof() {
        let mut c = ModeCatalog::new(2).unwrap();
        c.record(DEVICE_1280).unwrap();
        let proven = ModeEntry {
            proof: ScanoutProof::HostVerifiedApplied,
            ..DEVICE_1280
        };
        assert_eq!(c.record(proven), Ok(()));
        assert_eq!(c.entries(), &[proven]);
        assert_eq!(c.record(DEVICE_1280), Err(CatalogError::ConflictingProof));
        assert_eq!(c.entries(), &[proven]);
        // Identical re-observation is idempotent.
        assert_eq!(c.record(proven), Ok(()));
        assert_eq!(c.entries().len(), 1);
    }

    #[test]
    fn conflicting_rates_for_one_geometry_are_refused() {
        let mut c = ModeCatalog::new(2).unwrap();
        c.record(APPLIED_64).unwrap();
        let contradictory = ModeEntry {
            refresh: RefreshEvidence::VerifiedMilliHz(60_000),
            ..APPLIED_64
        };
        assert_eq!(c.record(contradictory), Err(CatalogError::ConflictingProof));
        assert_eq!(c.entries(), &[APPLIED_64]);
    }

    #[test]
    fn plan_keeps_previous_mode_for_rollback() {
        let c = catalog();
        let plan = c
            .plan_change(7, APPLIED_64, exact(32, 32), 11, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(plan.previous, APPLIED_64);
        assert_eq!(plan.requested, APPLIED_32);
        assert_eq!(plan.rollback_target(), APPLIED_64);
        assert_eq!(plan.confirmation_deadline_ms, 16_000);
        assert_eq!(plan.confirm(11, 7, APPLIED_32, 15_999), Ok(APPLIED_32));
        assert_eq!(plan.rollback_target(), APPLIED_64);
    }

    #[test]
    fn plan_is_a_noop_for_the_mode_already_applied() {
        let c = catalog();
        assert_eq!(
            c.plan_change(7, APPLIED_64, UserChoice::AUTOMATIC, 11, 1_000),
            Ok(None)
        );
    }

    #[test]
    fn plan_requires_token_generation_and_a_proven_current_mode() {
        let c = catalog();
        assert_eq!(
            c.plan_change(7, APPLIED_64, exact(32, 32), 0, 1_000),
            Err(CatalogError::InvalidTransaction)
        );
        assert_eq!(
            c.plan_change(8, APPLIED_64, exact(32, 32), 11, 1_000),
            Err(CatalogError::StaleConnector)
        );
        // A device-reported "current" mode cannot be the rollback baseline.
        assert_eq!(
            c.plan_change(7, DEVICE_1280, exact(32, 32), 11, 1_000),
            Err(CatalogError::UnprovenGpuTiming)
        );
        assert_eq!(
            c.plan_change(7, APPLIED_64, exact(1920, 1080), 11, 1_000),
            Err(CatalogError::UnprovenGpuTiming)
        );
        assert_eq!(
            c.plan_change(7, APPLIED_64, exact(32, 32), 11, u64::MAX),
            Err(CatalogError::InvalidTransaction)
        );
    }

    #[test]
    fn confirmation_requires_the_real_readback_before_the_deadline() {
        let c = catalog();
        let plan = c
            .plan_change(7, APPLIED_64, exact(32, 32), 11, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(plan.confirm(12, 7, APPLIED_32, 2_000), Err(CatalogError::InvalidTransaction));
        assert_eq!(plan.confirm(0, 7, APPLIED_32, 2_000), Err(CatalogError::InvalidTransaction));
        assert_eq!(plan.confirm(11, 8, APPLIED_32, 2_000), Err(CatalogError::StaleConnector));
        assert_eq!(plan.confirm(11, 7, APPLIED_64, 2_000), Err(CatalogError::DeviceDidNotApply));
        assert_eq!(plan.confirm(11, 7, APPLIED_32, 16_000), Err(CatalogError::ConfirmationExpired));
        assert!(plan.timed_out(16_000));
        assert!(!plan.timed_out(15_999));
        assert_eq!(plan.rollback_target(), APPLIED_64);
    }

    #[test]
    fn geometry_identity_ignores_refresh_and_proof_but_timing_does_not() {
        let same_geometry = ModeEntry {
            refresh: RefreshEvidence::VerifiedMilliHz(60_000),
            proof: ScanoutProof::DeviceReportedConfigured,
            ..APPLIED_64
        };
        assert!(APPLIED_64.same_geometry(same_geometry));
        assert!(!APPLIED_64.same_timing(same_geometry));
        assert!(!APPLIED_64.same_geometry(APPLIED_32));
        assert_eq!(APPLIED_64.area(), 4_096);
        assert_eq!(APPLIED_32.area(), 1_024);
        assert!(APPLIED_64.selectable());
        assert!(!DEVICE_1280.selectable());
    }

    #[test]
    fn error_labels_are_stable_for_serial_evidence() {
        for (error, label) in [
            (CatalogError::UnprovenGpuTiming, "unproven_gpu_timing"),
            (CatalogError::RefreshNotProgrammable, "refresh_not_programmable"),
            (CatalogError::DeviceDidNotApply, "device_did_not_apply"),
            (CatalogError::StaleConnector, "stale_connector"),
        ] {
            assert_eq!(error.label(), label);
        }
    }

    #[test]
    fn ties_are_deterministic_by_scanout_index() {
        let mut c = ModeCatalog::new(5).unwrap();
        let second_output = ModeEntry { scanout: 1, ..APPLIED_64 };
        c.record(second_output).unwrap();
        c.record(APPLIED_64).unwrap();
        assert_eq!(c.choose(5, UserChoice::AUTOMATIC), Ok(APPLIED_64));
    }

    // ---- host attestation channel -----------------------------------------

    const CHALLENGE: StageChallenge = StageChallenge {
        token: b'A',
        nonce: 0x574f_4154_0001,
        width: 64,
        height: 64,
        source_digest: 0x1a2b_3c4d,
    };

    #[test]
    fn digest_is_stable_across_channels_and_detects_corruption() {
        let renders = |x: u32, y: u32| -> [u8; 3] { [x as u8, y as u8, 0x5a] };
        let same = rgb_digest(64, 64, &renders);
        assert_eq!(same, rgb_digest(64, 64, &renders));
        assert_eq!(same, rgb_digest(64, 64, &|x, y| renders(x, y)));
        // Channel order, one host-visible pixel and geometry all matter.
        let swapped = |x: u32, y: u32| -> [u8; 3] { let p = renders(x, y); [p[2], p[1], p[0]] };
        assert_ne!(same, rgb_digest(64, 64, &swapped));
        let one_pixel = |x: u32, y: u32| -> [u8; 3] {
            let mut p = renders(x, y);
            if x == 63 && y == 63 { p[1] ^= 1; }
            p
        };
        assert_ne!(same, rgb_digest(64, 64, &one_pixel));
        assert_ne!(same, rgb_digest(32, 32, &renders));
        // An empty frame still produces the well-defined seed value.
        assert_eq!(rgb_digest(0, 0, &renders), DIGEST_SEED);
    }

    #[test]
    fn matching_reply_becomes_host_verified_evidence() {
        let reply = decode_attestation_reply(b"A 64x64 574f41540001 1a2b3c4d\n", CHALLENGE)
            .unwrap();
        assert_eq!(reply, Attestation {
            nonce: CHALLENGE.nonce, width: 64, height: 64, digest: CHALLENGE.source_digest,
        });
        let entry = reply.entry(0);
        assert_eq!(entry.proof, ScanoutProof::HostVerifiedApplied);
        // Geometry was captured, but no pixel clock was ever programmed.
        assert_eq!(entry.refresh, RefreshEvidence::Unavailable);
        assert!(entry.selectable());
        assert_eq!(reply.entry(0), APPLIED_64);
        // LF and CRLF are both accepted; no other terminator is required.
        assert!(decode_attestation_reply(b"A 64x64 574f41540001 1a2b3c4d", CHALLENGE).is_ok());
        assert!(decode_attestation_reply(b"A 64x64 574f41540001 1a2b3c4d\r\n", CHALLENGE).is_ok());
    }

    #[test]
    fn forged_stale_and_malformed_replies_never_attest() {
        for (reply, expected) in [
            (&b""[..], AttestationError::EmptyReply),
            (b"\n", AttestationError::EmptyReply),
            (b"A 64x64 574f41540001\n", AttestationError::MalformedReply),
            (b"A 64x64 574f41540001 1a2b3c4d 00\n", AttestationError::MalformedReply),
            (b"A 64x64 574f41540001 1a2b3c4d\t\n", AttestationError::MalformedReply),
            (b"A 64X64 574f41540001 1a2b3c4d\n", AttestationError::MalformedReply),
            (b"A 64x64 0 1a2b3c4d\n", AttestationError::BadNonce),
            (b"A 64x64 574f41540002 1a2b3c4d\n", AttestationError::BadNonce),
            (b"A 32x32 574f41540001 1a2b3c4d\n", AttestationError::WrongGeometry),
            (b"A 64x64 574f41540001 1a2b3c4e\n", AttestationError::DigestMismatch),
            (b"M 64x64 574f41540001 1a2b3c4d\n", AttestationError::UnexpectedStageToken),
            (b"AA 64x64 574f41540001 1a2b3c4d\n", AttestationError::UnexpectedStageToken),
            (b"A 64x64 574f41540001 1a2b3c4d\x00", AttestationError::MalformedReply),
        ] {
            assert_eq!(decode_attestation_reply(reply, CHALLENGE), Err(expected), "{reply:?}");
        }
        let oversized = [b'A'; MAX_REPLY_BYTES + 1];
        assert_eq!(
            decode_attestation_reply(&oversized, CHALLENGE),
            Err(AttestationError::ReplyTooLong)
        );
    }

    #[test]
    fn challenge_rejects_unusable_stage_parameters() {
        assert_eq!(
            StageChallenge::new(b'A', 0, 64, 64, 1).err(),
            Some(AttestationError::InvalidRequest)
        );
        assert_eq!(
            StageChallenge::new(b'A', 1, 0, 64, 1).err(),
            Some(AttestationError::InvalidRequest)
        );
        assert_eq!(
            StageChallenge::new(b'1', 1, 64, 64, 1).err(),
            Some(AttestationError::InvalidRequest)
        );
        assert_eq!(StageChallenge::new(b'M', 1, 32, 32, 1).unwrap().nonce, 1);
    }

    #[test]
    fn selectable_mode_requires_attestation_not_driver_assertion() {
        // Exactly what the old boot path did: claim host verification without
        // any host reply. That must remain impossible to reach through the
        // attestation path, and an unattested catalog stays non-selectable.
        let mut claimed = ModeCatalog::new(1).unwrap();
        claimed
            .record(ModeEntry::device_reported(
                0,
                64,
                64,
                RefreshEvidence::Unavailable,
            ))
            .unwrap();
        assert_eq!(claimed.selectable_count(), 0);
        assert_eq!(claimed.choose(1, UserChoice::AUTOMATIC), Err(CatalogError::NoSelectableMode));
        assert_eq!(claimed.choose(1, exact(64, 64)), Err(CatalogError::UnprovenGpuTiming));
        let attested = decode_attestation_reply(
            b"A 64x64 574f41540001 1a2b3c4d\n", CHALLENGE
        ).unwrap();
        claimed.record(attested.entry(0)).unwrap();
        assert_eq!(claimed.selectable_count(), 1);
        assert_eq!(claimed.choose(1, UserChoice::AUTOMATIC), Ok(APPLIED_64));
    }

    // ---- attested desktop selection ---------------------------------------

    const DESKTOP_ATTESTATION: Attestation = Attestation {
        nonce: 0x574f_4445_534b_0004,
        width: 1024,
        height: 768,
        digest: 0x0b6b_1dc5,
    };
    /// The rate QEMU's real EDID advertises; monitor data, never selectable.
    const EDID_MILLIHZ: u32 = 74_994;

    #[test]
    fn attested_desktop_becomes_the_automatic_choice() {
        let selection = prove_desktop_selection(
            1,
            0,
            DESKTOP_ATTESTATION,
            None,
            Some((1280, 800)),
            EDID_MILLIHZ,
        )
        .unwrap();
        assert_eq!((selection.width, selection.height), (1024, 768));
        assert_eq!(selection.entries, 2);
        assert_eq!(selection.selectable, 1);
        assert_eq!(selection.device_reported, 1);
        assert_eq!(selection.device_claim, "rejected:unproven_gpu_timing");
        assert_eq!(selection.refresh, RefreshEvidence::Unavailable);
        assert_eq!(selection.refresh.label(), "unavailable");
        // The entry itself carries no invented clock either.
        assert_eq!(DESKTOP_ATTESTATION.entry(0).refresh_label(), "unavailable");
        assert_eq!(DESKTOP_ATTESTATION.width(), 1024);
        assert_eq!(DESKTOP_ATTESTATION.height(), 768);
        assert_eq!(DESKTOP_ATTESTATION.nonce(), 0x574f_4445_534b_0004);
        assert_eq!(DESKTOP_ATTESTATION.digest(), 0x0b6b_1dc5);
    }

    #[test]
    fn a_smaller_attested_geometry_still_beats_a_larger_device_claim() {
        let small = Attestation { width: 64, height: 64, ..DESKTOP_ATTESTATION };
        let selection =
            prove_desktop_selection(1, 0, small, None, Some((1280, 800)), EDID_MILLIHZ).unwrap();
        assert_eq!((selection.width, selection.height), (64, 64));
        assert_eq!(selection.selectable, 1);
        assert_eq!(selection.device_reported, 1);
    }

    #[test]
    fn device_claim_for_the_attested_geometry_cannot_downgrade_it() {
        let selection = prove_desktop_selection(
            1,
            0,
            DESKTOP_ATTESTATION,
            None,
            Some((1024, 768)),
            EDID_MILLIHZ,
        )
        .unwrap();
        assert_eq!((selection.width, selection.height), (1024, 768));
        assert_eq!(selection.entries, 1);
        assert_eq!(selection.selectable, 1);
        assert_eq!(selection.device_reported, 0);
        assert_eq!(selection.device_claim, "refused:conflicting_proof");
    }

    #[test]
    fn attested_desktop_without_a_device_claim_still_proves_the_refusals() {
        let selection =
            prove_desktop_selection(1, 0, DESKTOP_ATTESTATION, None, None, EDID_MILLIHZ).unwrap();
        assert_eq!(selection.entries, 1);
        assert_eq!(selection.selectable, 1);
        assert_eq!(selection.device_claim, "not_present");
    }

    #[test]
    fn unusable_evidence_never_produces_a_desktop_selection() {
        for (generation, attestation, rate, expected) in [
            (0, DESKTOP_ATTESTATION, EDID_MILLIHZ, "catalog_generation"),
            (1, DESKTOP_ATTESTATION, 0, "missing_edid_rate"),
            (
                1,
                Attestation { width: 0, ..DESKTOP_ATTESTATION },
                EDID_MILLIHZ,
                "catalog_record_attested",
            ),
            (
                1,
                Attestation { height: 0, ..DESKTOP_ATTESTATION },
                EDID_MILLIHZ,
                "catalog_record_attested",
            ),
            (
                1,
                Attestation { width: 70_000, height: 70_000, ..DESKTOP_ATTESTATION },
                EDID_MILLIHZ,
                "catalog_record_attested",
            ),
        ] {
            assert_eq!(
                prove_desktop_selection(generation, 0, attestation, None, Some((1280, 800)), rate),
                Err(expected)
            );
        }
    }

    const REDUCED_ATTESTATION: Attestation = Attestation {
        nonce: 0x574f_4445_534b_0005,
        width: 1024,
        height: 384,
        digest: 0x1234_5678,
    };

    #[test]
    fn two_proven_geometries_keep_automatic_on_the_largest() {
        let selection = prove_desktop_selection(
            1,
            0,
            DESKTOP_ATTESTATION,
            Some(REDUCED_ATTESTATION),
            Some((1280, 800)),
            EDID_MILLIHZ,
        )
        .unwrap();
        assert_eq!((selection.width, selection.height), (1024, 768));
        assert_eq!((selection.second_width, selection.second_height), (1024, 384));
        assert_eq!(
            (selection.automatic_width, selection.automatic_height),
            (1024, 768)
        );
        assert_eq!(selection.entries, 3);
        assert_eq!(selection.selectable, 2);
        assert_eq!(selection.device_reported, 1);
        assert_eq!(selection.refresh, RefreshEvidence::Unavailable);
    }

    #[test]
    fn the_larger_of_two_proven_geometries_wins_automatic() {
        // Same two geometries, discovered in the other order: the result must
        // come from the proven areas, not from which one was attested first.
        let selection = prove_desktop_selection(
            1,
            0,
            REDUCED_ATTESTATION,
            Some(DESKTOP_ATTESTATION),
            None,
            EDID_MILLIHZ,
        )
        .unwrap();
        assert_eq!(
            (selection.automatic_width, selection.automatic_height),
            (1024, 768)
        );
        assert_eq!(selection.width, 1024);
        assert_eq!(selection.height, 384);
        assert_eq!((selection.second_width, selection.second_height), (1024, 768));
    }

    #[test]
    fn a_duplicate_second_geometry_is_refused() {
        let same = Attestation { digest: 0x9999_0001, ..DESKTOP_ATTESTATION };
        assert_eq!(
            prove_desktop_selection(
                1,
                0,
                DESKTOP_ATTESTATION,
                Some(same),
                None,
                EDID_MILLIHZ
            ),
            Err("catalog_second_not_distinct")
        );
    }

    #[test]
    fn a_second_geometry_must_be_attested_to_enter_the_catalog() {
        // Without the second attestation the same geometry the device can
        // really display is still refused: only pixel proof creates an entry.
        let selection = prove_desktop_selection(
            1,
            0,
            DESKTOP_ATTESTATION,
            None,
            None,
            EDID_MILLIHZ,
        )
        .unwrap();
        assert_eq!((selection.second_width, selection.second_height), (0, 0));
        assert_eq!(selection.selectable, 1);
    }

    #[test]
    fn a_second_geometry_never_gains_an_invented_refresh() {
        let with_rate = Attestation {
            nonce: 0x574f_4445_534b_0005,
            width: 1024,
            height: 384,
            digest: 0x1234_5678,
        };
        assert_eq!(with_rate.entry(0).refresh, RefreshEvidence::Unavailable);
        let selection = prove_desktop_selection(
            1,
            0,
            DESKTOP_ATTESTATION,
            Some(with_rate),
            None,
            EDID_MILLIHZ,
        )
        .unwrap();
        assert_eq!(selection.refresh, RefreshEvidence::Unavailable);
    }

    #[test]
    fn device_reported_constructor_is_never_selectable() {
        let claim = ModeEntry::device_reported(0, 1024, 768, RefreshEvidence::Unavailable);
        assert!(!claim.selectable());
        assert_eq!(claim.refresh_label(), "unavailable");
        let mut modes = ModeCatalog::new(4).unwrap();
        modes.record(claim).unwrap();
        assert_eq!(modes.selectable_count(), 0);
        assert_eq!(modes.choose(4, UserChoice::AUTOMATIC), Err(CatalogError::NoSelectableMode));
        assert_eq!(modes.choose(4, exact(1024, 768)), Err(CatalogError::UnprovenGpuTiming));
        // Only an accepted attestation turns the same geometry selectable.
        modes
            .record(Attestation { width: 1024, height: 768, ..DESKTOP_ATTESTATION }.entry(0))
            .unwrap();
        assert_eq!(modes.selectable_count(), 1);
    }
}
