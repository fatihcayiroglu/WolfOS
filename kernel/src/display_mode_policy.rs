//! WolfOS display selection policy (pure, allocation-free, no register I/O).
//! Driver-supplied connector timings and GPU pipeline limits are required.
//! No refresh rate is synthesized from a QEMU VBE resolution register.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    /// Exact rational timings rounded to millihertz (e.g. 59940 = 59.94 Hz).
    pub refresh_millihz: u32,
    /// Clock of the full video timing, including blanking intervals.
    pub pixel_clock_khz: u32,
    pub preferred: bool,
    pub interlaced: bool,
}

impl DisplayMode {
    /// Preferred/native is metadata, not a scanout register. Match only the
    /// actual timing fields when comparing hardware readback.
    pub fn same_timing(self, other: Self) -> bool {
        self.width == other.width && self.height == other.height
            && self.refresh_millihz == other.refresh_millihz
            && self.pixel_clock_khz == other.pixel_clock_khz
            && self.interlaced == other.interlaced
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipelineLimits {
    pub max_width: u32,
    pub max_height: u32,
    pub max_pixel_clock_khz: u32,
    pub max_refresh_millihz: u32,
    pub supports_interlaced: bool,
}

impl PipelineLimits {
    pub fn allows(self, mode: DisplayMode) -> bool {
        mode.width > 0
            && mode.height > 0
            && mode.refresh_millihz > 0
            && mode.refresh_millihz <= self.max_refresh_millihz
            && mode.pixel_clock_khz > 0
            && mode.width <= self.max_width
            && mode.height <= self.max_height
            && mode.pixel_clock_khz <= self.max_pixel_clock_khz
            && (!mode.interlaced || self.supports_interlaced)
            && (mode.width as u64).checked_mul(mode.height as u64).is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionChoice {
    Automatic,
    Exact { width: u32, height: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshChoice {
    Automatic,
    ExactMilliHz(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserChoice {
    pub resolution: ResolutionChoice,
    pub refresh: RefreshChoice,
}

impl UserChoice {
    pub const AUTOMATIC: Self = Self {
        resolution: ResolutionChoice::Automatic,
        refresh: RefreshChoice::Automatic,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeError {
    NoTrustedModes,
    UnsupportedSelection,
    InvalidTransaction,
    StaleConnector,
    DeviceDidNotApply,
    ConfirmationExpired,
}

/// Modes MUST come from a verified connector/EDID and driver pipeline
/// intersection, never a synthetic list of hypothetical Hz values.
/// The pipeline limit further narrows permitted options.
pub fn choose(
    advertised: &[DisplayMode],
    pipeline: PipelineLimits,
    choice: UserChoice,
) -> Result<DisplayMode, ModeError> {
    if advertised.is_empty() {
        return Err(ModeError::NoTrustedModes);
    }
    let mut best: Option<DisplayMode> = None;
    for mode in advertised.iter().copied() {
        if !pipeline.allows(mode) {
            continue;
        }
        if let ResolutionChoice::Exact { width, height } = choice.resolution {
            if mode.width != width || mode.height != height {
                continue;
            }
        }
        if let RefreshChoice::ExactMilliHz(rate) = choice.refresh {
            if mode.refresh_millihz != rate {
                continue;
            }
        }
        // Preferred native timing wins. Within equivalent preferences,
        // retain maximum area and then maximum supported refresh.
        // The driver supplies only modes safe for its link/bandwidth budget.
        let priority = (
            u8::from(mode.preferred),
            (mode.width as u64) * (mode.height as u64),
            mode.refresh_millihz,
        );
        let replace = match best {
            Some(current) => {
                let current_priority = (
                    u8::from(current.preferred),
                    (current.width as u64) * (current.height as u64),
                    current.refresh_millihz,
                );
                priority > current_priority
            }
            None => true,
        };
        if replace {
            best = Some(mode);
        }
    }
    best.ok_or(ModeError::UnsupportedSelection)
}

/// A rollback *plan*, not an assertion that hardware has already switched.
/// On an unconfirmed request the display manager must physically reapply
/// previous, then verify the actual connector/scanout before committing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeChangePlan {
    pub previous: DisplayMode,
    pub requested: DisplayMode,
    pub connector_generation: u64,
    pub confirmation_token: u64,
    pub confirmation_deadline_ms: u64,
}

pub const CONFIRM_WINDOW_MS: u64 = 15_000;

impl ModeChangePlan {
    pub fn rollback_target(self) -> DisplayMode { self.previous }
    pub fn timed_out(self, now_ms: u64) -> bool { now_ms >= self.confirmation_deadline_ms }

    /// Only user confirmation for the matching connector and actual observed
    /// timing before the deadline can acknowledge success. The display manager
    /// must actually reapply rollback_target on timeout or hotplug.
    pub fn confirm(
        self,
        token: u64,
        connector_generation: u64,
        observed: DisplayMode,
        now_ms: u64,
    ) -> Result<DisplayMode, ModeError> {
        if token != self.confirmation_token || token == 0 {
            return Err(ModeError::InvalidTransaction);
        }
        if connector_generation != self.connector_generation {
            return Err(ModeError::StaleConnector);
        }
        if self.timed_out(now_ms) {
            return Err(ModeError::ConfirmationExpired);
        }
        if !observed.same_timing(self.requested) {
            return Err(ModeError::DeviceDidNotApply);
        }
        Ok(observed)
    }
}

pub fn plan_change(
    current: DisplayMode,
    advertised: &[DisplayMode],
    pipeline: PipelineLimits,
    choice: UserChoice,
    connector_generation: u64,
    confirmation_token: u64,
    now_ms: u64,
) -> Result<Option<ModeChangePlan>, ModeError> {
    if confirmation_token == 0 || connector_generation == 0 {
        return Err(ModeError::InvalidTransaction);
    }
    // Do not attempt a new timing unless both old and new timings are
    // inside the connector's currently verified supported list.
    if !pipeline.allows(current) || !advertised.iter().any(|m|m.same_timing(current)) {
        return Err(ModeError::UnsupportedSelection);
    }
    let selected = choose(advertised, pipeline, choice)?;
    if selected.same_timing(current) {
        return Ok(None);
    }
    let deadline = now_ms.checked_add(CONFIRM_WINDOW_MS)
        .ok_or(ModeError::InvalidTransaction)?;
    Ok(Some(ModeChangePlan {
        previous: current,
        requested: selected,
        connector_generation,
        confirmation_token,
        confirmation_deadline_ms: deadline,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    const GPU: PipelineLimits = PipelineLimits {
        max_width: 3840, max_height: 2160, max_pixel_clock_khz: 700_000,
        max_refresh_millihz: 500_000, supports_interlaced: false,
    };
    const M1080_60: DisplayMode = DisplayMode {
        width: 1920, height: 1080, refresh_millihz: 60_000,
        pixel_clock_khz: 148_500, preferred: false, interlaced: false,
    };
    const M1080_144: DisplayMode = DisplayMode {
        refresh_millihz: 144_000, pixel_clock_khz: 360_000,
        ..M1080_60
    };
    const NATIVE: DisplayMode = DisplayMode {
        width: 2560, height: 1440, refresh_millihz: 120_000,
        pixel_clock_khz: 500_000, preferred: true, interlaced: false,
    };
    const M4K_30: DisplayMode = DisplayMode {
        width: 3840, height: 2160, refresh_millihz: 30_000,
        pixel_clock_khz: 297_000, preferred: false, interlaced: false,
    };
    const MODES: [DisplayMode; 4] = [M1080_60, M4K_30, NATIVE, M1080_144];

    fn pick(resolution: ResolutionChoice, refresh: RefreshChoice)
        -> Result<DisplayMode,ModeError>
    {
        choose(&MODES, GPU, UserChoice { resolution, refresh })
    }

    #[test]
    fn auto_prefers_trusted_native_timing_not_highest_pixel_count() {
        assert_eq!(choose(&MODES, GPU, UserChoice::AUTOMATIC), Ok(NATIVE));
    }
    #[test]
    fn manually_select_resolution_and_hz_independently() {
        assert_eq!(pick(ResolutionChoice::Exact { width: 1920, height: 1080 },
                        RefreshChoice::Automatic), Ok(M1080_144));
        assert_eq!(pick(ResolutionChoice::Exact { width: 1920, height: 1080 },
                        RefreshChoice::ExactMilliHz(60_000)), Ok(M1080_60));
    }
    #[test]
    fn manual_refresh_with_auto_resolution_only_chooses_matching_supported_mode() {
        assert_eq!(pick(ResolutionChoice::Automatic, RefreshChoice::ExactMilliHz(144_000)),
                   Ok(M1080_144));
    }
    #[test]
    fn unsupported_refresh_never_gets_synthesized() {
        assert_eq!(pick(ResolutionChoice::Automatic, RefreshChoice::ExactMilliHz(165_000)),
                   Err(ModeError::UnsupportedSelection));
        assert_eq!(pick(ResolutionChoice::Exact { width: 2560, height: 1440 },
                        RefreshChoice::ExactMilliHz(60_000)),
                   Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn absent_edid_modes_fail_closed() {
        assert_eq!(choose(&[],GPU,UserChoice::AUTOMATIC),Err(ModeError::NoTrustedModes));
    }
    #[test]
    fn no_unverified_overclocked_timing() {
        let overclocked=DisplayMode{refresh_millihz:600_000,..NATIVE};
        assert_eq!(choose(&[overclocked],GPU,UserChoice::AUTOMATIC),
                   Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn reject_unsupported_pipeline_pixel_clock() {
        assert_eq!(choose(&[NATIVE],PipelineLimits {
            max_pixel_clock_khz:400_000,..GPU
        },UserChoice::AUTOMATIC),Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn reject_resolution_above_gpu_pipe_limits() {
        assert_eq!(choose(&[NATIVE],PipelineLimits {
            max_width:1920,..GPU
        },UserChoice::AUTOMATIC),Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn reject_interlaced_without_driver_support() {
        let interlaced=DisplayMode{interlaced:true,..M1080_60};
        assert_eq!(choose(&[interlaced],GPU,UserChoice::AUTOMATIC),
                   Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn reject_zero_clock_resolution_or_refresh() {
        for invalid in [
            DisplayMode {pixel_clock_khz:0,..NATIVE},
            DisplayMode {width:0,..NATIVE},
            DisplayMode {height:0,..NATIVE},
            DisplayMode {refresh_millihz:0,..NATIVE},
        ] {
            assert_eq!(choose(&[invalid],GPU,UserChoice::AUTOMATIC),
                       Err(ModeError::UnsupportedSelection));
        }
    }
    #[test]
    fn native_tie_chooses_highest_verified_refresh() {
        let preferred60=DisplayMode{refresh_millihz:60_000,pixel_clock_khz:245_000,..NATIVE};
        assert_eq!(choose(&[preferred60,NATIVE],GPU,UserChoice::AUTOMATIC),Ok(NATIVE));
    }
    #[test]
    fn manual_resolution_with_auto_rate_is_never_silent_overclock() {
        let unsafe_fast=DisplayMode{refresh_millihz:165_000,pixel_clock_khz:800_000,..M1080_60};
        assert_eq!(choose(&[M1080_60,unsafe_fast],GPU,UserChoice {
            resolution: ResolutionChoice::Exact{width:1920,height:1080},
            refresh:RefreshChoice::Automatic
        }),Ok(M1080_60));
    }
    #[test]
    fn plan_requires_verified_current_mode_and_matching_connector_generation() {
        assert_eq!(plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,1,2,100).unwrap()
                   .unwrap().requested,NATIVE);
        assert_eq!(plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,0,2,100),
                   Err(ModeError::InvalidTransaction));
        assert_eq!(plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,1,0,100),
                   Err(ModeError::InvalidTransaction));
        assert_eq!(plan_change(DisplayMode{width:1000,..M1080_60},&MODES,GPU,
                   UserChoice::AUTOMATIC,1,2,100),Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn no_switch_needed_returns_no_confirmation_dialog() {
        assert_eq!(plan_change(NATIVE,&MODES,GPU,UserChoice::AUTOMATIC,7,11,100),Ok(None));
    }
    #[test]
    fn plan_keeps_old_mode_for_failed_or_timeout_rollback() {
        let plan=plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,7,11,100)
                 .unwrap().unwrap();
        assert_eq!(plan.rollback_target(),M1080_60);
        assert_eq!(plan.requested,NATIVE);
        assert_eq!(plan.confirm(11,7,NATIVE,500),Ok(NATIVE));
    }
    #[test]
    fn cannot_confirm_without_actual_hardware_mode() {
        let plan=plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,7,11,100)
                 .unwrap().unwrap();
        assert_eq!(plan.confirm(11,7,M1080_60,500),Err(ModeError::DeviceDidNotApply));
        assert_eq!(plan.rollback_target(),M1080_60);
    }
    #[test]
    fn reject_stale_connector_or_confirmation_token() {
        let plan=plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,7,11,100)
                 .unwrap().unwrap();
        assert_eq!(plan.confirm(12,7,NATIVE,500),Err(ModeError::InvalidTransaction));
        assert_eq!(plan.confirm(11,8,NATIVE,500),Err(ModeError::StaleConnector));
    }
    #[test]
    fn deadline_requires_confirm_before_15_seconds() {
        let plan=plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,7,11,100)
                 .unwrap().unwrap();
        assert_eq!(plan.confirmation_deadline_ms,15100);
        assert!(!plan.timed_out(15099));
        assert!(plan.timed_out(15100));
        assert_eq!(plan.confirm(11,7,NATIVE,15099),Ok(NATIVE));
        assert_eq!(plan.confirm(11,7,NATIVE,15100),Err(ModeError::ConfirmationExpired));
        assert_eq!(plan.rollback_target(),M1080_60);
    }
    #[test]
    fn reject_deadline_overflow_without_switch() {
        assert_eq!(plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,7,11,u64::MAX),
                   Err(ModeError::InvalidTransaction));
    }
    #[test]
    fn hardware_readback_ignores_preferred_flag_metadata() {
        let mut current=NATIVE;
        current.preferred=false;
        assert_eq!(plan_change(current,&MODES,GPU,UserChoice::AUTOMATIC,7,11,100),Ok(None));
        let plan=plan_change(M1080_60,&MODES,GPU,UserChoice::AUTOMATIC,7,11,100)
                 .unwrap().unwrap();
        assert_eq!(plan.confirm(11,7,current,500),Ok(current));
    }
    #[test]
    fn manual_selection_rejects_nonadvertised_height() {
        assert_eq!(pick(ResolutionChoice::Exact{width:2560,height:1600},
                        RefreshChoice::Automatic),
                   Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn exact_5994_hz_not_rounded_to_60_hz() {
        let almost60=DisplayMode{refresh_millihz:59_940,..M1080_60};
        assert_eq!(choose(&[almost60],GPU,UserChoice {
            resolution:ResolutionChoice::Automatic,
            refresh:RefreshChoice::ExactMilliHz(60_000)
        }),Err(ModeError::UnsupportedSelection));
        assert_eq!(choose(&[almost60],GPU,UserChoice {
            resolution:ResolutionChoice::Automatic,
            refresh:RefreshChoice::ExactMilliHz(59_940)
        }),Ok(almost60));
    }
}
