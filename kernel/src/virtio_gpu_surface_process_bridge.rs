//! Authenticated *metadata* bridge from WolfOS ProcessTable to GPU surfaces.
//!
//! ProcessTable owns monotonic 64-bit PID generations; clients MUST NOT mint a
//! process_generation themselves. This bridge accepts only exact live registry
//! snapshots and passes the registry-minted generation to SurfaceLedger.
//! Every operation requires one trusted external lock covering BOTH tables,
//! user-memory lifetime and cancellation. No CPU or GPU hardware is accessed.

use super::damage::Rect;
use super::surface_ledger::{Error as LedgerError, SurfaceLedger};
use super::surface_pixels::{CompositionReport, Identity, SurfacePixels};

#[cfg(test)]
#[path = "process_table.rs"]
mod standalone_registry;
#[cfg(test)]
use standalone_registry::{ProcessTable, TableError};
#[cfg(test)]
use standalone_registry::standalone_process::{CountedFrames, ProcessState};
#[cfg(not(test))]
use crate::process_table::{ProcessTable, TableError};
#[cfg(not(test))]
use crate::process_lifecycle::{CountedFrames, ProcessState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnknownProcess,
    InvalidProcessIdentity,
    WrongState,
    OutstandingSurfaces,
    Ledger(LedgerError),
    Process(TableError),
}

fn live_for_graphics(state: ProcessState) -> bool {
    matches!(state, ProcessState::Ready | ProcessState::Running | ProcessState::Blocked)
}

fn registry_owner<const S: usize, const F: usize>(
    registry: &ProcessTable<S,F>, pid: u64
) -> Result<ProcessState, Error> {
    if pid == 0 { return Err(Error::InvalidProcessIdentity); }
    let rec = registry.snapshot(pid).ok_or(Error::UnknownProcess)?;
    if rec.pid != pid { return Err(Error::InvalidProcessIdentity); }
    Ok(rec.state)
}

/// PID is already a monotonic generation in the existing WolfOS process
/// registry. Both identity fields are bound to that authoritative 64-bit
/// value; neither can be selected by a Ring3 application.
pub fn open_registered<const S: usize, const F: usize, const N: usize>(
    registry: &ProcessTable<S,F>,
    ledger: &mut SurfaceLedger<N>,
    pid: u64,
) -> Result<Identity, Error> {
    if !live_for_graphics(registry_owner(registry,pid)?) {
        return Err(Error::WrongState);
    }
    ledger.open(pid,pid).map_err(Error::Ledger)
}

fn authorize_surface<const S: usize, const F: usize>(
    registry: &ProcessTable<S,F>, identity: Identity
) -> Result<(), Error> {
    let state=registry_owner(registry,identity.pid)?;
    if identity.process_generation != identity.pid {
        return Err(Error::InvalidProcessIdentity);
    }
    if !live_for_graphics(state) { return Err(Error::WrongState); }
    Ok(())
}

/// Validates BOTH actual ProcessTable owners, then the full generation-tagged
/// ledger handles, then only the requested rectangle's pixels are written.
/// The caller must hold one lock throughout; this does NOT map user pages.
#[allow(clippy::too_many_arguments)]
pub fn compose_registered<const S: usize, const F: usize, const N: usize>(
    registry: &ProcessTable<S,F>,
    ledger: &SurfaceLedger<N>,
    destination: &mut [u32],
    background: &[u32],
    viewport: Rect,
    stride: usize,
    damage: Rect,
    first: SurfacePixels<'_>,
    second: SurfacePixels<'_>,
    top: Identity,
) -> Result<CompositionReport, Error> {
    authorize_surface(registry,first.identity())?;
    authorize_surface(registry,second.identity())?;
    ledger.compose_live(destination,background,viewport,stride,damage,
                        first,second,top).map_err(Error::Ledger)
}

/// Fail closed when an exited process still has a surface. Teardown must
/// run close_exited() then independently drain/retire all handles *before*
/// invoking ProcessTable::reap. This check itself does not mutate ProcessTable.
pub fn ready_to_reap<const S: usize, const F: usize, const N: usize>(
    registry: &ProcessTable<S,F>, ledger: &SurfaceLedger<N>, pid: u64,
) -> Result<(), Error> {
    if registry_owner(registry,pid)? != ProcessState::Exited {
        return Err(Error::WrongState);
    }
    if ledger.owner_remaining(pid,pid) != 0 {
        return Err(Error::OutstandingSurfaces);
    }
    Ok(())
}

fn close_owner<const N: usize>(
    ledger: &mut SurfaceLedger<N>, pid: u64
) -> Result<usize, Error> {
    match ledger.close_owner(pid,pid) {
        Ok(count) => Ok(count),
        // Exited processes may have never created a GUI surface.
        Err(LedgerError::StaleOwner) => Ok(0),
        Err(err) => Err(Error::Ledger(err)),
    }
}

/// Call under the same lock after ProcessTable has recorded EXITED and
/// before PMM release. No GPU completion is fabricated.
pub fn close_exited<const S: usize, const F: usize, const N: usize>(
    registry: &ProcessTable<S,F>,
    ledger: &mut SurfaceLedger<N>, pid: u64,
) -> Result<usize, Error> {
    if registry_owner(registry,pid)? != ProcessState::Exited {
        return Err(Error::WrongState);
    }
    close_owner(ledger,pid)
}

/// READY/BLOCKED cancellation needs the same surface drain as EXITED reap.
/// The real scheduler must have quiesced saved contexts/CPU handoffs and must
/// acquire its coordinator lock BEFORE using the ProcessTable cancel path.
pub fn close_for_cancel<const S: usize, const F: usize, const N: usize>(
    registry: &ProcessTable<S,F>,
    ledger: &mut SurfaceLedger<N>, pid: u64,
) -> Result<usize, Error> {
    if !matches!(registry_owner(registry,pid)?,
                 ProcessState::Ready | ProcessState::Blocked) {
        return Err(Error::WrongState);
    }
    close_owner(ledger,pid)
}

/// Metadata-only cancellation barrier; it does not establish that an AP
/// has left CR3, that a saved IRET context has been invalidated, or that
/// the VirtIO device is quiescent.
pub fn ready_to_cancel<const S: usize, const F: usize, const N: usize>(
    registry: &ProcessTable<S,F>, ledger: &SurfaceLedger<N>, pid: u64,
) -> Result<(), Error> {
    if !matches!(registry_owner(registry,pid)?,
                 ProcessState::Ready | ProcessState::Blocked) {
        return Err(Error::WrongState);
    }
    if ledger.owner_remaining(pid,pid) != 0 {
        return Err(Error::OutstandingSurfaces);
    }
    Ok(())
}

/// This is the first *actual call-through* from the graphics surface barrier
/// to the existing ProcessTable exit-reaping entry point. It denies the
/// underlying registry call while any surface handle remains (including a
/// closing, DMA-pinned handle). A wrong supervisor CR3 still fails via the
/// original ProcessTable check and never returns a PMM lease.
///
/// The caller MUST hold the production coordinator lock across BOTH ledgers,
/// trap/CPU quiescence and this invocation. This helper cannot stop legacy
/// callers invoking ProcessTable::reap directly; it is not hooked to an
/// actual Ring3 EXIT handler or PMM release yet.
pub fn reap_counted_guarded<const S: usize, const F: usize, const N: usize>(
    registry: &mut ProcessTable<S,F>,
    surfaces: &mut SurfaceLedger<N>,
    pid: u64,
    supervisor_cr3: u64,
) -> Result<(u32, CountedFrames<F>), Error> {
    close_exited(registry, surfaces, pid)?;
    ready_to_reap(registry, surfaces, pid)?;
    registry.reap_with_status_counted(pid, supervisor_cr3)
        .map_err(Error::Process)
}

/// The exact READY owner must close and drain every surface before a
/// cancellation may return an owned PMM frame lease. No implicit success or
/// fake GPU flush is manufactured when genuine acknowledgements are absent.
pub fn cancel_ready_counted_guarded<const S: usize, const F: usize, const N: usize>(
    registry: &mut ProcessTable<S,F>,
    surfaces: &mut SurfaceLedger<N>,
    pid: u64,
    supervisor_cr3: u64,
) -> Result<CountedFrames<F>, Error> {
    if registry_owner(registry, pid)? != ProcessState::Ready {
        return Err(Error::WrongState);
    }
    close_for_cancel(registry, surfaces, pid)?;
    ready_to_cancel(registry, surfaces, pid)?;
    registry.cancel_ready_counted(pid, supervisor_cr3)
        .map_err(Error::Process)
}

/// BLOCKED state has an independent cancellation entry point: never allow a
/// ready-process cancel call to silently consume a blocked saved IRET owner.
pub fn cancel_blocked_counted_guarded<const S: usize, const F: usize, const N: usize>(
    registry: &mut ProcessTable<S,F>,
    surfaces: &mut SurfaceLedger<N>,
    pid: u64,
    supervisor_cr3: u64,
) -> Result<CountedFrames<F>, Error> {
    if registry_owner(registry, pid)? != ProcessState::Blocked {
        return Err(Error::WrongState);
    }
    close_for_cancel(registry, surfaces, pid)?;
    ready_to_cancel(registry, surfaces, pid)?;
    registry.cancel_blocked_counted(pid, supervisor_cr3)
        .map_err(Error::Process)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::surface_ledger::State;

    fn rect(x:u32,y:u32,w:u32,h:u32)->Rect {
        Rect::checked(x,y,w,h).unwrap()
    }

    #[test]
    fn guarded_reap_refuses_two_inflight_gpu_fences_before_registry_reap() {
        let mut registry=ProcessTable::<1,3>::new();
        let mut surfaces=SurfaceLedger::<1>::new();
        let pid=registry.reserve(0x1000,[0x1000,0x2000,0x3000]).unwrap();
        let id=open_registered(&registry,&mut surfaces,pid).unwrap();
        surfaces.begin_submit(id,100,101).unwrap();
        registry.mark_running(pid,0x1000).unwrap();
        registry.exit_with_status(pid,0x1000,42).unwrap();

        assert_eq!(reap_counted_guarded(&mut registry,&mut surfaces,pid,0x9000),
                   Err(Error::OutstandingSurfaces));
        assert_eq!(registry.snapshot(pid).unwrap().state,ProcessState::Exited);
        assert_eq!(surfaces.state(id),Ok(State::ClosingSubmitted));
        assert_eq!(surfaces.release(id),Err(LedgerError::StillPinned));

        surfaces.ack_transfer(id,100).unwrap();
        assert_eq!(reap_counted_guarded(&mut registry,&mut surfaces,pid,0x9000),
                   Err(Error::OutstandingSurfaces));
        assert_eq!(surfaces.state(id),Ok(State::ClosingTransferred));
        surfaces.ack_flush(id,101).unwrap();
        // Even after all GPU replies, metadata must be retired explicitly.
        assert_eq!(reap_counted_guarded(&mut registry,&mut surfaces,pid,0x9000),
                   Err(Error::OutstandingSurfaces));
        surfaces.release(id).unwrap();

        // The original process registry STILL checks real supervisor CR3.
        assert!(matches!(reap_counted_guarded(&mut registry,&mut surfaces,pid,
                           0x1000),Err(Error::Process(_))));
        assert_eq!(registry.snapshot(pid).unwrap().state,ProcessState::Exited);
        let (status,frames)=reap_counted_guarded(
            &mut registry,&mut surfaces,pid,0x9000).unwrap();
        assert_eq!(status,42);
        assert_eq!(frames.as_slice(),&[0x1000,0x2000,0x3000]);
        assert_eq!(reap_counted_guarded(&mut registry,&mut surfaces,pid,0x9000),
                   Err(Error::UnknownProcess));
    }

    #[test]
    fn guarded_ready_cancel_refuses_stale_dma_and_preserves_other_pid() {
        let mut registry=ProcessTable::<2,2>::new();
        let mut surfaces=SurfaceLedger::<2>::new();
        let p1=registry.reserve(0x1000,[0x1000,0x2000]).unwrap();
        let p2=registry.reserve(0x3000,[0x3000,0x4000]).unwrap();
        let a=open_registered(&registry,&mut surfaces,p1).unwrap();
        let b=open_registered(&registry,&mut surfaces,p2).unwrap();
        surfaces.begin_submit(a,1,2).unwrap();

        assert_eq!(cancel_ready_counted_guarded(&mut registry,&mut surfaces,p1,0x9000),
                   Err(Error::OutstandingSurfaces));
        assert_eq!(surfaces.state(a),Ok(State::ClosingSubmitted));
        assert_eq!(surfaces.state(b),Ok(State::Live));
        assert_eq!(registry.occupied(),2);
        surfaces.ack_transfer(a,1).unwrap();
        assert_eq!(cancel_ready_counted_guarded(&mut registry,&mut surfaces,p1,0x9000),
                   Err(Error::OutstandingSurfaces));
        surfaces.ack_flush(a,2).unwrap();
        surfaces.release(a).unwrap();

        // Invalid supervisor root does not return the PMM lease or reap p1.
        assert!(matches!(cancel_ready_counted_guarded(
            &mut registry,&mut surfaces,p1,0x3000),Err(Error::Process(_))));
        assert!(registry.snapshot(p1).is_some());
        assert_eq!(surfaces.state(b),Ok(State::Live));
        let lease=cancel_ready_counted_guarded(
            &mut registry,&mut surfaces,p1,0x9000).unwrap();
        assert_eq!(lease.as_slice(),&[0x1000,0x2000]);
        assert!(registry.snapshot(p1).is_none());
        assert_eq!(registry.snapshot(p2).unwrap().state,ProcessState::Ready);
        assert_eq!(surfaces.state(b),Ok(State::Live));
    }

    #[test]
    fn blocked_cancel_is_separate_and_cannot_bypass_pending_surface() {
        let mut registry=ProcessTable::<1,2>::new();
        let mut surfaces=SurfaceLedger::<1>::new();
        let pid=registry.reserve(0x1000,[0x1000,0x2000]).unwrap();
        let id=open_registered(&registry,&mut surfaces,pid).unwrap();
        registry.mark_running(pid,0x1000).unwrap();
        registry.block_running(pid,0x1000).unwrap();
        assert_eq!(cancel_ready_counted_guarded(
            &mut registry,&mut surfaces,pid,0x9000),Err(Error::WrongState));

        surfaces.begin_submit(id,8,9).unwrap();
        assert_eq!(cancel_blocked_counted_guarded(
            &mut registry,&mut surfaces,pid,0x9000),Err(Error::OutstandingSurfaces));
        assert_eq!(surfaces.state(id),Ok(State::ClosingSubmitted));
        surfaces.ack_transfer(id,8).unwrap();
        surfaces.ack_flush(id,9).unwrap();
        surfaces.release(id).unwrap();
        let frames=cancel_blocked_counted_guarded(
            &mut registry,&mut surfaces,pid,0x9000).unwrap();
        assert_eq!(frames.as_slice(),&[0x1000,0x2000]);
        assert!(registry.snapshot(pid).is_none());
        assert_eq!(surfaces.require_live(id),Err(LedgerError::StaleHandle));
    }

    #[test]
    fn zero_gui_owner_reaps_and_cancels_without_fake_gpu_completions() {
        let mut registry=ProcessTable::<2,2>::new();
        let mut surfaces=SurfaceLedger::<0>::new();
        let exited=registry.reserve(0x1000,[0x1000,0x2000]).unwrap();
        let ready=registry.reserve(0x3000,[0x3000,0x4000]).unwrap();
        registry.mark_running(exited,0x1000).unwrap();
        registry.exit_zero(exited,0x1000).unwrap();
        let (code,frames)=reap_counted_guarded(
            &mut registry,&mut surfaces,exited,0x9000).unwrap();
        assert_eq!(code,0);
        assert_eq!(frames.as_slice(),&[0x1000,0x2000]);
        assert_eq!(cancel_ready_counted_guarded(
            &mut registry,&mut surfaces,ready,0x9000).unwrap().as_slice(),
            &[0x3000,0x4000]);
        assert_eq!(registry.occupied(),0);
    }

    #[test]
    fn wrong_process_state_or_stale_pid_never_releases_registry_frames() {
        let mut registry=ProcessTable::<1,2>::new();
        let mut surfaces=SurfaceLedger::<1>::new();
        let pid=registry.reserve(0x1000,[0x1000,0x2000]).unwrap();
        let id=open_registered(&registry,&mut surfaces,pid).unwrap();
        assert_eq!(reap_counted_guarded(&mut registry,&mut surfaces,pid,0x9000),
                   Err(Error::WrongState));
        assert_eq!(cancel_blocked_counted_guarded(
            &mut registry,&mut surfaces,pid,0x9000),Err(Error::WrongState));
        assert_eq!(surfaces.state(id),Ok(State::Live));
        assert_eq!(cancel_ready_counted_guarded(
            &mut registry,&mut surfaces,pid+1,0x9000),Err(Error::UnknownProcess));
        assert_eq!(surfaces.state(id),Ok(State::Live));
        assert_eq!(registry.snapshot(pid).unwrap().state,ProcessState::Ready);
    }

    #[test]
    fn registry_mints_identity_and_rejects_unknown_pid() {
        let mut processes=ProcessTable::<2,2>::new();
        let mut ledger=SurfaceLedger::<2>::new();
        assert_eq!(open_registered(&processes,&mut ledger,0),
                   Err(Error::InvalidProcessIdentity));
        assert_eq!(open_registered(&processes,&mut ledger,77),
                   Err(Error::UnknownProcess));
        let pid=processes.reserve(0x1000,[0x1000,0x2000]).unwrap();
        let surface=open_registered(&processes,&mut ledger,pid).unwrap();
        assert_eq!(surface.pid,pid);
        assert_eq!(surface.process_generation,pid);
        assert_eq!(surface.surface_generation,1);
        assert_eq!(ledger.state(surface),Ok(State::Live));
        assert_eq!(open_registered(&processes,&mut ledger,pid+1),
                   Err(Error::UnknownProcess));
    }

    #[test]
    fn exited_process_must_revoke_and_drain_before_reap() {
        let mut processes=ProcessTable::<2,2>::new();
        let mut ledger=SurfaceLedger::<2>::new();
        let pid=processes.reserve(0x1000,[0x1000,0x2000]).unwrap();
        let surface=open_registered(&processes,&mut ledger,pid).unwrap();
        ledger.begin_submit(surface,20,21).unwrap();
        processes.mark_running(pid,0x1000).unwrap();
        assert_eq!(close_exited(&processes,&mut ledger,pid),Err(Error::WrongState));
        processes.exit_with_status(pid,0x1000,42).unwrap();
        assert_eq!(open_registered(&processes,&mut ledger,pid),
                   Err(Error::WrongState));
        assert_eq!(ready_to_reap(&processes,&ledger,pid),
                   Err(Error::OutstandingSurfaces));
        assert_eq!(close_exited(&processes,&mut ledger,pid),Ok(1));
        assert_eq!(ledger.require_live(surface),Err(LedgerError::NotLive));
        assert_eq!(ledger.release(surface),Err(LedgerError::StillPinned));
        ledger.ack_transfer(surface,20).unwrap();
        assert_eq!(ready_to_reap(&processes,&ledger,pid),
                   Err(Error::OutstandingSurfaces));
        ledger.ack_flush(surface,21).unwrap();
        ledger.release(surface).unwrap();
        assert_eq!(ready_to_reap(&processes,&ledger,pid),Ok(()));
        let (status,frames)=processes.reap_with_status_counted(pid,0x9000).unwrap();
        assert_eq!(status,42);
        assert_eq!(frames.as_slice(),&[0x1000,0x2000]);
        assert_eq!(ready_to_reap(&processes,&ledger,pid),Err(Error::UnknownProcess));
        assert_eq!(open_registered(&processes,&mut ledger,pid),
                   Err(Error::UnknownProcess));
    }

    #[test]
    fn cancelled_ready_owner_cannot_leave_orphan_surface() {
        let mut processes=ProcessTable::<2,2>::new();
        let mut ledger=SurfaceLedger::<2>::new();
        let pid=processes.reserve(0x3000,[0x3000,0x4000]).unwrap();
        let a=open_registered(&processes,&mut ledger,pid).unwrap();
        let b=open_registered(&processes,&mut ledger,pid).unwrap();
        assert_eq!(ready_to_cancel(&processes,&ledger,pid),
                   Err(Error::OutstandingSurfaces));
        assert_eq!(close_for_cancel(&processes,&mut ledger,pid),Ok(2));
        ledger.release(a).unwrap();
        assert_eq!(ready_to_cancel(&processes,&ledger,pid),
                   Err(Error::OutstandingSurfaces));
        ledger.release(b).unwrap();
        assert_eq!(ready_to_cancel(&processes,&ledger,pid),Ok(()));
        let frames=processes.cancel_ready_counted(pid,0x9000).unwrap();
        assert_eq!(frames.as_slice(),&[0x3000,0x4000]);
        assert_eq!(close_for_cancel(&processes,&mut ledger,pid),
                   Err(Error::UnknownProcess));
    }

    #[test]
    fn unknown_and_forged_generation_do_not_modify_composition() {
        let mut processes=ProcessTable::<3,2>::new();
        let mut ledger=SurfaceLedger::<2>::new();
        let pid_a=processes.reserve(0x1000,[0x1000,0x2000]).unwrap();
        let pid_b=processes.reserve(0x3000,[0x3000,0x4000]).unwrap();
        let id_a=open_registered(&processes,&mut ledger,pid_a).unwrap();
        let id_b=open_registered(&processes,&mut ledger,pid_b).unwrap();
        let red=[0x00fe_1010;4];
        let blue=[0x0001_02fe;4];
        let first=SurfacePixels::new(id_a,rect(1,1,2,2),2,&red).unwrap();
        let second=SurfacePixels::new(id_b,rect(2,1,2,2),2,&blue).unwrap();
        let view=rect(0,0,5,4);
        let background=[3;20];
        let mut output=[0xdead;20];
        let r=compose_registered(&processes,&ledger,&mut output,&background,
                                 view,5,view,first,second,id_b).unwrap();
        assert_eq!(r.first,2);
        assert_eq!(r.second,4);
        assert_eq!(r.background,14);

        output.fill(0xdead);
        let forged=Identity{process_generation:id_a.pid+1,..id_a};
        let forged_first=SurfacePixels::new(
            forged,rect(1,1,2,2),2,&red).unwrap();
        assert_eq!(compose_registered(&processes,&ledger,&mut output,&background,
                   view,5,view,forged_first,second,id_b),
                   Err(Error::InvalidProcessIdentity));
        assert_eq!(output,[0xdead;20]);
        assert_eq!(close_for_cancel(&processes,&mut ledger,pid_b),Ok(1));
        assert_eq!(compose_registered(&processes,&ledger,&mut output,&background,
                   view,5,view,first,second,id_b),
                   Err(Error::Ledger(LedgerError::NotLive)));
        assert_eq!(output,[0xdead;20]);
    }

    #[test]
    fn pid_reuse_is_not_surface_reuse_and_exit_without_surface_is_safe() {
        let mut processes=ProcessTable::<1,2>::new();
        let mut ledger=SurfaceLedger::<1>::new();
        let p1=processes.reserve(0x1000,[0x1000,0x2000]).unwrap();
        let old=open_registered(&processes,&mut ledger,p1).unwrap();
        close_for_cancel(&processes,&mut ledger,p1).unwrap();
        ledger.release(old).unwrap();
        ready_to_cancel(&processes,&ledger,p1).unwrap();
        processes.cancel_ready_counted(p1,0x9000).unwrap();
        let p2=processes.reserve(0x3000,[0x3000,0x4000]).unwrap();
        assert!(p2>p1);
        let fresh=open_registered(&processes,&mut ledger,p2).unwrap();
        assert_eq!(fresh.slot,old.slot);
        assert!(fresh.surface_generation>old.surface_generation);
        assert_eq!(ledger.state(old),Err(LedgerError::StaleHandle));
        processes.mark_running(p2,0x3000).unwrap();
        processes.exit_zero(p2,0x3000).unwrap();
        assert_eq!(close_exited(&processes,&mut ledger,p2),Ok(1));
        ledger.release(fresh).unwrap();
        assert_eq!(ready_to_reap(&processes,&ledger,p2),Ok(()));

        let mut another=ProcessTable::<1,2>::new();
        let no_gui=another.reserve(0x5000,[0x5000,0x6000]).unwrap();
        another.mark_running(no_gui,0x5000).unwrap();
        another.exit_zero(no_gui,0x5000).unwrap();
        assert_eq!(close_exited(&another,&mut ledger,no_gui),Ok(0));
        assert_eq!(ready_to_reap(&another,&ledger,no_gui),Ok(()));
    }
}
