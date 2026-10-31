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
use standalone_registry::ProcessTable;
#[cfg(test)]
use standalone_registry::standalone_process::ProcessState;
#[cfg(not(test))]
use crate::process_table::ProcessTable;
#[cfg(not(test))]
use crate::process_lifecycle::ProcessState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnknownProcess,
    InvalidProcessIdentity,
    WrongState,
    OutstandingSurfaces,
    Ledger(LedgerError),
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::surface_ledger::State;

    fn rect(x:u32,y:u32,w:u32,h:u32)->Rect {
        Rect::checked(x,y,w,h).unwrap()
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
