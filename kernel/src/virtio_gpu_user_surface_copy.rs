//! Checked Ring3 virtual pixel snapshots into kernel-owned compositor storage.
//!
//! The trusted caller supplies a hardware-authenticated ProcessTable, the
//! still-live surface ledger and a *physical* memory provider. The existing
//! user_copy::copy_from verifies all four USER page-table levels and every
//! source byte before committing even one destination pixel. This module
//! additionally requires EVERY page-table read and leaf byte to belong to
//! the exact ProcessTable PMM lease for the claimed PID.
//!
//! This is a bounded software contract, not a real syscall or a promise of
//! stable user pages: caller must hold an exclusive coordinator lock, pin
//! the process page tables and data frames, and forbid remap/reap throughout
//! the complete copy and composition. No GPU command is submitted here.

use super::damage::Rect;
use super::surface_ledger::{Error as LedgerError, SurfaceLedger};
use super::surface_pixels::{CompositionReport, Error as PixelError, Identity, SurfacePixels};
use super::surface_process_bridge::{self, Error as BridgeError};

#[cfg(test)]
#[path = "user_copy.rs"]
mod standalone_copy;
#[cfg(test)]
use standalone_copy::{self as user_copy, CopyError};
#[cfg(not(test))]
use crate::user_copy::{self, CopyError};

#[cfg(test)]
use super::surface_process_bridge::standalone_registry::ProcessTable;
#[cfg(test)]
use super::surface_process_bridge::standalone_registry::standalone_process::ProcessState;
#[cfg(not(test))]
use crate::process_table::ProcessTable;
#[cfg(not(test))]
use crate::process_lifecycle::ProcessState;

/// Bounded pixel snapshot. With xRGB8888, at most one 256-byte syscall-sized
/// copy can be made for each of the two immutable source surfaces.
pub const MAX_SOURCE_PIXELS: usize = 64;
const MAX_SOURCE_BYTES: usize = MAX_SOURCE_PIXELS * 4;
const PAGE_MASK: u64 = !4095;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnknownProcess,
    InvalidOwnerGeneration,
    NotRunnable,
    InvalidSource,
    OversizedSource,
    BadPageOwner,
    Ledger(LedgerError),
    Copy(CopyError),
    Pixel(PixelError),
    Compose(BridgeError),
}

#[derive(Clone, Copy, Debug)]
pub struct UserSurface {
    pub identity: Identity,
    pub rect: Rect,
    pub stride: usize,
    /// Virtual address in the *owner's user CR3*, not an HHDM or kernel VA.
    pub user_va: u64,
}

fn source_len(source: UserSurface) -> Result<usize, Error> {
    Rect::checked(source.rect.x,source.rect.y,
                  source.rect.width,source.rect.height)
        .map_err(|_| Error::InvalidSource)?;
    if source.stride < source.rect.width as usize {
        return Err(Error::InvalidSource);
    }
    let pixels=source.stride.checked_mul(source.rect.height as usize)
        .ok_or(Error::OversizedSource)?;
    if pixels == 0 || pixels > MAX_SOURCE_PIXELS {
        return Err(Error::OversizedSource);
    }
    Ok(pixels)
}

fn check_owner<const S: usize, const F: usize, const N: usize>(
    registry: &ProcessTable<S,F>,
    surfaces: &SurfaceLedger<N>,
    source: UserSurface,
) -> Result<(u64, [u64;F], usize), Error> {
    if source.identity.pid == 0 ||
        source.identity.process_generation != source.identity.pid {
        return Err(Error::InvalidOwnerGeneration);
    }
    let record=registry.snapshot(source.identity.pid).ok_or(Error::UnknownProcess)?;
    if !matches!(record.state,ProcessState::Ready|ProcessState::Running|ProcessState::Blocked) {
        return Err(Error::NotRunnable);
    }
    if record.frame_count == 0 || record.frame_count > F ||
        record.cr3_root != record.frames[0] {
        return Err(Error::BadPageOwner);
    }
    surfaces.require_live(source.identity).map_err(Error::Ledger)?;
    Ok((record.cr3_root,record.frames,record.frame_count))
}

/// Sample TWO independent Ring3 owner-address-space buffers via checked 4-level
/// translation and PMM ownership before modifying the target. Each of the
/// immutable copied snapshots lives on the kernel stack, never in userspace.
///
/// The physical provider must only access already-pinned real RAM frames
/// through authenticated kernel mappings (e.g. HHDM). It MUST NOT use the
/// caller's user virtual address directly. This function refuses all physical
/// reads outside that process's exact live PMM lease, including PTE reads.
/// Multiple processes can therefore never cross-read each other's data.
#[allow(clippy::too_many_arguments)]
pub fn compose_user_snapshots<const S: usize, const F: usize, const N: usize>(
    registry: &ProcessTable<S,F>,
    surfaces: &SurfaceLedger<N>,
    destination: &mut [u32],
    background: &[u32],
    viewport: Rect,
    stride: usize,
    damage: Rect,
    first: UserSurface,
    second: UserSurface,
    top: Identity,
    mut read_pte: impl FnMut(u64) -> Option<u64>,
    mut read_byte: impl FnMut(u64) -> Option<u8>,
) -> Result<CompositionReport, Error> {
    let count_a=source_len(first)?;
    let count_b=source_len(second)?;
    let (root_a,owned_a,len_a)=check_owner(registry,surfaces,first)?;
    let (root_b,owned_b,len_b)=check_owner(registry,surfaces,second)?;

    // Exact ownership also guards PTE lookups, not just user leaf bytes.
    let mut a_bytes=[0u8; MAX_SOURCE_BYTES];
    user_copy::copy_from(root_a,first.user_va,&mut a_bytes[..count_a*4],
        |ptr| {
            if !owned_a[..len_a].contains(&(ptr & PAGE_MASK)) { return None }
            read_pte(ptr)
        },
        |phys| {
            if !owned_a[..len_a].contains(&(phys & PAGE_MASK)) { return None }
            read_byte(phys)
        },
    ).map_err(Error::Copy)?;

    let mut b_bytes=[0u8; MAX_SOURCE_BYTES];
    user_copy::copy_from(root_b,second.user_va,&mut b_bytes[..count_b*4],
        |ptr| {
            if !owned_b[..len_b].contains(&(ptr & PAGE_MASK)) { return None }
            read_pte(ptr)
        },
        |phys| {
            if !owned_b[..len_b].contains(&(phys & PAGE_MASK)) { return None }
            read_byte(phys)
        },
    ).map_err(Error::Copy)?;

    let mut a_pixels=[0u32;MAX_SOURCE_PIXELS];
    let mut b_pixels=[0u32;MAX_SOURCE_PIXELS];
    for (i,word) in a_pixels[..count_a].iter_mut().enumerate() {
        *word=u32::from_le_bytes(a_bytes[i*4..i*4+4].try_into().unwrap());
    }
    for (i,word) in b_pixels[..count_b].iter_mut().enumerate() {
        *word=u32::from_le_bytes(b_bytes[i*4..i*4+4].try_into().unwrap());
    }
    let a=SurfacePixels::new(first.identity,first.rect,first.stride,
                             &a_pixels[..count_a]).map_err(Error::Pixel)?;
    let b=SurfacePixels::new(second.identity,second.rect,second.stride,
                             &b_pixels[..count_b]).map_err(Error::Pixel)?;
    surface_process_bridge::compose_registered(
        registry,surfaces,destination,background,viewport,stride,damage,
        a,b,top,
    ).map_err(Error::Compose)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Machine {
        a: [u8;256],
        b: [u8;256],
        steal_a_leaf: bool,
        supervisor_pte: bool,
    }
    impl Machine {
        fn new() -> Self {
            let mut a=[0;256];
            let mut b=[0;256];
            for i in 0..16 {
                a[i*4..i*4+4].copy_from_slice(&0x00e2_1409u32.to_le_bytes());
                b[i*4..i*4+4].copy_from_slice(&0x000c_1edau32.to_le_bytes());
            }
            Self{a,b,steal_a_leaf:false,supervisor_pte:false}
        }
        fn pte(&self,at:u64)->Option<u64>{
            let entry=match at {
                0x1000=>0x2000|7,
                0x2000=>0x3000|7,
                0x3010=>0x4000|7,
                0x4000=>if self.steal_a_leaf {0xa000|7} else {0x5000|7},
                // A present PMM-owned PT frame can legitimately contain
                // an empty second leaf. Return the zero PTE, rather than
                // pretending the physical page-table read itself failed.
                0x4008=>0,
                0x6000=>0x7000|7,
                0x7000=>0x8000|7,
                0x8010=>0x9000|7,
                0x9000=>0xa000|7,
                0x9008=>0,
                _=>return None
            };
            if self.supervisor_pte && at==0x3010 {Some(entry & !4)}
            else {Some(entry)}
        }
        fn byte(&self,at:u64)->Option<u8>{
            if (0x5000..0x6000).contains(&at) {
                Some(*self.a.get((at-0x5000) as usize).unwrap_or(&0))
            } else if (0xa000..0xb000).contains(&at) {
                Some(*self.b.get((at-0xa000) as usize).unwrap_or(&0))
            } else {None}
        }
    }

    fn setup() -> (
        ProcessTable<2,5>,SurfaceLedger<2>,UserSurface,UserSurface,
    ) {
        let mut registry=ProcessTable::<2,5>::new();
        let a_pid=registry.reserve(0x1000,[
            0x1000,0x2000,0x3000,0x4000,0x5000,
        ]).unwrap();
        let b_pid=registry.reserve(0x6000,[
            0x6000,0x7000,0x8000,0x9000,0xa000,
        ]).unwrap();
        let mut ledger=SurfaceLedger::<2>::new();
        let a_id=surface_process_bridge::open_registered(
            &registry,&mut ledger,a_pid).unwrap();
        let b_id=surface_process_bridge::open_registered(
            &registry,&mut ledger,b_pid).unwrap();
        let a=UserSurface {
            identity:a_id,rect:Rect::checked(1,1,4,4).unwrap(),
            stride:4,user_va:0x400000,
        };
        let b=UserSurface {
            identity:b_id,rect:Rect::checked(3,2,4,4).unwrap(),
            stride:4,user_va:0x400000,
        };
        (registry,ledger,a,b)
    }

    fn compose_with(
        registry:&ProcessTable<2,5>, ledger:&SurfaceLedger<2>,
        a:UserSurface,b:UserSurface,machine:&Machine,
    ) -> Result<([u32;64],CompositionReport),Error> {
        let mut output=[0x00ab_cdef;64];
        let bg=[0x0022_3344;64];
        let view=Rect::checked(0,0,8,8).unwrap();
        let report=compose_user_snapshots(registry,ledger,&mut output,
            &bg,view,8,view,a,b,b.identity,
            |ptr|machine.pte(ptr),|ptr|machine.byte(ptr))?;
        Ok((output,report))
    }

    #[test]
    fn two_distinct_registered_user_virtual_buffers_compose_without_alias() {
        let (registry,ledger,a,b)=setup();
        let (out,report)=compose_with(&registry,&ledger,a,b,&Machine::new()).unwrap();
        // 4x4 + 4x4 with 2 columns x 3 rows overlap: 6 pixels.
        assert_eq!(report,CompositionReport{
            first:10,second:16,background:38
        });
        for y in 0..8u32 {
            for x in 0..8u32 {
                let want=if (3..7).contains(&x)&&(2..6).contains(&y) {
                    0x000c_1eda
                } else if (1..5).contains(&x)&&(1..5).contains(&y) {
                    0x00e2_1409
                } else {0x0022_3344};
                assert_eq!(out[(y*8+x) as usize],want);
            }
        }
    }

    #[test]
    fn corrupt_leaf_crossing_into_foreign_process_frame_fails_before_write() {
        let (registry,ledger,a,b)=setup();
        let mut machine=Machine::new();
        machine.steal_a_leaf=true;
        let bg=[5;64];
        let mut out=[99;64];
        let view=Rect::checked(0,0,8,8).unwrap();
        let result=compose_user_snapshots(&registry,&ledger,&mut out,&bg,
            view,8,view,a,b,b.identity,
            |ptr|machine.pte(ptr),|ptr|machine.byte(ptr));
        assert_eq!(result,Err(Error::Copy(CopyError::BadPhysical)));
        assert_eq!(out,[99;64]);
    }

    #[test]
    fn user_page_supervisor_flag_rejected_and_output_is_unchanged() {
        let (registry,ledger,a,b)=setup();
        let mut machine=Machine::new();
        machine.supervisor_pte=true;
        let bg=[5;64];
        let mut out=[99;64];
        let view=Rect::checked(0,0,8,8).unwrap();
        let result=compose_user_snapshots(&registry,&ledger,&mut out,&bg,
            view,8,view,a,b,b.identity,
            |ptr|machine.pte(ptr),|ptr|machine.byte(ptr));
        assert_eq!(result,Err(Error::Copy(CopyError::Supervisor)));
        assert_eq!(out,[99;64]);
    }

    #[test]
    fn stale_owner_and_forged_pid_generation_cannot_render() {
        let (registry,mut ledger,a,b)=setup();
        let forged=UserSurface {
            identity:Identity{process_generation:a.identity.pid+42,..a.identity},
            ..a
        };
        assert_eq!(compose_with(&registry,&ledger,forged,b,&Machine::new()),
                   Err(Error::InvalidOwnerGeneration));
        ledger.close_owner(a.identity.pid,a.identity.pid).unwrap();
        assert_eq!(compose_with(&registry,&ledger,a,b,&Machine::new()),
                   Err(Error::Ledger(LedgerError::NotLive)));
    }

    #[test]
    fn unowned_page_and_cross_page_range_refuse_atomic_destination() {
        let (registry,ledger,mut a,b)=setup();
        let machine=Machine::new();
        a.user_va=0x400ffe;
        let bg=[5;64];
        let mut out=[99;64];
        let view=Rect::checked(0,0,8,8).unwrap();
        let result=compose_user_snapshots(&registry,&ledger,&mut out,&bg,
            view,8,view,a,b,b.identity,
            |ptr|machine.pte(ptr),|ptr|machine.byte(ptr));
        assert_eq!(result,Err(Error::Copy(CopyError::NotPresent)));
        assert_eq!(out,[99;64]);
    }

    #[test]
    fn overlarge_source_and_wrong_top_rejected_without_writes() {
        let (registry,ledger,mut a,b)=setup();
        a.stride=usize::MAX;
        assert_eq!(compose_with(&registry,&ledger,a,b,&Machine::new()),
                   Err(Error::OversizedSource));
        let (_,_,a,b)=setup();
        let machine=Machine::new();
        let bg=[5;64];
        let mut out=[99;64];
        let view=Rect::checked(0,0,8,8).unwrap();
        let top=Identity{slot:999,..b.identity};
        assert_eq!(
            compose_user_snapshots(&registry,&ledger,&mut out,&bg,
               view,8,view,a,b,top,
               |ptr|machine.pte(ptr),|ptr|machine.byte(ptr)),
            Err(Error::Compose(BridgeError::Ledger(
                LedgerError::Pixel(PixelError::InvalidTop)
            )))
        );
        assert_eq!(out,[99;64]);
    }
}
