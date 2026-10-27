//! Serialized, bounded address-space activation/retirement bookkeeping.
//!
//! Reserve a CPU BEFORE it can load the private CR3. A reservation remains
//! outstanding even if retirement races the hardware load and confirmation
//! is refused. Only that CPU's completed switch back to the registered,
//! trusted supervisor root can drain its exact generation-tagged ticket.
//!
//! This gate owns no frames and performs no allocation, CR3 write, TLB
//! invalidation, IPI, scheduling or reclamation. Retired is metadata, NOT
//! permission to free memory. Callers must additionally retire saved contexts,
//! prevent untracked activation and authenticate observations on each CPU.
//! All methods require the same exclusive coordinator lock; pending hardware
//! work must be cancelled before acknowledging a reservation. The initial
//! contract requires PCID disabled and no private global translations: a
//! distinct CR3 alone cannot prove quiescence with retained PCID/global TLBs.

const PAGE: u64 = 4096;
const PHYSICAL_END: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Staged,
    Live,
    Retiring,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidCpuCount,
    InvalidIdentity,
    InvalidRoot,
    InvalidCpu,
    WrongPhase,
    CpuBusy,
    StaleTicket,
    InvalidTransition,
    WrongCr3,
    EpochExhausted,
    OutstandingCpus,
    OutstandingContexts,
}

/// Opaque identity of one CPU reservation, not a hardware quiescence proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    generation: u64,
    root: u64,
    cpu: usize,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cpu {
    Idle,
    Reserved(u64),
    Active(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub reserved: u64,
    pub active: u64,
    pub last_epoch: u64,
}

/// One ledger per globally unique process/address-space generation. Never
/// duplicate a ledger for the same identity or bypass its reservation gate.
pub struct RetirementGate<const CPUS: usize> {
    generation: u64,
    root: u64,
    supervisor_root: u64,
    phase: Phase,
    last_epoch: u64,
    /// Conservative history of every CPU that was ever granted a private
    /// CR3 reservation, including loads racing retirement confirmation.
    ever_reserved: u64,
    cpus: [Cpu; CPUS],
}

fn valid_root(root: u64) -> bool {
    root != 0 && root < PHYSICAL_END && root & (PAGE - 1) == 0
}

impl<const CPUS: usize> RetirementGate<CPUS> {
    /// The supervisor root must be independently authenticated, not taken
    /// from a user's claimed CR3. Generation is minted by the process owner.
    pub fn new(generation: u64, root: u64, supervisor_root: u64) -> Result<Self, Error> {
        if CPUS == 0 || CPUS > 64 {
            return Err(Error::InvalidCpuCount);
        }
        if generation == 0 {
            return Err(Error::InvalidIdentity);
        }
        if !valid_root(root) || !valid_root(supervisor_root) || root == supervisor_root {
            return Err(Error::InvalidRoot);
        }
        Ok(Self {
            generation,
            root,
            supervisor_root,
            phase: Phase::Staged,
            last_epoch: 0,
            ever_reserved: 0,
            cpus: [Cpu::Idle; CPUS],
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut result = Snapshot {
            phase: self.phase,
            reserved: 0,
            active: 0,
            last_epoch: self.last_epoch,
        };
        for (index, cpu) in self.cpus.iter().enumerate() {
            match cpu {
                Cpu::Reserved(_) => result.reserved |= 1u64 << index,
                Cpu::Active(_) => result.active |= 1u64 << index,
                Cpu::Idle => {}
            }
        }
        result
    }

    /// Conservative per-generation target set for a future TLB shootdown.
    /// Unlike `snapshot().active | snapshot().reserved`, this never forgets
    /// CPUs after a normal deactivation, failed confirmation or retirement.
    /// Every private CR3 load MUST have an earlier reservation through this
    /// ledger under the shared coordinator lock; bypasses break coverage.
    /// The result is metadata, not authenticated hardware invalidation or
    /// permission to reclaim frames. A caller must account for CPU hotplug,
    /// cached global/PCID translations and a complete IPI/flush protocol.
    pub fn potential_tlb_users(&self) -> u64 {
        self.ever_reserved
    }

    /// Globally minted address-space generation for cross-ledger matching.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Compare the registry-minted process generation and private CR3 root
    /// against this specific retirement gate. Does not authorize hardware.
    pub fn matches_process_identity(&self, pid: u64, root: u64) -> bool {
        self.generation == pid && self.root == root
    }

    /// Publish only after disconnected image/ownership admission succeeds.
    pub fn publish(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Staged {
            return Err(Error::WrongPhase);
        }
        self.phase = Phase::Live;
        Ok(())
    }

    /// Register intent before releasing the coordinator lock to load CR3.
    /// Retiring closes this gate even when earlier reservations are pending.
    pub fn reserve_cpu(&mut self, cpu: usize) -> Result<Ticket, Error> {
        if self.phase != Phase::Live {
            return Err(Error::WrongPhase);
        }
        if cpu >= CPUS {
            return Err(Error::InvalidCpu);
        }
        if self.cpus[cpu] != Cpu::Idle {
            return Err(Error::CpuBusy);
        }
        let epoch = self
            .last_epoch
            .checked_add(1)
            .ok_or(Error::EpochExhausted)?;
        self.cpus[cpu] = Cpu::Reserved(epoch);
        self.last_epoch = epoch;
        self.ever_reserved |= 1u64 << cpu;
        Ok(Ticket {
            generation: self.generation,
            root: self.root,
            cpu,
            epoch,
        })
    }

    fn check_ticket(&self, ticket: Ticket) -> Result<(), Error> {
        if ticket.generation != self.generation || ticket.root != self.root || ticket.cpu >= CPUS {
            return Err(Error::StaleTicket);
        }
        match self.cpus[ticket.cpu] {
            Cpu::Reserved(epoch) | Cpu::Active(epoch) if epoch == ticket.epoch => Ok(()),
            _ => Err(Error::StaleTicket),
        }
    }

    /// Confirm on the owning CPU after its actual private CR3 load. If
    /// retirement won the race, keep the reservation pinned, switch away,
    /// then acknowledge; failure here never drains an outstanding CPU.
    pub fn confirm_active(&mut self, ticket: Ticket, actual_cr3: u64) -> Result<(), Error> {
        if self.phase != Phase::Live {
            return Err(Error::WrongPhase);
        }
        self.check_ticket(ticket)?;
        if self.cpus[ticket.cpu] != Cpu::Reserved(ticket.epoch) {
            return Err(Error::InvalidTransition);
        }
        if actual_cr3 != self.root {
            return Err(Error::WrongCr3);
        }
        self.cpus[ticket.cpu] = Cpu::Active(ticket.epoch);
        Ok(())
    }

    /// Close activation permanently; staged cancellation uses the same path.
    pub fn begin_retirement(&mut self) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Staged | Phase::Live) {
            return Err(Error::WrongPhase);
        }
        self.phase = Phase::Retiring;
        Ok(())
    }

    /// Called by the ticket's CPU after switching away, completing required
    /// invalidation and cancelling any pending CR3 load. A coordinator cannot
    /// substitute its own CR3 observation for another CPU's acknowledgement.
    /// In Live this drains a normal deactivation; its next entry gets a new
    /// epoch, so a delayed acknowledgement cannot clear the new reservation.
    pub fn acknowledge_quiescent(&mut self, ticket: Ticket, actual_cr3: u64) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Live | Phase::Retiring) {
            return Err(Error::WrongPhase);
        }
        self.check_ticket(ticket)?;
        if actual_cr3 != self.supervisor_root {
            return Err(Error::WrongCr3);
        }
        self.cpus[ticket.cpu] = Cpu::Idle;
        Ok(())
    }

    /// Complete bookkeeping only after every reservation/activation drains.
    /// This does not release a PMM lease or certify external saved contexts.
    pub fn finish_retirement(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Retiring {
            return Err(Error::WrongPhase);
        }
        if self.cpus.iter().any(|cpu| *cpu != Cpu::Idle) {
            return Err(Error::OutstandingCpus);
        }
        self.phase = Phase::Retired;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live<const N: usize>() -> RetirementGate<N> {
        let mut gate = RetirementGate::new(7, 0x1000, 0x9000).unwrap();
        gate.publish().unwrap();
        gate
    }

    #[test]
    fn validates_identity_capacity_and_both_roots() {
        assert!(matches!(
            RetirementGate::<0>::new(1, 0x1000, 0x9000),
            Err(Error::InvalidCpuCount)
        ));
        assert!(matches!(
            RetirementGate::<65>::new(1, 0x1000, 0x9000),
            Err(Error::InvalidCpuCount)
        ));
        assert!(matches!(
            RetirementGate::<1>::new(0, 0x1000, 0x9000),
            Err(Error::InvalidIdentity)
        ));
        for bad in [0, 1, 0x1001, PHYSICAL_END, u64::MAX] {
            assert!(matches!(
                RetirementGate::<1>::new(1, bad, 0x9000),
                Err(Error::InvalidRoot)
            ));
            assert!(matches!(
                RetirementGate::<1>::new(1, 0x1000, bad),
                Err(Error::InvalidRoot)
            ));
        }
        assert!(matches!(
            RetirementGate::<1>::new(1, 0x1000, 0x1000),
            Err(Error::InvalidRoot)
        ));
    }

    #[test]
    fn staged_cancellation_and_terminal_state_never_admit_cpus() {
        let mut gate = RetirementGate::<1>::new(7, 0x1000, 0x9000).unwrap();
        assert_eq!(gate.reserve_cpu(0), Err(Error::WrongPhase));
        assert_eq!(gate.finish_retirement(), Err(Error::WrongPhase));
        gate.begin_retirement().unwrap();
        gate.finish_retirement().unwrap();
        let before = gate.snapshot();
        assert_eq!(gate.publish(), Err(Error::WrongPhase));
        assert_eq!(gate.reserve_cpu(0), Err(Error::WrongPhase));
        assert_eq!(gate.begin_retirement(), Err(Error::WrongPhase));
        assert_eq!(gate.finish_retirement(), Err(Error::WrongPhase));
        assert_eq!(gate.snapshot(), before);
    }

    #[test]
    fn retirement_between_reservation_and_cr3_load_cannot_drop_cpu() {
        let mut gate = live::<2>();
        let ticket = gate.reserve_cpu(0).unwrap();
        gate.begin_retirement().unwrap();
        let before = gate.snapshot();
        assert_eq!(gate.confirm_active(ticket, 0x1000), Err(Error::WrongPhase));
        assert_eq!(gate.reserve_cpu(1), Err(Error::WrongPhase));
        assert_eq!(
            gate.acknowledge_quiescent(ticket, 0x1000),
            Err(Error::WrongCr3)
        );
        assert_eq!(gate.finish_retirement(), Err(Error::OutstandingCpus));
        assert_eq!(gate.snapshot(), before);
        gate.acknowledge_quiescent(ticket, 0x9000).unwrap();
        gate.finish_retirement().unwrap();
    }

    #[test]
    fn all_four_cpu_acknowledgement_orders_require_the_last_cpu() {
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let order = [a, b, c, d];
                        if order
                            .iter()
                            .enumerate()
                            .any(|(i, cpu)| order[..i].contains(cpu))
                        {
                            continue;
                        }
                        let mut gate = live::<4>();
                        let tickets = core::array::from_fn::<_, 4, _>(|cpu| {
                            let ticket = gate.reserve_cpu(cpu).unwrap();
                            gate.confirm_active(ticket, 0x1000).unwrap();
                            ticket
                        });
                        gate.begin_retirement().unwrap();
                        assert_eq!(gate.snapshot().active, 15);
                        for (index, cpu) in order.into_iter().enumerate() {
                            assert_eq!(gate.finish_retirement(), Err(Error::OutstandingCpus));
                            gate.acknowledge_quiescent(tickets[cpu], 0x9000).unwrap();
                            assert_eq!(gate.snapshot().active.count_ones(), (3 - index) as u32);
                        }
                        gate.finish_retirement().unwrap();
                        assert_eq!(gate.snapshot().phase, Phase::Retired);
                    }
                }
            }
        }
    }

    #[test]
    fn mixed_active_and_not_yet_loaded_reservations_both_block_completion() {
        let mut gate = live::<4>();
        let running = gate.reserve_cpu(0).unwrap();
        let pending = gate.reserve_cpu(3).unwrap();
        gate.confirm_active(running, 0x1000).unwrap();
        gate.begin_retirement().unwrap();
        assert_eq!(gate.snapshot().active, 1);
        assert_eq!(gate.snapshot().reserved, 8);
        gate.acknowledge_quiescent(running, 0x9000).unwrap();
        assert_eq!(gate.finish_retirement(), Err(Error::OutstandingCpus));
        assert_eq!(gate.confirm_active(pending, 0x1000), Err(Error::WrongPhase));
        gate.acknowledge_quiescent(pending, 0x9000).unwrap();
        gate.finish_retirement().unwrap();
        let retired = gate.snapshot();
        assert_eq!(
            gate.acknowledge_quiescent(pending, 0x9000),
            Err(Error::WrongPhase)
        );
        assert_eq!(gate.confirm_active(running, 0x1000), Err(Error::WrongPhase));
        assert_eq!(gate.snapshot(), retired);
    }

    #[test]
    fn delayed_duplicate_and_foreign_identity_tickets_cannot_clear_new_entry() {
        let mut gate = live::<2>();
        let old = gate.reserve_cpu(0).unwrap();
        gate.confirm_active(old, 0x1000).unwrap();
        gate.acknowledge_quiescent(old, 0x9000).unwrap();
        let current = gate.reserve_cpu(0).unwrap();
        let before = gate.snapshot();
        assert_eq!(
            gate.acknowledge_quiescent(old, 0x9000),
            Err(Error::StaleTicket)
        );
        assert_eq!(gate.confirm_active(old, 0x1000), Err(Error::StaleTicket));
        for foreign in [
            Ticket {
                generation: 8,
                ..current
            },
            Ticket {
                root: 0x2000,
                ..current
            },
            Ticket { cpu: 2, ..current },
            Ticket {
                epoch: 0,
                ..current
            },
        ] {
            assert_eq!(
                gate.acknowledge_quiescent(foreign, 0x9000),
                Err(Error::StaleTicket)
            );
        }
        assert_eq!(gate.snapshot(), before);
        gate.confirm_active(current, 0x1000).unwrap();
        gate.acknowledge_quiescent(current, 0x9000).unwrap();
        assert_eq!(
            gate.acknowledge_quiescent(current, 0x9000),
            Err(Error::StaleTicket)
        );
    }

    #[test]
    fn rejected_roots_and_transitions_preserve_masks_and_epochs() {
        let mut gate = live::<1>();
        assert_eq!(gate.reserve_cpu(1), Err(Error::InvalidCpu));
        assert_eq!(gate.snapshot().last_epoch, 0);
        let ticket = gate.reserve_cpu(0).unwrap();
        let reserved = gate.snapshot();
        assert_eq!(gate.reserve_cpu(0), Err(Error::CpuBusy));
        assert_eq!(gate.confirm_active(ticket, 0x9000), Err(Error::WrongCr3));
        assert_eq!(gate.snapshot(), reserved);
        gate.confirm_active(ticket, 0x1000).unwrap();
        let active = gate.snapshot();
        assert_eq!(
            gate.confirm_active(ticket, 0x1000),
            Err(Error::InvalidTransition)
        );
        for wrong in [0, 0x1000, 0x2000, 0x9001, PHYSICAL_END] {
            assert_eq!(
                gate.acknowledge_quiescent(ticket, wrong),
                Err(Error::WrongCr3)
            );
        }
        assert_eq!(gate.snapshot(), active);
    }

    #[test]
    fn historical_tlb_targets_survive_deactivation_and_retirement() {
        let mut gate = live::<4>();
        assert_eq!(gate.potential_tlb_users(), 0);

        // Even an unconfirmed reservation is a potential private CR3 load:
        // hardware may race a later retirement before software confirms it.
        let first = gate.reserve_cpu(3).unwrap();
        assert_eq!(gate.potential_tlb_users(), 0b1000);
        gate.acknowledge_quiescent(first, 0x9000).unwrap();
        assert_eq!(gate.snapshot().active | gate.snapshot().reserved, 0);
        assert_eq!(gate.potential_tlb_users(), 0b1000);

        let second = gate.reserve_cpu(1).unwrap();
        gate.confirm_active(second, 0x1000).unwrap();
        let third = gate.reserve_cpu(3).unwrap();
        gate.confirm_active(third, 0x1000).unwrap();
        assert_eq!(gate.potential_tlb_users(), 0b1010);
        gate.acknowledge_quiescent(second, 0x9000).unwrap();
        gate.acknowledge_quiescent(third, 0x9000).unwrap();
        assert_eq!(gate.snapshot().reserved | gate.snapshot().active, 0);
        assert_eq!(gate.potential_tlb_users(), 0b1010);

        let racing = gate.reserve_cpu(0).unwrap();
        gate.begin_retirement().unwrap();
        assert_eq!(gate.confirm_active(racing, 0x1000), Err(Error::WrongPhase));
        assert_eq!(gate.potential_tlb_users(), 0b1011);
        assert_eq!(gate.finish_retirement(), Err(Error::OutstandingCpus));
        gate.acknowledge_quiescent(racing, 0x9000).unwrap();
        gate.finish_retirement().unwrap();
        assert_eq!(gate.snapshot().phase, Phase::Retired);
        assert_eq!(gate.snapshot().reserved | gate.snapshot().active, 0);
        assert_eq!(gate.potential_tlb_users(), 0b1011);
    }

    #[test]
    fn rejected_reservations_and_stale_acks_never_erase_cpu_history() {
        let mut gate = live::<2>();
        assert_eq!(gate.reserve_cpu(2), Err(Error::InvalidCpu));
        assert_eq!(gate.potential_tlb_users(), 0);
        let old = gate.reserve_cpu(0).unwrap();
        assert_eq!(gate.potential_tlb_users(), 1);
        assert_eq!(gate.reserve_cpu(0), Err(Error::CpuBusy));
        assert_eq!(gate.confirm_active(old, 0x9000), Err(Error::WrongCr3));
        gate.acknowledge_quiescent(old, 0x9000).unwrap();
        let next = gate.reserve_cpu(0).unwrap();
        assert_eq!(gate.acknowledge_quiescent(old, 0x9000), Err(Error::StaleTicket));
        assert_eq!(gate.potential_tlb_users(), 1);
        gate.acknowledge_quiescent(next, 0x9000).unwrap();

        gate.last_epoch = u64::MAX;
        assert_eq!(gate.reserve_cpu(1), Err(Error::EpochExhausted));
        assert_eq!(gate.potential_tlb_users(), 1);
        assert_eq!(gate.snapshot().reserved | gate.snapshot().active, 0);
    }

    #[test]
    fn highest_cpu_history_bit_is_preserved_without_shift_overflow() {
        let mut gate = live::<64>();
        let far = gate.reserve_cpu(63).unwrap();
        assert_eq!(gate.potential_tlb_users(), 1u64 << 63);
        gate.confirm_active(far, 0x1000).unwrap();
        gate.acknowledge_quiescent(far, 0x9000).unwrap();
        let near = gate.reserve_cpu(0).unwrap();
        assert_eq!(gate.potential_tlb_users(), (1u64 << 63) | 1);
        gate.acknowledge_quiescent(near, 0x9000).unwrap();
        gate.begin_retirement().unwrap();
        gate.finish_retirement().unwrap();
        assert_eq!(gate.potential_tlb_users(), (1u64 << 63) | 1);
    }

    #[test]
    fn highest_cpu_bit_and_epoch_exhaustion_fail_closed() {
        let mut gate = live::<64>();
        let ticket = gate.reserve_cpu(63).unwrap();
        assert_eq!(gate.snapshot().reserved, 1u64 << 63);
        gate.confirm_active(ticket, 0x1000).unwrap();
        assert_eq!(gate.snapshot().active, 1u64 << 63);
        gate.acknowledge_quiescent(ticket, 0x9000).unwrap();
        gate.last_epoch = u64::MAX;
        let before = gate.snapshot();
        assert_eq!(gate.reserve_cpu(0), Err(Error::EpochExhausted));
        assert_eq!(gate.snapshot(), before);
    }
}
