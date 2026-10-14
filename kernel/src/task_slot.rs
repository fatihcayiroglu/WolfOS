//! BSP-only fixed-slot task ownership and deferred recycling contract.
//!
//! Task termination is NOT stack deallocation: the CPU can still carry the
//! task's interrupted RSP and FXSAVE image after a hardware preemption.
//! Retirement is allowed only at a later verified quiescent point, when the
//! scheduler has returned to a disjoint BSP stack with IF=0 and no live
//! interrupts may resume the finished task.
//!
//! This model uses generation-tagged handles so an old task identity can
//! never operate on a newly allocated occupant of the same physical slot.
//! It does not allocate physical pages, provide a production task API,
//! guard kernel stacks, or solve cross-CPU (SMP) memory reclamation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Vacant,
    Allocated,
    Finished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskHandle {
    pub slot: usize,
    pub generation: u64,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    state: SlotState,
}

pub struct SlotTable<const N: usize> {
    entries: [Slot; N],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError {
    InvalidSlot,
    Occupied,
    NotAllocated,
    NotFinished,
    StaleHandle,
    GenerationOverflow,
    NotQuiescent,
    RunnableOrUnfinished,
    InsufficientObservedGrace,
}

/// Live evidence supplied by the BSP after the hardware preemption proof
/// completes. A caller cannot use this by itself to assert safety: it MUST
/// derive flags from actual CPU IF, stack RSP, scheduler state, and IRQ tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimGate {
    pub interrupts_disabled: bool,
    pub scheduler_inactive: bool,
    pub bsp_on_disjoint_stack: bool,
    pub old_task_not_current: bool,
    pub ready_mask: u64,
    pub finished_mask: u64,
    pub frozen_irq_observations: u64,
}

pub const MIN_GRACE_IRQS: u64 = 6;

impl<const N: usize> SlotTable<N> {
    pub const fn new() -> Self {
        Self {
            entries: [Slot {
                generation: 0,
                state: SlotState::Vacant,
            }; N],
        }
    }

    fn checked(&self, handle: TaskHandle) -> Result<Slot, SlotError> {
        let slot = *self.entries.get(handle.slot).ok_or(SlotError::InvalidSlot)?;
        if handle.generation == 0 || handle.generation != slot.generation {
            return Err(SlotError::StaleHandle);
        }
        Ok(slot)
    }

    pub fn state(&self, handle: TaskHandle) -> Result<SlotState, SlotError> {
        Ok(self.checked(handle)?.state)
    }

    /// Ownership state is independent of the scheduler's Ready bitmap.
    /// The caller must initialize a safe trap frame/xstate before enqueueing.
    pub fn handle(&self, slot_id: usize) -> Result<TaskHandle, SlotError> {
        let slot = self.entries.get(slot_id).ok_or(SlotError::InvalidSlot)?;
        if slot.state == SlotState::Vacant {
            return Err(SlotError::NotAllocated);
        }
        Ok(TaskHandle { slot: slot_id, generation: slot.generation })
    }

    pub fn spawn(&mut self, slot_id: usize) -> Result<TaskHandle, SlotError> {
        let slot = self.entries.get_mut(slot_id).ok_or(SlotError::InvalidSlot)?;
        if slot.state != SlotState::Vacant {
            return Err(SlotError::Occupied);
        }
        let generation = slot.generation.checked_add(1)
            .ok_or(SlotError::GenerationOverflow)?;
        // Generation is updated only when the slot has been fully detached
        // and placed into Vacant. Never wrap to reuse an ancient identity.
        // Allocated alone does NOT put a task in the runnable bitmap.
        slot.generation = generation;
        slot.state = SlotState::Allocated;
        Ok(TaskHandle { slot: slot_id, generation })
    }

    pub fn finish(&mut self, handle: TaskHandle) -> Result<(), SlotError> {
        if self.checked(handle)?.state != SlotState::Allocated {
            return Err(SlotError::NotAllocated);
        }
        self.entries[handle.slot].state = SlotState::Finished;
        Ok(())
    }

    pub fn retire(
        &mut self,
        handle: TaskHandle,
        gate: ReclaimGate,
    ) -> Result<(), SlotError> {
        if self.checked(handle)?.state != SlotState::Finished {
            return Err(SlotError::NotFinished);
        }
        if !gate.interrupts_disabled || !gate.scheduler_inactive
            || !gate.bsp_on_disjoint_stack || !gate.old_task_not_current
        {
            return Err(SlotError::NotQuiescent);
        }
        let bit = 1u64.checked_shl(
            u32::try_from(handle.slot).map_err(|_| SlotError::InvalidSlot)?
        ).ok_or(SlotError::InvalidSlot)?;
        if gate.ready_mask & bit != 0 || gate.finished_mask & bit == 0 {
            return Err(SlotError::RunnableOrUnfinished);
        }
        if gate.frozen_irq_observations < MIN_GRACE_IRQS {
            return Err(SlotError::InsufficientObservedGrace);
        }
        self.entries[handle.slot].state = SlotState::Vacant;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_gate() -> ReclaimGate {
        ReclaimGate {
            interrupts_disabled: true,
            scheduler_inactive: true,
            bsp_on_disjoint_stack: true,
            old_task_not_current: true,
            ready_mask: 0b011,
            finished_mask: 0b100,
            frozen_irq_observations: 8,
        }
    }

    #[test]
    fn only_finished_tasks_with_confirmed_quiescence_can_be_recycled() {
        let mut slots = SlotTable::<3>::new();
        let old = slots.spawn(2).unwrap();
        assert_eq!(slots.spawn(2), Err(SlotError::Occupied));
        assert_eq!(slots.retire(old, safe_gate()), Err(SlotError::NotFinished));
        slots.finish(old).unwrap();
        assert_eq!(slots.finish(old), Err(SlotError::NotAllocated));
        assert_eq!(slots.state(old), Ok(SlotState::Finished));
        slots.retire(old, safe_gate()).unwrap();
        assert_eq!(slots.state(old), Ok(SlotState::Vacant));
        let renewed = slots.spawn(2).unwrap();
        assert_eq!(renewed.slot, 2);
        assert_eq!(renewed.generation, old.generation + 1);
        assert_eq!(slots.state(renewed), Ok(SlotState::Allocated));
        assert_eq!(slots.state(old), Err(SlotError::StaleHandle));
        assert_eq!(slots.finish(old), Err(SlotError::StaleHandle));
        assert_eq!(slots.retire(old, safe_gate()), Err(SlotError::StaleHandle));
    }

    #[test]
    fn deny_quiescence_while_irq_or_scheduler_or_old_stack_is_active() {
        let mut slots = SlotTable::<3>::new();
        let handle = slots.spawn(2).unwrap();
        slots.finish(handle).unwrap();
        let safe = safe_gate();
        for change in 0..4 {
            let mut gate = safe;
            match change {
                0 => gate.interrupts_disabled = false,
                1 => gate.scheduler_inactive = false,
                2 => gate.bsp_on_disjoint_stack = false,
                3 => gate.old_task_not_current = false,
                _ => unreachable!(),
            }
            assert_eq!(slots.retire(handle, gate), Err(SlotError::NotQuiescent));
            assert_eq!(slots.state(handle), Ok(SlotState::Finished));
        }
        slots.retire(handle, safe).unwrap();
    }

    #[test]
    fn deny_early_free_or_running_mask_alias_and_keep_finished_state() {
        let mut slots = SlotTable::<3>::new();
        let handle = slots.spawn(2).unwrap();
        slots.finish(handle).unwrap();
        let mut early = safe_gate();
        early.frozen_irq_observations = MIN_GRACE_IRQS - 1;
        assert_eq!(
            slots.retire(handle, early),
            Err(SlotError::InsufficientObservedGrace)
        );
        let mut ready = safe_gate();
        ready.ready_mask = 0b111;
        assert_eq!(
            slots.retire(handle, ready),
            Err(SlotError::RunnableOrUnfinished)
        );
        let mut absent = safe_gate();
        absent.finished_mask = 0;
        assert_eq!(
            slots.retire(handle, absent),
            Err(SlotError::RunnableOrUnfinished)
        );
        assert_eq!(slots.state(handle), Ok(SlotState::Finished));
    }

    #[test]
    fn reject_invalid_handles_and_generation_exhaustion() {
        let mut slots = SlotTable::<3>::new();
        assert_eq!(slots.spawn(3), Err(SlotError::InvalidSlot));
        let task = slots.spawn(2).unwrap();
        assert_eq!(
            slots.state(TaskHandle { slot: 2, generation: 0 }),
            Err(SlotError::StaleHandle)
        );
        assert_eq!(
            slots.state(TaskHandle { slot: 3, generation: task.generation }),
            Err(SlotError::InvalidSlot)
        );
        slots.entries[1].generation = u64::MAX;
        assert_eq!(slots.spawn(1), Err(SlotError::GenerationOverflow));
        assert_eq!(slots.entries[1].state, SlotState::Vacant);
    }

    #[test]
    fn cannot_accidentally_retire_another_slot_with_valid_generation() {
        let mut slots = SlotTable::<3>::new();
        let a = slots.spawn(0).unwrap();
        let b = slots.spawn(2).unwrap();
        assert_eq!(slots.retire(a, safe_gate()), Err(SlotError::NotFinished));
        slots.finish(b).unwrap();
        assert_eq!(slots.retire(b, safe_gate()), Ok(()));
        assert_eq!(slots.state(a), Ok(SlotState::Allocated));
    }
}
