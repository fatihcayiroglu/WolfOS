//! BSP-only *new-work* placement among bounded AP-owned FIFO queues.
//!
//! This policy selects a destination BEFORE publishing a new job. It never
//! dequeues another CPU's work, steals a live stack, changes owner after
//! enqueue, or sends an IPI. Caller remains the single producer of all AP
//! queues and must snapshot occupancy from each queue at a controlled
//! enqueue boundary (no concurrent competing producers).
//!
//! A preferred AP receives jobs until full; overflow goes to the
//! least-loaded ONLINE secondary CPU, with stable lowest-index tie break.
//! The BSP and offline CPUs can never be selected. Full means refusal,
//! never overwriting already published work.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    InvalidPreferred,
    NoCapacity,
    InvalidSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub destination: usize,
    pub redirected: bool,
}

/// Snapshot fields are indexed by the Limine CPU directory, not xAPIC IDs.
/// 'bsp' is an arbitrary index and must never be assigned new AP-owned work.
/// This pure policy does not change any of its inputs.
pub fn choose_destination<const N: usize>(
    preferred: usize,
    bsp: usize,
    online: &[bool; N],
    queued: &[usize; N],
    capacity: usize,
) -> Result<Decision, PlacementError> {
    if preferred >= N || preferred == bsp || bsp >= N {
        return Err(PlacementError::InvalidPreferred);
    }
    if capacity == 0 || queued.iter().any(|count| *count > capacity) {
        return Err(PlacementError::InvalidSnapshot);
    }
    if online[preferred] && queued[preferred] < capacity {
        return Ok(Decision {
            destination: preferred,
            redirected: false,
        });
    }
    let best = (0..N)
        .filter(|&cpu| cpu != bsp && online[cpu] && queued[cpu] < capacity)
        .min_by_key(|&cpu| (queued[cpu], cpu));
    best.map(|destination| Decision {
        destination,
        redirected: destination != preferred,
    }).ok_or(PlacementError::NoCapacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_requested_cpu_until_full_then_redirects_least_loaded() {
        let online = [true; 4];
        let mut counts = [0usize; 4];
        let mut redirects = 0;
        let mut distribution = [0usize; 4];
        for _ in 0..12 {
            let choice = choose_destination(1, 0, &online, &counts, 4).unwrap();
            assert_ne!(choice.destination, 0);
            redirects += usize::from(choice.redirected);
            counts[choice.destination] += 1;
            distribution[choice.destination] += 1;
        }
        assert_eq!(counts, [0, 4, 4, 4]);
        assert_eq!(distribution, [0, 4, 4, 4]);
        assert_eq!(redirects, 8);
        assert_eq!(
            choose_destination(1, 0, &online, &counts, 4),
            Err(PlacementError::NoCapacity),
        );
    }

    #[test]
    fn refuses_bsp_offline_and_invalid_occupancy() {
        let online = [true, true, false, true];
        let counts = [0, 4, 0, 2];
        assert_eq!(
            choose_destination(1, 0, &online, &counts, 4),
            Ok(Decision { destination: 3, redirected: true }),
        );
        assert_eq!(
            choose_destination(2, 0, &online, &counts, 4),
            Ok(Decision { destination: 3, redirected: true }),
        );
        assert_eq!(
            choose_destination(0, 0, &online, &counts, 4),
            Err(PlacementError::InvalidPreferred),
        );
        assert_eq!(
            choose_destination(4, 0, &online, &counts, 4),
            Err(PlacementError::InvalidPreferred),
        );
        assert_eq!(
            choose_destination(1, 4, &online, &counts, 4),
            Err(PlacementError::InvalidPreferred),
        );
        assert_eq!(
            choose_destination(1, 0, &online, &[0, 5, 0, 0], 4),
            Err(PlacementError::InvalidSnapshot),
        );
        assert_eq!(
            choose_destination(1, 0, &online, &counts, 0),
            Err(PlacementError::InvalidSnapshot),
        );
    }

    #[test]
    fn least_load_then_stable_cpu_index_tiebreak() {
        let online = [true; 5];
        let counts = [0, 4, 2, 1, 1];
        assert_eq!(
            choose_destination(1, 0, &online, &counts, 4).unwrap().destination,
            3,
        );
        assert_eq!(
            choose_destination(1, 0, &online, &[0, 4, 2, 2, 2], 4)
                .unwrap().destination,
            2,
        );
        assert_eq!(
            choose_destination(1, 0, &online, &[0, 4, 4, 4, 4], 4),
            Err(PlacementError::NoCapacity),
        );
    }

    #[test]
    fn nonzero_bsp_index_never_selected() {
        let online = [true; 4];
        let counts = [2, 4, 0, 1];
        let choice = choose_destination(1, 2, &online, &counts, 4).unwrap();
        assert_eq!(choice.destination, 3);
        assert!(choice.redirected);
    }
}
