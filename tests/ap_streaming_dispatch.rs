//! Host-only adversarial streaming proof for the exact WolfOS SPSC AP FIFO
//! and the production-intended new-work placement policy. This test cannot
//! claim IPI delivery, IRQ wakeup, task migration or production scheduling.

#[path = "../kernel/src/percpu_work_queue.rs"]
mod queue;
#[path = "../kernel/src/ap_work_placement.rs"]
mod placement;

use placement::{choose_destination, PlacementError};
use queue::{CpuWorkQueue, QueueError, CAPACITY};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

const CPUS: usize = 4;
const JOBS: u64 = 384;

#[test]
fn three_real_ap_owner_threads_stream_without_loss_replay_or_overwrite() {
    let queues = Arc::new([
        CpuWorkQueue::new(0),
        CpuWorkQueue::new(1),
        CpuWorkQueue::new(2),
        CpuWorkQueue::new(3),
    ]);
    let online = [false, true, true, true];
    let started = Arc::new(AtomicBool::new(false));
    let finished_publication = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<(usize, u64, u64, u64)>();

    let workers: Vec<_> = (1..CPUS)
        .map(|cpu| {
            let queues = Arc::clone(&queues);
            let started = Arc::clone(&started);
            let finished_publication = Arc::clone(&finished_publication);
            let tx = tx.clone();
            thread::spawn(move || {
                while !started.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                loop {
                    match queues[cpu].dequeue(cpu) {
                        Ok(Some(job)) => {
                            let result = queue::digest(cpu, job.sequence, job.token);
                            tx.send((cpu, job.sequence, job.token, result))
                                .expect("coordinator must remain listening");
                        }
                        Ok(None) => {
                            if finished_publication.load(Ordering::Acquire) {
                                break;
                            }
                            thread::yield_now();
                        }
                        Err(err) => panic!("AP {cpu} rejected own FIFO dequeue: {err:?}"),
                    }
                }
            })
        })
        .collect();
    drop(tx);

    let mut seqs = [0u64; CPUS];
    let mut submitted = 0u64;
    let mut redirected = 0usize;

    // Freeze all AP consumers, completely fill their queues, then prove an
    // attempted 13th submission is rejected BEFORE enabling consumers.
    for job_id in 1..=12u64 {
        let queued = [
            0,
            queues[1].try_len().unwrap(),
            queues[2].try_len().unwrap(),
            queues[3].try_len().unwrap(),
        ];
        let choice = choose_destination(1, 0, &online, &queued, CAPACITY).unwrap();
        let cpu = choice.destination;
        seqs[cpu] += 1;
        let token = (job_id << 16) | ((cpu as u64) << 8) | 0x5a;
        queues[cpu].enqueue(cpu, seqs[cpu], token).unwrap();
        submitted += 1;
        redirected += usize::from(choice.redirected);
    }
    assert_eq!(seqs, [0, 4, 4, 4]);
    assert_eq!(redirected, 8);
    assert_eq!(
        choose_destination(1, 0, &online, &[0, 4, 4, 4], CAPACITY),
        Err(PlacementError::NoCapacity)
    );
    for cpu in 1..CPUS {
        assert_eq!(queues[cpu].try_len(), Ok(CAPACITY));
        assert_eq!(
            queues[cpu].enqueue(cpu, 5, 0x5555),
            Err(QueueError::Full)
        );
    }

    // The BSP stays the sole producer. Three AP threads independently drain
    // at their own pace while the BSP repeatedly observes capacity and
    // admits new jobs. No task is moved after initial placement.
    started.store(true, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut observed_backpressure = 1usize;
    for job_id in 13..=JOBS {
        loop {
            assert!(Instant::now() < deadline, "streaming producer deadlocked");
            let mut queued = [0usize; CPUS];
            let mut retry = false;
            for cpu in 1..CPUS {
                match queues[cpu].try_len() {
                    Ok(count) => {
                        assert!(count <= CAPACITY);
                        queued[cpu] = count;
                    }
                    Err(QueueError::Contended) => retry = true,
                    Err(error) => panic!("invalid AP {cpu} occupancy: {error:?}"),
                }
            }
            if retry {
                thread::yield_now();
                continue;
            }
            match choose_destination(1, 0, &online, &queued, CAPACITY) {
                Ok(choice) => {
                    let cpu = choice.destination;
                    seqs[cpu] += 1;
                    let token = (job_id << 16) | ((cpu as u64) << 8) | 0x5a;
                    queues[cpu].enqueue(cpu, seqs[cpu], token)
                        .expect("single producer must never overfill selected queue");
                    submitted += 1;
                    redirected += usize::from(choice.redirected);
                    break;
                }
                Err(PlacementError::NoCapacity) => {
                    observed_backpressure += 1;
                    thread::yield_now();
                }
                Err(error) => panic!("unexpected placement rejection: {error:?}"),
            }
        }
    }
    finished_publication.store(true, Ordering::Release);
    for worker in workers {
        worker.join().expect("AP worker panicked");
    }

    let mut received: [Vec<(u64, u64, u64)>; CPUS] =
        std::array::from_fn(|_| Vec::new());
    let mut ids = BTreeSet::new();
    for (cpu, sequence, token, actual_digest) in rx {
        assert!((1..CPUS).contains(&cpu));
        assert_eq!(((token >> 8) & 0xff) as usize, cpu);
        assert_eq!(token & 0xff, 0x5a);
        assert_eq!(actual_digest, queue::digest(cpu, sequence, token));
        let job_id = token >> 16;
        assert!((1..=JOBS).contains(&job_id));
        assert!(ids.insert(job_id), "job executed twice: {job_id}");
        received[cpu].push((sequence, token, actual_digest));
    }
    assert_eq!(submitted, JOBS);
    assert_eq!(ids.len(), JOBS as usize);
    assert!(redirected >= 8);
    assert!(observed_backpressure >= 1);
    assert!(received[0].is_empty());
    for cpu in 1..CPUS {
        assert_eq!(received[cpu].len(), seqs[cpu] as usize);
        for (index, (sequence, _, _)) in received[cpu].iter().enumerate() {
            assert_eq!(*sequence, index as u64 + 1, "AP {cpu} FIFO reordered");
        }
        assert!(queues[cpu].is_drained(seqs[cpu]));
        assert_eq!(queues[cpu].try_len(), Ok(0));
    }
}

#[test]
fn an_online_but_full_preferred_ap_yields_to_active_consumers_elsewhere() {
    let online = [false, true, true, false];
    assert_eq!(
        choose_destination(1, 0, &online, &[0, 4, 1, 0], CAPACITY)
            .unwrap().destination,
        2
    );
    assert_eq!(
        choose_destination(1, 0, &online, &[0, 4, 4, 0], CAPACITY),
        Err(PlacementError::NoCapacity)
    );
}
