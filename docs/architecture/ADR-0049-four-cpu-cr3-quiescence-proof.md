# ADR-0049: require every real CPU's CR3 departure before retirement

## Problem

ADR-0048's ledger has deterministic multi-CPU tests and real BSP CR3 evidence,
but a coordinator's own supervisor CR3 cannot establish remote quiescence.
Hardware evidence must show that another CPU still executing the private
root blocks completion, including the last outstanding AP.

## Isolated proof

`make smp-address-space-retirement-smoke` enables a separate four-vCPU CPL0
test. It preserves existing Ring3 and AP timer/IPI scenarios. Before AP
bootstrap, BSP allocates one PML4 and copies its complete current kernel
root, borrowing all child tables and unchanged mappings. A single exclusive
ledger lock serializes reservation, activation and acknowledgement.

After completing their ordinary stack/context boot checks, each authenticated
AP index reserves a ticket, really loads the private root, reads CR3 locally,
confirms its ticket and publishes its active state. IF must be off and PCID
disabled on every participant. APs then wait without touching PMM or serial.

BSP waits for all three APs, reserves its own ticket, loads the private CR3,
and starts retirement. It restores its original CR3 and acknowledges only
its own ticket. Retirement must still be refused while all APs remain active.
BSP then releases two APs, each of which verifies that its active CR3 cannot
acknowledge departure, restores the original root, reads it on that CPU and
acknowledges its own exact ticket. The final AP deliberately remains active;
completion must again fail and PMM ownership must remain unchanged.

Only after releasing the last AP and acquiring all acknowledgements does BSP
verify every CPU's actual before/after CR3 observations, complete the ledger,
and free exactly the one owned PML4. The shared child tables remain resident.
After acknowledging, an AP cannot load the private CR3 again and returns to
its permanent halt path. Every timeout/error after AP release retains the
root instead of risking release while a CPU might still use it. AP failure
paths restore their original CR3 before returning; missing acknowledgements
cannot be replaced by BSP observations.

The runner requires the exact complete proof line, normal boot and debug-exit
33. Wrong CPU counts, a missing last-AP rejection, partial/duplicate/reordered
markers, faults and failed exits are rejected by host evidence tests. The
existing BSP runner retains its separate default proof and 1/4-vCPU coverage.

## Scope limits

This demonstrates real remote CR3 quiescence for four fixed kernel workers
sharing immutable kernel mappings, using cooperative barriers. It does not
implement a production Ring3 lifecycle, dynamic CPU hotplug, PCID/INVPCID,
private global translations, interrupt-driven TLB shootdown or process-frame
ownership transfer. No user mappings are changed while CPUs run. Each local
CR3 reload uses the checked PCID-disabled contract; borrowed global kernel
translations keep identical mappings and their child tables are never freed.

The generic ledger still owns no PMM frames and its Retired state alone does
not authorize reclamation. Integrating staged-to-active frame ownership and
retiring saved user/kernel contexts remains separate work. Both new hardware
gates and the complete historical P0 suite are mandatory before merging.
