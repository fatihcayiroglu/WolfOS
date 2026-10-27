# ADR-0060 — Owner-bound retirement with real CPU-local CR3 invalidation

## Decision

Extend the existing feature-isolated four-vCPU CPL0 retirement QEMU test. It already reserves each CPU against one move-only `ActiveAddressSpace` PMM owner **before** loading a private cloned PML4, and each CPU must restore the supervisor CR3 before its generation-ticket departure is acknowledged.

After all four CPUs have departed and the synthetic-only saved-context wait ticket is revoked:

1. Under one existing nonallocating ledger lock, borrow the **actual** `ActiveAddressSpace` and arm a `ShootdownBarrier<4>` for its own generation. The owner API rejects live CPU reservations, outstanding saved contexts, wrong generation and any target set excluding historical CPU users.
2. Publish a release mask to the BSP and two APs. Each independently executes a **second, real local CR3 write to the registered supervisor root** after publication. With PCID disabled and no private global translations, this architecturally invalidates the local non-global TLB entries. Each CPU then acknowledges only its own identity, under the same owner/barrier lock.
3. Withhold the final AP. The BSP checks the exact remaining bit, refusal of a new barrier epoch, unchanged pending state and unchanged PMM allocation count. Timeouts are failures, never acknowledgements.
4. Release the final AP, require its real local CR3 reload and exact ack, then check the round is complete and still bound to the retiring owner. **Only now** finish metadata retirement and execute the pre-existing `unsafe` one-PML4 reclamation proof.

The strict host QEMU validator requires the older CPU departures, saved-context pin, late wake refusal, exact PMM release evidence **plus** four post-publication CR3 flush acknowledgements and withheld-last-CPU proof. Every earlier P0 host and hardware test remains mandatory.

## Why this is intentionally limited

- This proves a genuine **four-CPU CPL0** owner/retirement/barrier/local-flush composition. It is not the general Ring3 process scheduler.
- It uses CPUs already spinning in the feature-isolated boot coordinator; **no directed IPI** is sent. Cross-CPU asynchronous invalidation, offline CPUs and CPU hotplug remain unsolved.
- The private root is one cloned PML4 whose kernel children stay borrowed and resident. PCID is disabled, and there are no private global translations. Real arbitrary user mappings, borrowed page walkers, external devices and saved hardware contexts are outside this proof.
- `ShootdownBarrier` completion alone still cannot authorize memory release. The existing narrowly scoped unsafe reclaim step separately relies on authenticated CR3 restoration, no future private loads, context cancellation and borrowed-table lifetime.
- An early return or failed timeout must preserve the active PMM owner; physical frames must not be freed under an uncertain barrier.
- No physical disks, partitions or installed operating systems are touched. The new code is QEMU-feature-only and does not alter normal WolfOS boot.
