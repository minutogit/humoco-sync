# Formal TLA+ Models for `humoco-sync` Lock Quorums & Rotation (Phase V3)

This directory contains the TLA+ specifications verifying the safety and liveness invariants defined in [`docs/plans/SYNC_LOCKS_UMSETZUNGSPLAN.md`](../../docs/plans/SYNC_LOCKS_UMSETZUNGSPLAN.md) (Phase V3) and [`docs/concepts/sync_double_spend_schutz_plan.md`](../../docs/concepts/sync_double_spend_schutz_plan.md):

- [`SyncLocks.tla`](SyncLocks.tla) / [`SyncLocks.cfg`](SyncLocks.cfg): Write-once slot locks, leap-lock multi-hop prefixes (`<= 3` hops via `forkHop`), PoS Green-Rule quorum intersection (`#receipts >= Q` and `#trusted >= N - Q + 1`) under Byzantine equivocation, and mandatory `DurableIntent` completion (`TypeOK`, `NoDoubleGreenOnSameSlot`, `SameServerDoubleSignImpliesByzantine`, `CompletionDetectsEquivocationOrConflict`).
- [`Rotation.tla`](Rotation.tla) / [`Rotation.cfg`](Rotation.cfg): 3-phase committee rotation (`?lock_freeze` -> `?lock_import` -> `?lock_commit`), 72h timelock and authority veto, expiring pre-proposal freezes, single-proposal locking (`voted_proposal[rev]`), QC-based union import, standby `successors`, and guarantor nomination binding (`NoCommittedQCLockLost`, `UniqueCommittedNextRevision`, `GuarantorNominationBindingPreserved`, `NoPermanentFreezeWithoutProposal`, `RotationEventuallyCompletes`, `PreFreezeEventuallyExpires`).

## Running TLC

Requires Java (OpenJDK 11+) and [`tla2tools.jar`](https://github.com/tlaplus/tlaplus/releases):

```bash
curl -fL -o /tmp/tla2tools.jar https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar

rm -rf /tmp/tlc-synclocks /tmp/tlc-rotation
java -XX:+UseParallelGC -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock -metadir /tmp/tlc-synclocks -config SyncLocks.cfg SyncLocks.tla
java -XX:+UseParallelGC -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock -metadir /tmp/tlc-rotation -config Rotation.cfg Rotation.tla
```

*(Note: `-deadlock` is passed for `SyncLocks.tla` and `Rotation.tla` because terminal states where both checkouts finished or rotation committed have no further enabled transitions by design.)*
