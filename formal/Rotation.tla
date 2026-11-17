------------------------------ MODULE Rotation ------------------------------
\* Formal TLA+ safety and liveness specification for AnchorManifest committee
\* rotation (Rev 1 -> Rev 2) over 3 phases (freeze -> import -> commit) with
\* 72h timelock, authority veto, expiring pre-proposal freeze, single-proposal
\* lock (voted_proposal[rev]), QC-based union import, standby successors, and
\* guarantor nomination binding (Phase V3).
\*
\* Reflects V1 LUECKE-01 & LUECKE-04c:
\*   - Protocol slot IDs are canonical per set (not blinded per server), so union
\*     import preserves all locks with a Quorum Certificate.
\*   - Pre-proposal freeze expires after MaxPreFreezeAge ticks to avoid freeze DoS.

EXTENDS Naturals, FiniteSets

CONSTANTS
    OldCommittee,     \* e.g. {"s1", "s2", "s3"}
    StandbyPool,      \* e.g. {"s4", "s5"} (s4 for Creator, s5 for Guarantor)
    CreatorExtra,     \* e.g. "s6" (creator-controlled server outside declared G1 successor)
    QOld,             \* e.g. 2 for 2/3
    TimelockTicks,    \* e.g. 3 (abstracts 72h timelock)
    MaxPreFreezeAge   \* e.g. 2 (abstracts 30 min pre-proposal freeze TTL)

AllServers == OldCommittee \cup StandbyPool \cup {CreatorExtra}
Authorities == {"Creator", "G1"}
Locks == {"L1", "L2"} \* Lock L1 has a QC on OldCommittee; L2 may be unconfirmed

\* Initial slot ownership in Rev 1:
\* Slot 1 ("s1") nominated by Creator (standby "s4")
\* Slot 2 ("s2") nominated by Guarantor G1 (standby "s5")
\* Slot 3 ("s3") nominated by Creator (no standby needed for small model)
InitG1Server == "s2"
DeclaredG1Successor == "s5"

VARIABLES
    honestOldStore,   \* [OldCommittee -> SUBSET Locks]
    crashed,          \* Subset of OldCommittee (at most |OldCommittee| - QOld)
    freezeState,      \* [OldCommittee -> {"none", "pre", "permanent"}]
    freezeAge,        \* [OldCommittee -> 0..MaxPreFreezeAge]
    creatorInactive,  \* BOOLEAN (true after 30 days creator inactivity)
    votedProposal,    \* Record or "NULL":
                      \*   [proposer: {"Creator", "G1", "Holder"},
                      \*    target: SUBSET AllServers,
                      \*    g1SlotServer: AllServers,
                      \*    coSignedG1: BOOLEAN,
                      \*    usesDeclaredSuccessors: BOOLEAN,
                      \*    retainMatch: BOOLEAN]
    timelockAge,      \* 0..TimelockTicks
    vetoed,           \* BOOLEAN
    snapshots,        \* [OldCommittee -> SUBSET Locks \cup {"NONE"}]
    importAcks,       \* SUBSET AllServers (target servers that verified and acked import)
    importedUnion,    \* [AllServers -> SUBSET Locks]
    epochCommitted,   \* BOOLEAN
    committedTargets, \* SUBSET (SUBSET AllServers)
    committedG1Server \* AllServers \cup {"NONE"}

vars == <<
    honestOldStore, crashed, freezeState, freezeAge, creatorInactive,
    votedProposal, timelockAge, vetoed, snapshots, importAcks,
    importedUnion, epochCommitted, committedTargets, committedG1Server
>>

\* Assume Lock L1 already attained a Quorum Certificate in Rev 1, i.e., it resides
\* on at least QOld servers in OldCommittee (here {"s1", "s2"}).
Init ==
    /\ honestOldStore = [s \in OldCommittee |->
          IF s \in {"s1", "s2"} THEN {"L1"}
          ELSE IF s = "s3" THEN {"L2"}
          ELSE {}]
    /\ crashed = {}
    /\ freezeState = [s \in OldCommittee |-> "none"]
    /\ freezeAge = [s \in OldCommittee |-> 0]
    /\ creatorInactive \in BOOLEAN
    /\ votedProposal = "NULL"
    /\ timelockAge = 0
    /\ vetoed = FALSE
    /\ snapshots = [s \in OldCommittee |-> "NONE"]
    /\ importAcks = {}
    /\ importedUnion = [s \in AllServers |-> {}]
    /\ epochCommitted = FALSE
    /\ committedTargets = {}
    /\ committedG1Server = "NONE"

TypeOK ==
    /\ honestOldStore \in [OldCommittee -> SUBSET Locks]
    /\ crashed \subseteq OldCommittee
    /\ freezeState \in [OldCommittee -> {"none", "pre", "permanent"}]
    /\ freezeAge \in [OldCommittee -> 0..MaxPreFreezeAge]
    /\ creatorInactive \in BOOLEAN
    /\ timelockAge \in 0..TimelockTicks
    /\ vetoed \in BOOLEAN
    /\ importAcks \subseteq AllServers
    /\ importedUnion \in [AllServers -> SUBSET Locks]
    /\ epochCommitted \in BOOLEAN
    /\ committedTargets \subseteq (SUBSET AllServers)
    /\ committedG1Server \in AllServers \cup {"NONE"}

\* Server crash bounded by Liveness threshold (at least QOld old servers remain alive)
CrashOldServer(s) ==
    /\ s \in OldCommittee \ crashed
    /\ Cardinality(OldCommittee \ (crashed \cup {s})) >= QOld
    /\ crashed' = crashed \cup {s}
    /\ UNCHANGED <<honestOldStore, freezeState, freezeAge, creatorInactive, votedProposal,
                   timelockAge, vetoed, snapshots, importAcks, importedUnion,
                   epochCommitted, committedTargets, committedG1Server>>

\* Pre-proposal freeze (phase 1a): allowed before proposal; expires after MaxPreFreezeAge
PreProposalFreeze(s) ==
    /\ s \in OldCommittee \ crashed
    /\ ~epochCommitted
    /\ votedProposal = "NULL"
    /\ freezeState[s] = "none"
    /\ freezeState' = [freezeState EXCEPT ![s] = "pre"]
    /\ freezeAge' = [freezeAge EXCEPT ![s] = 0]
    /\ UNCHANGED <<honestOldStore, crashed, creatorInactive, votedProposal,
                   timelockAge, vetoed, snapshots, importAcks, importedUnion,
                   epochCommitted, committedTargets, committedG1Server>>

PreProposalFreezeExpires(s) ==
    /\ s \in OldCommittee
    /\ votedProposal = "NULL"
    /\ freezeState[s] = "pre"
    /\ freezeAge[s] = MaxPreFreezeAge
    /\ freezeState' = [freezeState EXCEPT ![s] = "none"]
    /\ freezeAge' = [freezeAge EXCEPT ![s] = 0]
    /\ UNCHANGED <<honestOldStore, crashed, creatorInactive, votedProposal,
                   timelockAge, vetoed, snapshots, importAcks, importedUnion,
                   epochCommitted, committedTargets, committedG1Server>>

\* Nomination binding predicate checked by servers and clients (Concept Section 5.4):
\* G1's seat can only remain InitG1Server, move to DeclaredG1Successor, or be
\* co-signed by G1 itself. Even a malicious Creator CANNOT put CreatorExtra in G1's seat.
ValidNominationBinding(g1Srv, coSignedG1) ==
    \/ g1Srv = InitG1Server
    \/ g1Srv = DeclaredG1Successor
    \/ coSignedG1 = TRUE

\* Submit a rotation proposal (only 1 per revision via votedProposal = "NULL" guard).
SubmitProposal(proposer, g1Srv, coSignedG1, retainMatch) ==
    /\ ~epochCommitted
    /\ votedProposal = "NULL"
    /\ ~vetoed
    /\ ( \/ proposer = "Creator"
         \/ (proposer = "G1" /\ creatorInactive)
         \/ (proposer = "Holder" /\ g1Srv \in {InitG1Server, DeclaredG1Successor}) )
    /\ retainMatch = TRUE
    \* Servers themselves verify Nomination Binding before accepting into votedProposal:
    /\ ValidNominationBinding(g1Srv, coSignedG1)
    /\ LET tgt == (OldCommittee \ {InitG1Server}) \cup {g1Srv}
       IN  votedProposal' = [
             proposer |-> proposer,
             target |-> tgt,
             g1SlotServer |-> g1Srv,
             coSignedG1 |-> coSignedG1,
             retainMatch |-> retainMatch
           ]
    \* Any pre-existing freeze turns permanent while proposal is pending:
    /\ freezeState' = [s \in OldCommittee |->
          IF freezeState[s] = "pre" THEN "permanent" ELSE freezeState[s]]
    /\ timelockAge' = 0
    /\ UNCHANGED <<honestOldStore, crashed, freezeAge, creatorInactive, vetoed,
                   snapshots, importAcks, importedUnion, epochCommitted,
                   committedTargets, committedG1Server>>

\* Another authority vetoes during the 72h timelock window (Concept Section 5.4/5.5)
VetoProposal(vetoer) ==
    /\ ~epochCommitted
    /\ votedProposal /= "NULL"
    /\ timelockAge < TimelockTicks
    /\ vetoer \in Authorities
    /\ vetoer /= votedProposal.proposer
    /\ vetoed' = TRUE
    /\ votedProposal' = "NULL"
    /\ freezeState' = [s \in OldCommittee |-> "none"]
    /\ snapshots' = [s \in OldCommittee |-> "NONE"]
    /\ importAcks' = {}
    /\ UNCHANGED <<honestOldStore, crashed, freezeAge, creatorInactive,
                   timelockAge, importedUnion, epochCommitted,
                   committedTargets, committedG1Server>>

\* Time advances both pre-proposal freeze ages and proposal timelock
TickTime ==
    /\ ~epochCommitted
    /\ \/ /\ votedProposal = "NULL"
          /\ \E s \in OldCommittee : freezeState[s] = "pre" /\ freezeAge[s] < MaxPreFreezeAge
          /\ freezeAge' = [s \in OldCommittee |->
                IF freezeState[s] = "pre" /\ freezeAge[s] < MaxPreFreezeAge
                THEN freezeAge[s] + 1 ELSE freezeAge[s]]
          /\ UNCHANGED timelockAge
       \/ /\ votedProposal /= "NULL"
          /\ timelockAge < TimelockTicks
          /\ timelockAge' = timelockAge + 1
          /\ UNCHANGED freezeAge
    /\ UNCHANGED <<honestOldStore, crashed, freezeState, creatorInactive, votedProposal,
                   vetoed, snapshots, importAcks, importedUnion,
                   epochCommitted, committedTargets, committedG1Server>>

\* Phase 1 (?lock_freeze): Old servers permanently freeze after proposal and emit snapshot
PermanentFreezeAndSnapshot(s) ==
    /\ ~epochCommitted
    /\ votedProposal /= "NULL"
    /\ s \in OldCommittee \ crashed
    /\ freezeState' = [freezeState EXCEPT ![s] = "permanent"]
    /\ snapshots' = [snapshots EXCEPT ![s] = honestOldStore[s]]
    /\ UNCHANGED <<honestOldStore, crashed, freezeAge, creatorInactive, votedProposal,
                   timelockAge, vetoed, importAcks, importedUnion,
                   epochCommitted, committedTargets, committedG1Server>>

\* Phase 2 (?lock_import): Target server validates timelock, nomination binding,
\* QOld snapshots, and computes union over all surviving snapshots.
TargetImport(t) ==
    /\ ~epochCommitted
    /\ votedProposal /= "NULL"
    /\ timelockAge >= TimelockTicks
    /\ t \in votedProposal.target
    /\ t \notin importAcks
    /\ votedProposal.retainMatch = TRUE
    /\ ValidNominationBinding(votedProposal.g1SlotServer, votedProposal.coSignedG1)
    /\ LET readyOld == {s \in OldCommittee : snapshots[s] /= "NONE"}
       IN  /\ Cardinality(readyOld) >= QOld
           /\ LET unionLocks == UNION {snapshots[s] : s \in readyOld}
              IN  /\ importedUnion' = [importedUnion EXCEPT ![t] = unionLocks]
                  /\ importAcks' = importAcks \cup {t}
    /\ UNCHANGED <<honestOldStore, crashed, freezeState, freezeAge, creatorInactive,
                   votedProposal, timelockAge, vetoed, snapshots, epochCommitted,
                   committedTargets, committedG1Server>>

\* Phase 3 (?lock_commit): Once all targets acked, QOld old servers commit MigrationCert
CommitMigration ==
    /\ ~epochCommitted
    /\ votedProposal /= "NULL"
    /\ votedProposal.target \subseteq importAcks
    /\ LET frozenOld == {s \in OldCommittee \ crashed : freezeState[s] = "permanent" /\ snapshots[s] /= "NONE"}
       IN  Cardinality(frozenOld) >= QOld
    /\ epochCommitted' = TRUE
    /\ committedTargets' = committedTargets \cup {votedProposal.target}
    /\ committedG1Server' = votedProposal.g1SlotServer
    /\ UNCHANGED <<honestOldStore, crashed, freezeState, freezeAge, creatorInactive,
                   votedProposal, timelockAge, vetoed, snapshots, importAcks, importedUnion>>

Next ==
    \/ \E s \in OldCommittee : CrashOldServer(s)
    \/ \E s \in OldCommittee : PreProposalFreeze(s)
    \/ \E s \in OldCommittee : PreProposalFreezeExpires(s)
    \/ \E p \in {"Creator", "G1", "Holder"}, g1s \in AllServers, co \in BOOLEAN :
          SubmitProposal(p, g1s, co, TRUE)
    \/ \E v \in Authorities : VetoProposal(v)
    \/ TickTime
    \/ \E s \in OldCommittee : PermanentFreezeAndSnapshot(s)
    \/ \E t \in AllServers : TargetImport(t)
    \/ CommitMigration

Spec == Init /\ [][Next]_vars

\* --- SAFETY INVARIANTS ---

\* 1. Rotation never loses any lock that achieved a Quorum Certificate ("L1"):
NoCommittedQCLockLost ==
    epochCommitted =>
      \A t \in UNION committedTargets : "L1" \in importedUnion[t]

\* 2. Never two committed next revisions r+1:
UniqueCommittedNextRevision ==
    Cardinality(committedTargets) <= 1

\* 3. A Guarantor slot is NEVER replaced by an unendorsed Creator-controlled server:
GuarantorNominationBindingPreserved ==
    epochCommitted =>
      (committedG1Server /= CreatorExtra \/ (votedProposal /= "NULL" /\ votedProposal.coSignedG1))

\* 4. No permanent freeze without an active proposal:
NoPermanentFreezeWithoutProposal ==
    \A s \in OldCommittee :
      (freezeState[s] = "permanent") => (votedProposal /= "NULL")

\* --- LIVENESS ---

\* Under weak fairness, once a non-vetoed valid proposal is submitted and at least
\* QOld old servers remain alive, rotation eventually commits.
LiveSpec == Spec /\ WF_vars(TickTime)
                 /\ \A s \in OldCommittee : WF_vars(PermanentFreezeAndSnapshot(s))
                 /\ \A t \in AllServers : WF_vars(TargetImport(t))
                 /\ WF_vars(CommitMigration)

RotationEventuallyCompletes ==
    (votedProposal /= "NULL" /\ ~vetoed) ~> (epochCommitted \/ vetoed)

=============================================================================
