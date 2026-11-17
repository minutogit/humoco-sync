------------------------------ MODULE SyncLocks ------------------------------
\* Formal TLA+ safety specification for humoco-sync write-once lock quorums,
\* leap-lock multi-hop prefixes (<= 3 hops), PoS Green-Rule checkout, and
\* mandatory asynchronous DurableIntent completion (Phase V3).
\*
\* Design assumptions reflected from V1 (LUECKE-01):
\*   - Canonical per-set slot IDs across all committee servers (file paths are
\*     blinded per server, protocol slot IDs match for QC & rotation).
\*   - At most 1 Byzantine equivocating server in small TLC config (<= 4 servers).

EXTENDS Naturals, FiniteSets

CONSTANTS
    Servers,          \* Committee server IDs, e.g. {"s1", "s2", "s3", "s4"}
    ByzServers,       \* Equivocating / censoring subset of Servers (<= 1)
    TrustedM1,        \* Servers trusted by Merchant 1
    TrustedM2,        \* Servers trusted by Merchant 2
    Q,                \* Quorum threshold, e.g. 3 for 3/4 (2Q - N >= 1)
    MaxHop            \* Max hop depth modeled, e.g. 3

TxValues == {"TxA", "TxB"}
Hops == 1..MaxHop

ASSUME ByzServers \subseteq Servers
ASSUME TrustedM1 \subseteq Servers
ASSUME TrustedM2 \subseteq Servers
ASSUME Q \in 1..Cardinality(Servers)
ASSUME 2 * Q - Cardinality(Servers) >= 1
ASSUME MaxHop \in 1..3

\* Honest servers hold at most one Write-Once entry per slot (first writer wins).
\* Byzantine servers can record distinct receipts issued to different merchants.
VARIABLES
    honestStore,      \* [Servers -> [Hops -> TxValues \cup {"NONE"}]]
    crashed,          \* Subset of Servers currently unreachable / offline
    receiptsM1,       \* Subset of [server: Servers, hop: Hops, tx: TxValues]
    receiptsM2,       \* Subset of [server: Servers, hop: Hops, tx: TxValues]
    conflictsSeenM1,  \* Subset of [server: Servers, hop: Hops, tx: TxValues]
    conflictsSeenM2,  \* Subset of [server: Servers, hop: Hops, tx: TxValues]
    greenM1,          \* Subset of Hops marked Green by Merchant 1
    greenM2,          \* Subset of Hops marked Green by Merchant 2
    intentDoneM1,     \* Subset of Hops for which M1 finished completion to all live servers
    intentDoneM2      \* Subset of Hops for which M2 finished completion to all live servers

vars == <<
    honestStore, crashed,
    receiptsM1, receiptsM2,
    conflictsSeenM1, conflictsSeenM2,
    greenM1, greenM2,
    intentDoneM1, intentDoneM2
>>

TypeOK ==
    /\ honestStore \in [Servers -> [Hops -> TxValues \cup {"NONE"}]]
    /\ crashed \subseteq Servers
    /\ receiptsM1 \subseteq [server: Servers, hop: Hops, tx: TxValues]
    /\ receiptsM2 \subseteq [server: Servers, hop: Hops, tx: TxValues]
    /\ conflictsSeenM1 \subseteq [server: Servers, hop: Hops, tx: TxValues]
    /\ conflictsSeenM2 \subseteq [server: Servers, hop: Hops, tx: TxValues]
    /\ greenM1 \subseteq Hops
    /\ greenM2 \subseteq Hops
    /\ intentDoneM1 \subseteq Hops
    /\ intentDoneM2 \subseteq Hops

Init ==
    /\ honestStore = [s \in Servers |-> [h \in Hops |-> "NONE"]]
    /\ crashed = {}
    /\ receiptsM1 = {}
    /\ receiptsM2 = {}
    /\ conflictsSeenM1 = {}
    /\ conflictsSeenM2 = {}
    /\ greenM1 = {}
    /\ greenM2 = {}
    /\ intentDoneM1 = {}
    /\ intentDoneM2 = {}

\* Causal prerequisite for Leap-Lock: locking hop h requires all ancestor hops
\* 1..(h-1) to be either already locked with the same or ancestor chain.
\* In a double-spend race on hop h, M1 submits TxA on hop h and M2 submits TxB on hop h.
LockRequestM1(s, h, tx) ==
    /\ s \notin crashed
    /\ tx = "TxA"
    /\ \A prev \in 1..(h - 1) :
          (\E r \in receiptsM1 : r.server = s /\ r.hop = prev)
          \/ (honestStore[s][prev] /= "NONE")
    /\ IF s \notin ByzServers
       THEN
         IF honestStore[s][h] = "NONE" \/ honestStore[s][h] = tx
         THEN /\ honestStore' = [honestStore EXCEPT ![s][h] = tx]
              /\ receiptsM1' = receiptsM1 \cup {[server |-> s, hop |-> h, tx |-> tx]}
              /\ UNCHANGED conflictsSeenM1
         ELSE /\ conflictsSeenM1' = conflictsSeenM1 \cup {[server |-> s, hop |-> h, tx |-> honestStore[s][h]]}
              /\ UNCHANGED <<honestStore, receiptsM1>>
       ELSE
         \* Byzantine server may arbitrarily issue FirstWrite for tx OR report conflict
         \/ /\ receiptsM1' = receiptsM1 \cup {[server |-> s, hop |-> h, tx |-> tx]}
            /\ UNCHANGED <<honestStore, conflictsSeenM1>>
         \/ /\ conflictsSeenM1' = conflictsSeenM1 \cup {[server |-> s, hop |-> h, tx |-> "TxB"]}
            /\ UNCHANGED <<honestStore, receiptsM1>>
    /\ UNCHANGED <<crashed, receiptsM2, conflictsSeenM2, greenM1, greenM2, intentDoneM1, intentDoneM2>>

LockRequestM2(s, h, tx) ==
    /\ s \notin crashed
    /\ tx = "TxB"
    /\ \A prev \in 1..(h - 1) :
          (\E r \in receiptsM2 : r.server = s /\ r.hop = prev)
          \/ (honestStore[s][prev] /= "NONE")
    /\ IF s \notin ByzServers
       THEN
         IF honestStore[s][h] = "NONE" \/ honestStore[s][h] = tx
         THEN /\ honestStore' = [honestStore EXCEPT ![s][h] = tx]
              /\ receiptsM2' = receiptsM2 \cup {[server |-> s, hop |-> h, tx |-> tx]}
              /\ UNCHANGED conflictsSeenM2
         ELSE /\ conflictsSeenM2' = conflictsSeenM2 \cup {[server |-> s, hop |-> h, tx |-> honestStore[s][h]]}
              /\ UNCHANGED <<honestStore, receiptsM2>>
       ELSE
         \/ /\ receiptsM2' = receiptsM2 \cup {[server |-> s, hop |-> h, tx |-> tx]}
            /\ UNCHANGED <<honestStore, conflictsSeenM2>>
         \/ /\ conflictsSeenM2' = conflictsSeenM2 \cup {[server |-> s, hop |-> h, tx |-> "TxA"]}
            /\ UNCHANGED <<honestStore, receiptsM2>>
    /\ UNCHANGED <<crashed, receiptsM1, conflictsSeenM1, greenM1, greenM2, intentDoneM1, intentDoneM2>>

\* Evaluate checkout Green-Rule (Concept Section 5.3):
\*   #FirstWrite_receipts >= Q /\ #Trusted_FirstWrite_receipts >= N - Q + 1 /\ 0 conflicts
N == Cardinality(Servers)
MinTrusted == N - Q + 1

CheckGreenM1(h) ==
    LET rSet == {r.server : r \in {x \in receiptsM1 : x.hop = h /\ x.tx = "TxA"}}
        cSet == {c \in conflictsSeenM1 : c.hop = h}
    IN  /\ cSet = {}
        /\ Cardinality(rSet) >= Q
        /\ Cardinality(rSet \cap TrustedM1) >= MinTrusted
        /\ greenM1' = greenM1 \cup {h}
        /\ UNCHANGED <<honestStore, crashed, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM2, intentDoneM1, intentDoneM2>>

CheckGreenM2(h) ==
    LET rSet == {r.server : r \in {x \in receiptsM2 : x.hop = h /\ x.tx = "TxB"}}
        cSet == {c \in conflictsSeenM2 : c.hop = h}
    IN  /\ cSet = {}
        /\ Cardinality(rSet) >= Q
        /\ Cardinality(rSet \cap TrustedM2) >= MinTrusted
        /\ greenM2' = greenM2 \cup {h}
        /\ UNCHANGED <<honestStore, crashed, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, intentDoneM1, intentDoneM2>>

\* Crash and recover transitions (servers never lose honestStore when recovering)
CrashServer(s) ==
    /\ s \notin crashed
    /\ crashed' = crashed \cup {s}
    /\ UNCHANGED <<honestStore, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, greenM2, intentDoneM1, intentDoneM2>>

RecoverServer(s) ==
    /\ s \in crashed
    /\ crashed' = crashed \ {s}
    /\ UNCHANGED <<honestStore, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, greenM2, intentDoneM1, intentDoneM2>>

\* Mandatory completion via DurableIntent: merchant only marks intentDone(h)
\* once every non-Byzantine server has returned either FirstWrite or ConflictSeen.
CompleteIntentM1(h) ==
    /\ h \in greenM1
    /\ \A s \in (Servers \ ByzServers) :
          (\E r \in receiptsM1 : r.server = s /\ r.hop = h)
          \/ (\E c \in conflictsSeenM1 : c.server = s /\ c.hop = h)
    /\ intentDoneM1' = intentDoneM1 \cup {h}
    /\ UNCHANGED <<honestStore, crashed, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, greenM2, intentDoneM2>>

CompleteIntentM2(h) ==
    /\ h \in greenM2
    /\ \A s \in (Servers \ ByzServers) :
          (\E r \in receiptsM2 : r.server = s /\ r.hop = h)
          \/ (\E c \in conflictsSeenM2 : c.server = s /\ c.hop = h)
    /\ intentDoneM2' = intentDoneM2 \cup {h}
    /\ UNCHANGED <<honestStore, crashed, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, greenM2, intentDoneM1>>

Next ==
    \/ \E s \in Servers, h \in Hops : LockRequestM1(s, h, "TxA")
    \/ \E s \in Servers, h \in Hops : LockRequestM2(s, h, "TxB")
    \/ \E h \in Hops : CheckGreenM1(h)
    \/ \E h \in Hops : CheckGreenM2(h)
    \/ \E s \in Servers : CrashServer(s)
    \/ \E s \in Servers : RecoverServer(s)
    \/ \E h \in Hops : CompleteIntentM1(h)
    \/ \E h \in Hops : CompleteIntentM2(h)

Spec == Init /\ [][Next]_vars

\* --- SAFETY INVARIANTS ---

\* Under the Green-Rule trust assumption:
\*   Either 2Q - N >= |ByzServers| + 1 (safety by quorum intersection alone, e.g. 3/4 with f=1),
\*   OR merchants' trusted sets contain at most 2Q - N - 1 Byzantine servers.
\* With |ByzServers| <= 1 and Q = 3, N = 4: 2Q - N = 2 > 1, so even if BOTH merchants
\* trusted the Byzantine server, two Green quorums CANNOT form on the same slot!
NoDoubleGreenOnSameSlot ==
    \A h \in Hops : ~(h \in greenM1 /\ h \in greenM2)

\* If M1 went Green and completed its DurableIntent to all honest servers, and
\* M2 also received a FirstWrite receipt on the same slot from some server,
\* either M1 observed a conflict, M2 observed a conflict, or an honest server saw both,
\* or a Byzantine server issued conflicting FirstWrites (EquivocationProof).
CompletionDetectsEquivocationOrConflict ==
    \A h \in Hops :
      (h \in intentDoneM1 /\ (\E r2 \in receiptsM2 : r2.hop = h)) =>
        (\E c1 \in conflictsSeenM1 : c1.hop = h)
        \/ (\E r1 \in receiptsM1, r2 \in receiptsM2 :
              r1.hop = h /\ r2.hop = h /\ r1.server = r2.server /\ r1.tx /= r2.tx)

=============================================================================
