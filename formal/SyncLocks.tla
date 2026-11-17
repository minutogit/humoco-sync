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

TxValues == {"TxP", "TxA", "TxB"}
Hops == 1..MaxHop

ASSUME ByzServers \subseteq Servers
ASSUME TrustedM1 \subseteq Servers
ASSUME TrustedM2 \subseteq Servers
ASSUME Q \in 1..Cardinality(Servers)
ASSUME 2 * Q - Cardinality(Servers) >= 1
ASSUME MaxHop \in 1..3

\* Honest servers hold at most one Write-Once entry per slot (first writer wins).
\* Byzantine servers can record distinct receipts issued to different merchants.
\* forkHop models the hop depth where two conflicting branches ("TxA" vs "TxB")
\* diverge after sharing an honest Leap-Lock prefix ("TxP") on 1..(forkHop - 1).
VARIABLES
    forkHop,          \* Depth in Hops where M1 ("TxA") and M2 ("TxB") diverge
    honestStore,      \* [Servers -> [Hops -> TxValues \cup {"NONE"}]]
    crashed,          \* Subset of Servers currently unreachable / offline (<= 1)
    receiptsM1,       \* Subset of [server: Servers, hop: Hops, tx: TxValues]
    receiptsM2,       \* Subset of [server: Servers, hop: Hops, tx: TxValues]
    conflictsSeenM1,  \* Subset of [server: Servers, hop: Hops, tx: TxValues]
    conflictsSeenM2,  \* Subset of [server: Servers, hop: Hops, tx: TxValues]
    greenM1,          \* Subset of Hops marked Green by Merchant 1
    greenM2,          \* Subset of Hops marked Green by Merchant 2
    intentDoneM1,     \* Subset of Hops for which M1 finished completion to all live honest servers
    intentDoneM2      \* Subset of Hops for which M2 finished completion to all live honest servers

vars == <<
    forkHop, honestStore, crashed,
    receiptsM1, receiptsM2,
    conflictsSeenM1, conflictsSeenM2,
    greenM1, greenM2,
    intentDoneM1, intentDoneM2
>>

ExpectedTxM1(h) == IF h < forkHop THEN "TxP" ELSE "TxA"
ExpectedTxM2(h) == IF h < forkHop THEN "TxP" ELSE "TxB"

TypeOK ==
    /\ forkHop \in Hops
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
    /\ forkHop \in Hops
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
\* 1..(h-1) on an honest server to hold the caller's exact ancestor chain.
LockRequestM1(s, h) ==
    LET tx == ExpectedTxM1(h)
    IN  /\ s \notin crashed
        /\ ~(\E r \in receiptsM1 : r.server = s /\ r.hop = h)
        /\ ~(\E c \in conflictsSeenM1 : c.server = s /\ c.hop = h)
        /\ \A prev \in 1..(h - 1) :
              /\ (\E r \in receiptsM1 : r.server = s /\ r.hop = prev)
              /\ (s \in ByzServers \/ honestStore[s][prev] = ExpectedTxM1(prev))
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
        /\ UNCHANGED <<forkHop, crashed, receiptsM2, conflictsSeenM2, greenM1, greenM2, intentDoneM1, intentDoneM2>>

LockRequestM2(s, h) ==
    LET tx == ExpectedTxM2(h)
    IN  /\ s \notin crashed
        /\ ~(\E r \in receiptsM2 : r.server = s /\ r.hop = h)
        /\ ~(\E c \in conflictsSeenM2 : c.server = s /\ c.hop = h)
        /\ \A prev \in 1..(h - 1) :
              /\ (\E r \in receiptsM2 : r.server = s /\ r.hop = prev)
              /\ (s \in ByzServers \/ honestStore[s][prev] = ExpectedTxM2(prev))
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
        /\ UNCHANGED <<forkHop, crashed, receiptsM1, conflictsSeenM1, greenM1, greenM2, intentDoneM1, intentDoneM2>>

\* Evaluate checkout Green-Rule (Concept Section 5.3):
\*   #FirstWrite_receipts >= Q /\ #Trusted_FirstWrite_receipts >= N - Q + 1 /\ 0 conflicts
N == Cardinality(Servers)
MinTrusted == N - Q + 1

CheckGreenM1(h) ==
    LET rSet == {r.server : r \in {x \in receiptsM1 : x.hop = h /\ x.tx = "TxA"}}
        cSet == {c \in conflictsSeenM1 : c.hop <= h}
    IN  /\ h \notin greenM1
        /\ cSet = {}
        /\ Cardinality(rSet) >= Q
        /\ Cardinality(rSet \cap TrustedM1) >= MinTrusted
        /\ greenM1' = greenM1 \cup {h}
        /\ UNCHANGED <<forkHop, honestStore, crashed, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM2, intentDoneM1, intentDoneM2>>

CheckGreenM2(h) ==
    LET rSet == {r.server : r \in {x \in receiptsM2 : x.hop = h /\ x.tx = "TxB"}}
        cSet == {c \in conflictsSeenM2 : c.hop <= h}
    IN  /\ h \notin greenM2
        /\ cSet = {}
        /\ Cardinality(rSet) >= Q
        /\ Cardinality(rSet \cap TrustedM2) >= MinTrusted
        /\ greenM2' = greenM2 \cup {h}
        /\ UNCHANGED <<forkHop, honestStore, crashed, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, intentDoneM1, intentDoneM2>>

\* Crash and recover transitions (bounded crash model <= N - Q concurrent crashes;
\* servers never lose honestStore when recovering).
CrashServer(s) ==
    /\ s \notin crashed
    /\ Cardinality(crashed) < N - Q
    /\ crashed' = crashed \cup {s}
    /\ UNCHANGED <<forkHop, honestStore, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, greenM2, intentDoneM1, intentDoneM2>>

RecoverServer(s) ==
    /\ s \in crashed
    /\ crashed' = crashed \ {s}
    /\ UNCHANGED <<forkHop, honestStore, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, greenM2, intentDoneM1, intentDoneM2>>

\* Mandatory completion via DurableIntent: merchant only marks intentDone(h)
\* once every non-Byzantine server has returned FirstWrite for h or ConflictSeen at <= h.
CompleteIntentM1(h) ==
    /\ h \in greenM1
    /\ h \notin intentDoneM1
    /\ \A s \in (Servers \ ByzServers) :
          (\E r \in receiptsM1 : r.server = s /\ r.hop = h /\ r.tx = "TxA")
          \/ (\E c \in conflictsSeenM1 : c.server = s /\ c.hop <= h)
    /\ intentDoneM1' = intentDoneM1 \cup {h}
    /\ UNCHANGED <<forkHop, honestStore, crashed, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, greenM2, intentDoneM2>>

CompleteIntentM2(h) ==
    /\ h \in greenM2
    /\ h \notin intentDoneM2
    /\ \A s \in (Servers \ ByzServers) :
          (\E r \in receiptsM2 : r.server = s /\ r.hop = h /\ r.tx = "TxB")
          \/ (\E c \in conflictsSeenM2 : c.server = s /\ c.hop <= h)
    /\ intentDoneM2' = intentDoneM2 \cup {h}
    /\ UNCHANGED <<forkHop, honestStore, crashed, receiptsM1, receiptsM2, conflictsSeenM1, conflictsSeenM2, greenM1, greenM2, intentDoneM1>>

Next ==
    \/ \E s \in Servers, h \in Hops : LockRequestM1(s, h)
    \/ \E s \in Servers, h \in Hops : LockRequestM2(s, h)
    \/ \E h \in Hops : CheckGreenM1(h)
    \/ \E h \in Hops : CheckGreenM2(h)
    \/ \E s \in Servers : CrashServer(s)
    \/ \E s \in Servers : RecoverServer(s)
    \/ \E h \in Hops : CompleteIntentM1(h)
    \/ \E h \in Hops : CompleteIntentM2(h)

Spec == Init /\ [][Next]_vars

\* --- SAFETY INVARIANTS ---

\* Under 2Q - N >= |ByzServers| + 1 (here N=4, Q=3, |ByzServers|=1 -> 2 >= 2),
\* two Green quorums CANNOT form on the same slot even if both merchants trust "s4".
NoDoubleGreenOnSameSlot ==
    \A h \in Hops : ~(h \in greenM1 /\ h \in greenM2)

\* An honest server never signs conflicting FirstWrite receipts on the same slot.
SameServerDoubleSignImpliesByzantine ==
    \A r1 \in receiptsM1, r2 \in receiptsM2 :
      (r1.hop = r2.hop /\ r1.server = r2.server /\ r1.tx /= r2.tx) =>
        r1.server \in ByzServers

\* If M1 went Green and finished DurableIntent to all honest servers, any competing
\* FirstWrite seen by M2 on h triggers a ConflictSeen on an honest server or identifies ByzServers.
CompletionDetectsEquivocationOrConflict ==
    \A h \in Hops, r2 \in receiptsM2 :
      (h \in intentDoneM1 /\ r2.hop = h /\ r2.tx = "TxB") =>
        \/ (\E c1 \in conflictsSeenM1 : c1.hop <= h /\ c1.server = r2.server)
        \/ (r2.server \in ByzServers)

=============================================================================
