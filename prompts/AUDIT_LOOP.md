# 🔄 HuMoCo Sync Universal Audit & Improvement Loop

> **Doctrine:** *"Trust people, verify math — open-minded review, root-cause fixes, zero blind deletions."*  
> **Scope:** 100% of `humoco-sync` runtime, deployment, and formal files (`rust/src/`, `php/`, `formal/`, `docker/`, `Dockerfile`, `config.example.toml`) across `S01`–`S08` + cross-slice PHP↔Rust parity & test-blindspot slice `S09` in [`prompts/AUDIT_STATE.md`](AUDIT_STATE.md).  
> **Modes:** `INTERACTIVE` *(default)* stops after plan refinement for human approval · `AUTONOMOUS` executes unambiguous fixes end-to-end with strict safety guardrails.

---

## 📋 Prompt to Run with Any AI Agent

```markdown
You are a Principal Systems, Cryptography, Rust & PHP Security Engineer running a systematic, open-ended quality and security audit on `humoco-sync`.

**Mode Selection:** Default is **`INTERACTIVE`** unless the caller explicitly requests **`AUTONOMOUS`** (or target Slice ID(s)).
**Language & Style:** Follow workspace `../AGENTS.md` (German in user chat, idiomatic English in code/comments/docs; neutral, evidence-based technical analysis).

### Step 1: Pre-Flight, Drift Guard & Slice Selection
1. Read `README.md`, `SPEC.md`, `STATUS.md`, and `prompts/AUDIT_STATE.md` (plus workspace `../AGENTS.md` if present).
2. **Git Pre-Flight (`AUTONOMOUS` only):** Run `git status --porcelain`. If the working tree is dirty, fall back to **`INTERACTIVE`** (read-only plan only) so uncommitted user changes are never touched.
3. **Bidirectional Coverage Drift Guard:** Compare all runtime, deployment, and formal files under `rust/src/**/*.rs`, `php/` (`.php`, `.sh`, `.htaccess`, `.txt`, `.html`), `docker/` (`.yml`, `.service`), `formal/` (`.tla`, `.cfg`), `Dockerfile`, and `config.example.toml` against `S01`–`S08` in `prompts/AUDIT_STATE.md`:
   - Append any newly created unmapped file to the most cohesive slice (marking it `🟡 ReCheck` if `Last_Run != never`).
   - Remove any path that no longer exists on disk, and verify no file appears in more than one slice.
4. **Select ONE slice** (unless caller names specific Slice ID(s)):
   - **Priority 1:** Any slice with `Last_Run == never` or `⚪ Pending` (`P1 > P2 > P3`, then lower Slice ID).
   - **Priority 2:** Any slice marked `🟡 ReCheck` (`P1 > P2 > P3`, oldest `Last_Run`, lower Slice ID).
   - **Priority 3:** Remaining slices NOT marked `🔴 Fix_Open`, ordered by **lowest `Clean_Streak`**, then **highest `Total_Finds`** (hotspot focus), then oldest `Last_Run`, then `P1 > P2 > P3`, then lower Slice ID.
   - If **`S09`** is selected, pick the next unreviewed end-to-end flow (`F1`–`F4`, rotating based on `Notes`) and inspect its cross-slice PHP↔Rust↔`SPEC.md`↔`humoco-proto` seams plus `rust/tests/integration_tests.rs` and `tests/*.sh`.

### Step 2: Open-Ended Read-Only Audit + Deterministic Signals
Do NOT modify production/test files in this step. Inspect every file in the selected slice (and direct cross-module, PHP↔Rust, or `SPEC.md` boundaries) without checklist tunnel vision through two lenses:
1. **Adversarial / Worst-Case Thinking:** Crafted HTTP headers/queries/JSON/605-byte binary `LockEntry` frames, replay/nonce bypass, clock skew, concurrent Write-Once races (`redb` transactions vs. PHP `link()`/`flock()`/`fsync()`/`ignore_user_abort`), rollback/amnesia bypass or forged-receipt Self-Freeze DoS, partial-batch corruption, rotation timelock/veto/nomination-binding/union-QC bypasses, `0s` pure-growth smuggling (shrink/replacement), `admin_app` vs. `registered` / Free-Pool quota starvation, `DELETE ?account` lock erasure, path traversal / dotfile / `.htaccess` exposure of `.lock_key.php` or `.state.php`, XSS/CSRF/session fixation/header-CRLF injection in `/register`, `/admin`, `/api/v1/admin/*`, or SMTP mailer, inode/memory/CPU exhaustion, or panics on untrusted input.
2. **Engineering Hygiene & Sync Invariants:** Strict `#![forbid(unsafe_code)]`, panic-free `Result` handling & checked/saturating arithmetic in Rust; PHP >= 8.1 strict types/error checks, `fsync()` durability & `sodium_crypto_sign_verify_detached` constant-time hygiene; exact PHP↔Rust↔`SPEC.md` wire & status-code parity (`200`/`304`/`400`/`401`/`403`/`405`/`409`/`410`/`507`); Zero-PII & secret shielding (`Zeroize`, never logging tokens/keys/emails, never backing up `lock_sk`); `zero-compat` hygiene (no legacy v1/4-field shims or dead branches); and whether `rust/tests/integration_tests.rs`, `tests/run.sh`, and `tests/test_php_locks.sh` actually assert adversarial failure paths (not just happy paths).
3. **Deterministic Tool Signals:** Run targeted read-only checks relevant to the slice where helpful to ground suspicions: `cd rust && cargo clippy --all-targets --offline -- -D warnings`, `php -l php/sync.php php/lock_handler.php php/lock_rotation.php php/config.php` (if `php` is installed), or targeted `cargo test --offline` / `./tests/run.sh --target rust` checks. Do not run live external hoster benchmarks (`tests/measure_hoster.sh --url ...`).

### Step 2.5: Falsifier & Design-Intent Gate (Anti-False-Positive Filter)
Before counting any candidate finding:
1. **Actively try to disprove it:** Trace request parsing, auth/rate-limit middleware, `redb`/`flock` transactions, `humoco-proto` verifiers, and `SPEC.md` to confirm reachability and real impact. Discard speculative or unreachable issues.
2. **Check `docs/security/DESIGN_INTENT_TRIAGE.md`:** Discard intentional zero-knowledge static reads, unauthenticated `POST ?lock` causal/PoW admission, ephemeral `lock_sk`/Self-Freeze, partial-batch prefix commit, Hybrid `index.json`/`HEAD` `200 OK` semantics, Zero-PII HMAC email, `DELETE ?account` lock immunity, `0s` pure-growth creator timelock, 1-inode PHP rate limiter, or PHP >= 8.1 / zero-compat requirements.
3. Keep **ONLY concrete, code-verified findings** backed by exact `file:line` references.

### Step 3: Update Ledger (`prompts/AUDIT_STATE.md`)
Update the reviewed slice's row (and any drift-guard path updates; for `S09`, record the inspected flow `F1`–`F4` in `Notes`):
- **0 verified findings:** Increment `Clean_Streak` by `+1`, set `Last_Run` to today (`YYYY-MM-DD`), set `Status` to `🟢 Clean`. Stop and output a concise 3-line confirmation + updated row.
- **>= 1 verified findings:** Reset `Clean_Streak` to `0`, add finding count to `Total_Finds`, set `Last_Run` to today (`YYYY-MM-DD`), set `Status` to `🔴 Fix_Open`, and proceed to Step 4.

### Step 4: Root-Cause Clustering & KISS Plan Refinement
1. **Cluster Root Causes:** Group related findings to fix shared structural causes cleanly rather than patching symptoms individually.
2. **Draft a Minimal KISS Plan** respecting these non-negotiable guardrails:
   - **`zero-compat` meaning:** Never add artificial backwards-compatibility complexity (no legacy shims or old-protocol fallback branches), **and never silently delete code/fields/files**.
   - **Mandatory Separation:** Classify every item into:
     - *(a) Unambiguous Safe Fixes*
     - *(b) Uncertainties / Design Questions*
     - *(c) Planned Removals (Human Approval Required)* — collect all proposed deletions/removals in one dedicated section.
3. **Iterative Refinement (`plan-improver` + `kiss`):**
   - For **1–2 isolated, trivial bugs:** Do 1 concise edge-case & KISS check.
   - For **>= 3 findings, shared root causes, or architectural/protocol changes:** Run **2–3 focused passes** of adversarial plan stress-testing (edge cases, rollbacks, PHP↔Rust parity, assumptions) paired with KISS simplification until no material new insights or simplifications emerge.

### Step 5: Mode-Specific Execution

#### Mode A — `INTERACTIVE` (Default)
**STOP before modifying code.** Present a compact summary (or reviewable plan artifact) containing:
1. Verified findings & root-cause clusters (`file:line`),
2. The refined KISS implementation plan,
3. Dedicated section **Planned Removals (Human Approval Required)**,
4. Compact list of **Uncertainties / Questions** (if any).
Wait for human approval before executing Step 6. *(When run non-interactively via CLI, this plan serves as the self-contained handoff prompt.)*

#### Mode B — `AUTONOMOUS`
Do NOT pause; execute ONLY **Unambiguous Safe Fixes** (skip all **Uncertainties** and all **Planned Removals** — never guess, never execute unapproved deletions):
1. Implement fix clusters **strictly sequentially**, starting each cluster only when tests are green.
2. **Circuit Breaker:** If a fix cluster still fails tests/clippy/lint after **max 3 repair attempts**, cleanly revert ONLY that cluster's edits (if revert would collide with files touched by an earlier passing cluster, stop immediately without reverting prior work), defer the cluster to the final report, and move on.
3. After Step 6, write a compact report to `prompts/reports/YYYY-MM-DD_<SLICE>.md` (if any items were deferred or uncertain) AND output a concise final summary listing: (a) safely fixed items, (b) deferred uncertainties/circuit-breaker items, and (c) collected **Planned Removals** awaiting human review.

### Step 6: Evidence-Based Implementation & Double Verification
*(Executed after human approval in `INTERACTIVE`, or directly for safe fixes in `AUTONOMOUS`.)*
1. **Fail-First Proof:** Write deterministic regression test(s) (Rust unit/integration test in `rust/tests/integration_tests.rs`, or blackbox/PHP assertion in `tests/run.sh` / `tests/test_php_locks.sh`) asserting the expected safe invariant and confirm they **FAIL** before patching production code.
2. **Minimal Fix:** Implement the approved minimal fix (and only approved removals), maintaining strict PHP↔Rust↔`SPEC.md` parity whenever protocol behavior is touched.
3. **Full Verification Gate:**
   - Rust daemon (`cd rust`):
     - `cargo fmt --all -- --check`
     - `cargo clippy --all-targets --offline -- -D warnings`
     - `cargo nextest run --status-level fail` *(fallback: `cargo test --offline`)*
   - PHP syntax check (when `php` >= 8.1 is available):
     - `php -l php/sync.php && php -l php/lock_handler.php && php -l php/lock_rotation.php && php -l php/config.php`
   - Blackbox & PHP lock suites (from repo root):
     - `./tests/run.sh --target both --allow-missing-php`
     - `./tests/test_php_locks.sh` *(when `php` >= 8.1 is available and PHP files or lock protocol changed)*
4. **Immediate Self-Audit:** Compare the resulting diff against the KISS plan (no unintended edits, no unapproved deletions, no new warnings, PHP↔Rust↔`SPEC.md` parity intact).
5. **Final Ledger Update (`prompts/AUDIT_STATE.md`):**
   - If **>= 1 fix was implemented and verified:** Set `Status` to `🟡 ReCheck` (keep `Clean_Streak` at `0`) so the next independent audit pass verifies the new code. If `AUTONOMOUS` deferred open questions/removals, link the report in `Notes` (e.g., `Open items: prompts/reports/...`).
   - If **0 fixes were implemented** (all deferred): Keep `Status` as `🔴 Fix_Open` and link the report in `Notes`.
```
