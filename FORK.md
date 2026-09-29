# BytFactory's maintained Hermes fork

This repository, [ih-hugh/hermes-agent](https://github.com/ih-hugh/hermes-agent),
carries the Hermes changes required by BytFactory. Its upstream is
[NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent).
Prefer supported plugins and upstream contributions; carry a core patch here only
with a concrete consumer, behavioral tests, review, and an entry in this register.
Factory policy, budgets, gate verdicts, and work-order transitions remain in
BytFactory. Hermes run status is an observation, not a factory verdict.

The factory operator owns patch intake and release decisions. A patch author
updates this register in the same PR; an independent reviewer checks its behavior,
upstream status, and retirement criterion. BytFactory's operator contracts are the
[Hermes integration contract](https://github.com/ih-hugh/BytFactory/blob/main/docs/hermes-integration.md)
and [Mintlify handbook source, section 23.4](https://github.com/ih-hugh/BytFactory/blob/main/handbook/tenancy-and-forking.mdx).
At the early 2026-09-28 checkpoint below, BytFactory's maintained-fork writeback
was pending. [BytFactory PR #67](https://github.com/ih-hugh/BytFactory/pull/67)
subsequently merged that policy into the linked contract and handbook. The dated
checkpoint remains historical evidence, not a description of the current runtime.

## Source checkpoint: 2026-09-28 UTC

These are recorded observations, not moving version aliases or deployment claims.

| Reference | Exact commit |
| --- | --- |
| Shared upstream ancestor | `cedf4a3d78675283fa93e4e6ea2d6212bf414667` |
| Fork main after PR #2 | `2be8441ba14eb9cf5809d7f3084663066692206f` |
| Upstream main at audit | `9a0a1625367242596d338ae2da541c4a1fc785a2` |
| Latest published upstream release at audit: [v2026.9.24 / v0.21.5](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.9.24) | `f97608f178d1ffeca59860195ab7da295f7c8e5f` |
| BytFactory's committed vendor pin at `385b3b9cb22f833ba387f75c8357dea43828ac7d` | `384454ff4168074d787f052c75fce8c4df01e856` |

At this checkpoint the fork has nine reachable commits absent from upstream main,
and upstream main has 10,443 absent from the fork. Against the release above the
counts are nine and 6,603. These include merge history; they do not measure the
number of compatibility changes. Recompute from exact refs at the next intake.

The factory's installed editable gateway source was clean at `384454ff`, and the
running shared gateway's command and editable package target pointed to that tree.
Its checkout still had an upstream `origin` URL: the exact commit, not the remote
name, identifies the fork source. This was OS/service/source evidence, without an
in-process revision attestation. PR #2 was merged but **not installed or live
qualified**. The gateway serves other profiles as well as `byf-builder`; its restart
is not a builder-only action. No runtime update or restart accompanied this record.

## Carried changes

### PR #1 — names-only run tool diagnostics

- [Pull request](https://github.com/ih-hugh/hermes-agent/pull/1), merged 2026-09-20
  as `384454ff4168074d787f052c75fce8c4df01e856`.
- Implementation commits: `81a0cbf85231b3ad39ce2b364df01a20a261b2ad`,
  `5901171fb72991ad6989c53c7b5c61edf472f558`,
  `21e9bd523aa695b598141cdc44ca7a2afb3fdae0`,
  `90f33dfbde30903b3a60805be06e5388ca4ece17`,
  `95c2f2334aa4a950b78af1aaabefb8b0b875b649`.
- Purpose: let an authenticated run owner inspect the bounded, names-only tool
  inventory at the actual SDK-send boundary. Opt-in `names-v1` capture records
  invocation ordering and producer closure; unsupported transports, extensions,
  auxiliary calls, capture errors, and scope drift produce incomplete evidence.
  Capture must not alter normal tool assembly, provider requests, or authorization.
- Main seams: `agent/tool_diagnostic*.py`, chat-completion send paths,
  `gateway/platforms/api_server_tool_diagnostic.py`, runs routes, `model_tools.py`,
  and delegated/auxiliary calls. The PR contains the complete file list and API docs.
- Regression coverage: `tests/agent/test_tool_diagnostic.py`,
  `tests/gateway/test_api_server_tool_diagnostic.py`, and exact-source scratch gateway
  SDK-send qualification recorded in the PR. Its original affected selection was
  124 passing tests; this record does not rerun or extend that qualification.
- Upstream status at the checkpoint: no equivalent names-only endpoint or capture
  modules in the inspected upstream tree. Upstream runtime identity metadata alone
  does not prove which tool names were sent. No upstream submission is recorded here.
- Retire when a released upstream equivalent passes ownership, privacy, bounds,
  invocation/closure, actual SDK-send, and BytFactory consumer tests. Keep those
  behavioral checks when dropping the local implementation.

### PR #2 — approval status follows the pending request queue

- [Pull request](https://github.com/ih-hugh/hermes-agent/pull/2), merged 2026-09-28
  as `2be8441ba14eb9cf5809d7f3084663066692206f`.
- Implementation commits: `48988f688edac1b1e5dbf86bb2e4f1018cda526a`,
  `c926e3d57767276d749fddd15f305f4a2b20e3a2`.
- Purpose: remove stale `waiting_for_approval` projections after a request settles.
  Gateway-loop callbacks consult the live per-run queue, keep the displayed request
  while it is pending, and advance to the next redacted prompt after settlement.
  Success and HTTP 409 responses trigger reconciliation; a 409 is never evidence
  that permission was granted or denied. Stopping, terminal, absent, and retired
  runs remain guarded. This changes status projection, not approval authority.
- Main seam: `gateway/platforms/api_server_runs.py`. Regression coverage lives in
  `tests/gateway/test_api_server_runs.py` and
  `tests/gateway/test_approval_prompt_redaction.py`; 73 affected tests passed at the
  reviewed implementation head. No GitHub check suite was reported on that fork PR.
- Broader testing disclosed two failures reproduced on the exact PR #1 base:
  `test_roomlink_and_run_route_tuples_are_shard_owned` (route enumeration omits the
  existing diagnostic route) and
  `test_nonrecursive_verification_artifact_cleanup_is_not_dangerous` (existing
  temporary-file cleanup classification). These remain qualification work; the
  full Hermes suite is not claimed green.
- Upstream status at the checkpoint: the inspected runs API still lacks equivalent
  queue projection. Its existing settle hook handles messaging notices, which is
  not the same behavior. No upstream submission is recorded here.
- Retire when released upstream behavior passes concurrent-prompt, timeout,
  interrupt, HTTP 409, keyed persistence, redaction, and stopping/terminal race
  regressions, followed by exact-source scratch gateway qualification.

## Unmerged candidate: R0 producer finalization

This candidate is under implementation and review on `codex/recovery-session-seal`.
It is not on fork main, in the BytFactory vendor pin, or deployed. The reviewed
BytFactory plan is `docs/superpowers/plans/2026-09-28-supported-recovery.md`.
At the 2026-09-29 source refresh, fork main remained
`c8cc4723244cea6b994dab5974fcb11d7615f671` and BytFactory main remained
`11414a16930c90de04b320bce2550c8746ed8018`, with vendor pin
`2be8441ba14eb9cf5809d7f3084663066692206f`.

- Purpose: retain keyed runs-API root/nudge membership before dispatch, account for
  actual producers and acknowledged writes, then close admission and seal immutable
  transcript, usage and workspace-provider observations. Unknown sends, outstanding
  producers, unsupported lineage and incomplete source evidence refuse a seal.
  The resulting receipt grants no Factory gate, budget, cleanup or work-order authority.
- Main seams: `hermes_state_recovery*.py`, guarded session/message/usage writes,
  `agent/recovery_context.py`, `agent/recovery_producers.py`, actual SDK/tool workers,
  terminal-provider interception, and the runs and recovery HTTP routes. Alternate
  dispatch, detached delivery, shutdown replay and ordinary maintenance must respect
  protected rows. The PR diff is the complete changed-file inventory.
- Eligibility: this first constructor path qualifies only an explicitly configured
  direct OpenAI API chat-completions route and the exact loaded BytFactory workspace
  terminal. Discovery, dynamic fallback, other transports, extra tools and auxiliary
  producers remain unsupported. Ordinary model routing remains unchanged, but protected
  or unclassifiable database authority can make repair and alternate dispatch refuse.
  This restricted path is implemented, but the actual installed H/F source pair is
  still pin-mismatched and capability readiness remains false. Frontier Terminal's
  existing Nous configuration is not qualified by this candidate.
- Protected startup requires completed local turn-machinery warmup. Initial, rebuilt
  and per-request clients use the same stock OpenAI transport with SDK retries disabled;
  automatic auxiliary title generation is suppressed. Native usage is validated before
  acknowledgement, and pricing uses bundled metadata without remote model lookup.
  Missing prices remain unknown instead of becoming invented zero cost.
- HTTP: new protected admission and recovery routes require the selected profile's
  configured owner key and explicit opt-in. An identical committed runs-API key and
  owned run status remain readable when new admission is disabled or unready; this
  lookup grants no authority to start more work. The physical profile home is retained
  separately from the opaque owner scope. Bounded workers retain their slots until
  actual completion after cancellation or HTTP timeout; a proved committed admission
  result is handed off or explicitly marked incomplete rather than discarded.
  Root admission does not decode existing ordinary history. Nudge history is read in
  one snapshot with row, byte and deadline bounds before payload decoding.
  Saved seal/page reads and identical committed seal replay can survive restart without
  a provider; new finalization needs the matching admitted writer. A fresh process
  cannot take over a predecessor's unsealed closing work: lost owner/callback evidence
  remains incomplete. A receipt reports the
  observed persistent store UUID, which Factory must compare to independently retained
  admission evidence. Pathname checks are not adversarial opened-inode attestation.
- Qualification recorded so far: independently reviewed source units include the
  23-case process crash matrix, restricted constructor and request clients (98 checks),
  protected accounting (101 checks), and bounded served admission (51 checks rerun in
  independent review). A served scratch turn records one native SDK stream send,
  acknowledged usage, persisted user/assistant rows and producer closure. Provider
  capture is synthetic and no network request occurs. The broader comparison below
  retains known base failures; these checks do not establish real provider billing,
  a matching installed Factory source pair, shared-gateway readiness or human acceptance.
- Baseline: the exact pre-change `c8cc4723` selection of 117 files passed 1,485 tests
  and failed seven on macOS/Python 3.12.14 with the locked dev/messaging extras.
  Failures were route enumeration, temporary-file cleanup classification, three Linux
  mountinfo cases on macOS, SQLite synchronous expectation and an FTS query-count
  assertion. Keep these distinct from candidate regressions and Linux/full-CI results.
  An expanded 184-file base run passed 2,260 tests with the same seven failures and
  six missing optional-SDK failures; the latter passed after installing existing locked
  extras in a private qualification environment. The first 250-file candidate run at
  `582227cd817f6a9728244d8aadd141e1808c75f6` passed 3,274 tests, failed 46 and skipped
  42. The candidate regressions were fixed and independently reviewed, including
  a later-discovered VACUUM identity-lock deadlock repaired in `53badc2f`. The final
  251-file comparison at `53badc2fdecc1d37ea67991c0831b56230b627da`, using the same
  private locked environment and canonical runner with four workers, no automatic
  retries and a 180-second per-file limit, passed **3,339**, failed the same **seven**
  base cases and skipped **42**, with no timeout. This is a qualified change
  comparison, not a globally green suite or Linux/full-CI result. An earlier
  intermittent `DeletedWalGenerationError` remains a recorded qualification item;
  its absence here does not establish a causal fix. Blocking Ruff passes; `ty`
  remains advisory and non-green, with its changed-path diagnostics reviewed.
- Maintenance cost: this patch spans admission, asynchronous completion, SQLite schema
  and triggers, source codecs, physical SDK sends and terminal ownership. Upstream
  changes in any of those areas require a fresh behavioral audit. Do not forward-port
  only the HTTP endpoints or treat a source revert as a database rollback; protected
  stores require exact supported guard/schema definitions and preserve sealed evidence.
  Ordinary-session exclusion claims are permanent. Raw-schema leases can be released
  only by their owning process; an interrupted lease is not timed out on restart.
  These claims block conflicting protected admission. Partial or stale guard catalogs
  need a reviewed migration or forensic decision, never opportunistic repair.
  The private `state_meta.ordinary_init_settled_v1` stamp lets a fully initialized
  ordinary store reopen without a schema-write claim. It is an optimization, not
  authority: loaded initializer source, schema/version, journal/search capabilities,
  active raw-schema leases and actual store identity are rechecked. Drift uses claimed
  reconciliation; protected stores retain their separate strict attach path.
  Source installations must remain immutable until restart; this is not attestation
  of every loaded module. Existing WAL refusal and durability rules still apply.
- Upstream status: no R0 submission is recorded. A limited 2026-09-29 inventory at
  upstream main `666f313d1d3abd8077291ba464cf0a10f1a6157f` and the historical release
  commit above found no equivalent recovery ledger/modules. This is not a complete
  upstream compatibility audit or proof that no differently named equivalent exists.
- Retirement: retain tests for atomic keyed membership, producer closure across worker
  cancellation, lost-owner refusal and committed replay after restart, guarded
  cross-process writes, acknowledged usage without
  invented zero cost, immutable receipt/page replay, exact owner/profile scope, bounded
  capture and the independent Factory grant/source association. Qualify actual physical
  SDK sends and the effective terminal-only tool surface; require refusal before effects
  for alternate transports, dynamic fallback and auxiliary or delegated execution.
  Retire the patch only
  when a released upstream equivalent passes those tests plus the actual Factory pin
  and disposable served-runtime qualification. A terminal status or dead PID is never
  sufficient replacement evidence.

## Upstream maintenance plan

This is the proposed operating cadence; no recurring job or automatic update has
been installed.

1. **Review upstream weekly.** Record the date, exact fork/main/release refs, common
   ancestor, changed integration paths, advisories, and patch retirement decisions
   in a reviewed update to this register. Prioritize the latest published release
   as the normal integration target. Assess relevant security fixes promptly,
   outside the weekly cadence, and backport a narrow fix when a broad sync would
   delay it.
2. **Integrate in a fork PR.** Use an isolated branch from fork main and explicit
   remotes: fork for pushes, upstream for intake. Never reset fork main to upstream
   or run an unattended live `hermes update`. Preserve patch history and contributor
   credit. Inspect every conflict and changes to runs API, approvals, tool-send
   capture, terminal/workspace plugins, idempotency, and Kanban. For this initial
   catch-up, use intermediate verified upstream boundaries if the latest release
   cannot be reviewed as one change. Record retained, adapted, and retired patches.
3. **Qualify the exact candidate.** Use `scripts/run_tests.sh` with isolated test
   state, including affected Hermes suites and relevant broader regressions. Keep
   baseline failures visible. Verify BytFactory's Python board adapter, workspace
   confinement and trusted plugin, stop/cancel, approval status, and actual SDK-send
   diagnostic behavior through a scratch gateway. Complete BytFactory compatibility,
   replay, Docker/slow qualification and independent review. Require exact-head CI
   where configured; missing checks are not passing checks.
4. **Pin and deploy as separate steps.** A reviewed fork merge becomes an exact
   `vendor/hermes-agent` gitlink in a protected BytFactory PR. Release qualification
   does not update the separately installed gateway. Before deployment, verify the
   service's profile scope, pause admission and verify the tick timer is stopped,
   then separately verify dispatched controllers and remote work are drained. Retain
   dated config backups and the prior exact source/environment, and arrange coordinated shared
   service maintenance or a separately reviewed builder service. Confirm fork
   source, interpreter/import target, plugin identity, and post-restart process;
   then qualify observed approval behavior and one bounded factory trial.
5. **Keep rollback explicit.** Retain the prior factory tag, Hermes SHA, environment
   and compatible configuration. Assess SQLite/schema compatibility before an
   upgrade: reverting source alone is not a database rollback. If qualification
   fails, pause admission and use the reviewed restoration procedure. Never rewrite
   travelers, fork history, or unresolved run/accounting evidence to force recovery.

PR #2 was the next deployment candidate at the early 2026-09-28 checkpoint.
[BytFactory PR #68](https://github.com/ih-hugh/BytFactory/pull/68) subsequently pinned
it; the integration contract records the later dated deployment and bounded trials.
This register does not freshly attest the running gateway. R0 requires a separate
reviewed fork merge, Factory pin, release and deployment qualification. The much
larger upstream catch-up remains a separate reviewed compatibility scope.
