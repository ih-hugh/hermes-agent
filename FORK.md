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

## PR #4 — R0 producer finalization, qualification continuing

[PR #4](https://github.com/ih-hugh/hermes-agent/pull/4) was merged by the owner on
2026-09-29 as `47e1cea164cf6abbef881bc7c3c470cdbd870c6a`. The merge does not clear
the qualification items below. R0 is not in the BytFactory vendor pin or deployed. The reviewed
BytFactory plan is `docs/superpowers/plans/2026-09-28-supported-recovery.md`.
At the pre-merge 2026-09-29 source refresh, fork main remained
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
- Native selected-plugin qualification requires both the exact workspace-provider
  registration and its loader-owned tool-override policy in the same manager scope.
  The policy must remain disabled; absent, foreign, duplicate or enabled policy
  registrations and extra callbacks refuse protected admission. The native loader
  installs the disabled policy even without operator opt-in, so it is part of the
  supported registration inventory rather than an additional callback. Qualification
  inspects the settled policy slot without invoking selected-provider methods.
  Loader-backed regressions cover this inventory; installed-pair served qualification,
  the separate Factory pin and deployment remain independent evidence.
- Recovery member, provider-invocation and sealed-value generation parsing requires
  exact integer zero or one before Literal coercion, including each nested semantic
  member tuple. Booleans, floats, strings and missing/unsupported generations refuse
  at Python and JSON boundaries. The accepted integer values and published JSON
  schemas are unchanged; existing admission and admission-result checks remain strict.
  This evidence-type correction does not qualify a served runtime or authorize cleanup.
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

### R0 qualification follow-up — macOS WAL detector and fork CI

- `85b32502f2fe046f40007bdbee56650bdda1af95` rechecks the same macOS process and
  descriptor before using an enumerated WAL/SHM holder. A scratch real-libproc
  barrier reproduced a false refusal after that descriptor closed. A live stale
  descriptor still refuses; fd reuse is judged by its fresh identity. Only
  `EBADF`/`ESRCH` clear a vanished candidate. Short, empty or otherwise ambiguous
  results retain the earlier observation. This closes the reproduced race class;
  it does not establish the cause of the earlier uninstrumented failure or make
  the two observations atomic. Main seams are `hermes_state_dbfile.py` and
  `tests/hermes_state/test_deleted_wal_generation_guard.py`. Independent focused
  qualification passed 61 tests with 11 Linux-only skips on macOS. No upstream
  submission is recorded; retain the real close/reuse/live/ambiguous regressions
  when assessing an upstream equivalent.
- On 2026-09-29 the fork's Actions tab still showed inherited workflows disabled
  despite REST reporting Actions enabled and CI active. Enabling CI alone did not
  clear that repository latch. After recording the prior state and disabling
  unrelated workflows, the repository Actions permissions update enabled the
  fork. The UI and REST state were checked: CI and its selected reusable workflow
  files are present, while publishing, automatic source edits and unrelated workflows
  remain disabled. Scheduled OSV retains GitHub's `disabled_fork` state; its reusable CI
  scan and result jobs passed in the first manual run. Activation did not produce
  a retrospective PR #4 run. Actual exact-source aggregate CI qualification remains open.
- `95b88e67b06e28725f9395597bba9a102517d468` makes the existing CI usable on
  forks with standard hosted runners: upstream retains its larger runner labels;
  fork Linux tests use four workers with a bounded 60-minute full-suite job, and
  fork Windows, JS and Rust lanes use standard labels. The selected tests, steps
  and aggregate gate are unchanged. CI also accepts manual dispatch for future
  exact-main qualification. Independent structural review passed; a hosted run
  is still required. Retire these repository conditions if upstream CI becomes
  portable across forks without changing test coverage.


- `d3ed01fee8785a1d23da4a9cb1ef7b19822f02f5` makes the late SQLite contention
  tests deterministic: controlled elapsed time reaches the real blocked commit,
  its trace and rollback assertions, instead of consuming almost the entire
  deadline in a deliberate sleep. Product deadlines are unchanged. Independent
  canonical qualification passed all 14 tests in that file without retries.
- `e37c999ab82b065f2943e77fb1728bef1cfcc78e` corrects five inherited test fixtures:
  existing route enumeration, canonical temporary pathname, Linux-only detection,
  macOS durability floor and tracing of the actual pooled FTS reader. Independent
  canonical qualification passed all 452 tests across the five files without
  retries. No production safety condition was relaxed.
- The contributor check correctly refused the initial qualification branch because
  its commit author lacked an existing-format mapping. `2022bc1fc1b2044e475ceeafe5d069c2c76e09f5`
  adds the verified `ih-hugh` mapping without changing the gate. The adjacent
  case-collision fixture now asserts exact stored spelling and unchanged contents;
  a differently cased pathname can resolve to the original on macOS. All 11
  contributor tests passed in independent canonical qualification without retries.
- The first PR-triggered run failed before allocating any jobs with a GitHub
  internal error. Manual run
  [36590035558](https://github.com/ih-hugh/hermes-agent/actions/runs/36590035558)
  at `9cadc68d5b2f8682f115439025d254e5455aedaa` proved standard runner allocation
  and reusable security scanning, but it predates the fixture and mapping fixes
  and is not a passing exact-source qualification. The qualification branch contains these follow-ups;
  [PR #5](https://github.com/ih-hugh/hermes-agent/pull/5) tracks its review. The aggregate CI, installed source-pair, Factory pin
  and deployment gates remain separate.

### R0 qualification follow-up — full-suite compatibility

The first full hosted run at `9cadc68d` completed 4,222 test files with 49,943
passing tests, 60 failures and 505 skips. It exposed paths outside the earlier
affected selection. The corrections below preserve the admission/store boundary;
a focused green run is not full hosted CI or an installed Factory source-pair proof.

- `9db4df6f` updates gateway fixtures to include admission-worker shutdown state,
  the selected profile's configured owner key, and the actual scratch SessionDB.
  Independent canonical checks passed all 22 affected tests.
- `e2f8672d` and `9c34f643` apply the existing named-profile liveness guard before
  ordinary exclusion claims and raw delegation reads can create directories.
  An archived named profile remains archived. Direct and served regressions were
  reviewed; the respective independent affected runs passed 42 and 30 tests.
- `47a7a935`, `aa07fb25` and `8b98ec74` synchronize test fixtures with actual
  producer retirement or an explicit owner-release event. Run status alone does
  not prove retirement. DELETE-journal contention retains its typed immediate
  refusal; no product deadline was widened. The latter commit also supplies the
  declared exception and redaction interfaces in a terminal-provider SDK stub.
- `bca76d30` recognizes an ordinary legacy completion only when the entire
  missing-ledger catalog is the exact canonical exclusion-only bootstrap. Ledger
  and bounded catalog probes share an explicit read transaction. Extra, incomplete
  or altered catalogs still refuse. Independent affected checks passed 71 tests.
  First-ever concurrent initialization may still safely refuse against an unknown
  zero-byte inode; no repair exception was added.
- `92849cd7` closes the raw async schema-check/reconciliation race. The raw opener
  now holds an exact durable schema claim until successful initialization and
  hardening; uncertainty retains the claim. The shared SQLite helper's optional
  existing-file mode uses an escaped `mode=rw` URI and does not recreate a missing
  main file or parent. This mode is not inode attestation; the caller separately
  validates its retained claim against the connection. Both admission orderings,
  failed cleanup, vanished paths and escaped filenames are covered. Independent
  qualification from that committed source passed 157 tests without retries.
- `20142282` accepts effective DELETE mode for a settled ordinary database when
  the existing vulnerable-SQLite gate forces it, even if WAL was requested.
  Fixed-runtime external mode changes still reconcile. The catalog, source epoch,
  identity and FTS checks remain required; the WAL safety gate is unchanged.
- `ed9e2eb3` retains the new file's exclusive-creation descriptor through SQLite's
  first open and the pathname/inode check. This prevents immediate inode reuse
  from hiding an unlink/replacement during bootstrap. Refusal and error paths
  close the retained descriptor; existing files do not acquire this descriptor.
  This is not adversarial opened-inode attestation. Independent affected checks
  passed 32 tests. `a566c439` explicitly selects a fixed SQLite runtime in the
  separate WAL-sidecar ownership test and asserts that its fixture is in WAL.
- `44987b15` makes repair fixtures reach their intended live-holder guards by
  retaining a classifiable recovery catalog. Concurrent repairers may refuse a
  live holder; an explicit later operator retry must leave exactly one surgery
  and one forensic backup. Product repair behavior is unchanged. Independent
  checks passed 38 tests with one Linux-only skip; Linux remains a separate gate.
- `4453db94` tests one recovery read snapshot against a real concurrent protected
  writer in both journal modes. WAL must commit the newer revision before the
  reader fetches members while the reader still sees its old revision and member;
  DELETE must delay commit until that read ends. A fresh read must then see the
  committed closed member in both cases. Independent canonical checks passed 44
  tests. No product snapshot or write behavior changed.
- `bcc03c1c` prevents a disabled toolset alias from subtracting Blank Slate's kept
  terminal tool. It also returns a static 503 for unclassifiable session-store
  authority instead of claiming an empty session list; a pre-existing zero-byte
  file is not bootstrapped or rewritten. Quickstart happy-path tests now use a
  supported simulated hardware budget while retaining the real catalog decision.
  The immutable combined journal-mode and CLI selection at `bcc03c1c` passed 513
  tests in six files without retries.
- `13127f7f` gives ordinary agent fixtures explicit ordinary DB identity and updates
  private initialization arguments and spies to match their current contracts.
  `d46cb483` makes the model-picker fixture explicitly simulate absent Anthropic
  OAuth instead of consulting the operator's home. Original behavior assertions
  are retained; these commits do not change model routing or protected persistence.
- `c97e3431` corrects a desktop quickstart fixture whose authoritative mocked
  backend returned no jobs while its renderer cache claimed a running job. The
  actual initial poll now returns that same job. All 21 affected tests passed
  independently; the full local UI suite passed 7,721 tests in 819 files. Product
  desktop behavior is unchanged.
- `4406c783` anchors the existing whole-input launchctl/Hermes approval lookaheads
  once instead of rescanning every suffix. Matching order, descriptions and stored
  approval keys remain unchanged. The unchanged 2,000/4,000-segment benchmark
  timed out locally and in hosted CI before the change; independent review passes
  it in 1.6 seconds afterward. Four affected approval files passed 478 tests,
  failed three pre-existing macOS real-binary subprocess fixtures and skipped one.
  The same three sort/man cases failed before the regex edit and never call the
  detector. They remain host qualification failures, not a globally green claim.
- `c27c1bd2` lets the workspace-check wrapper drain its output before returning
  failure. Immediate process exit truncated hosted desktop failures and even the
  final summary. A real child-process regression reproduces the truncation with
  a 2 MiB failed-check log; all 70 root JavaScript tests, types and lint pass with
  the fix. Check selection, assertions and failure exit status are unchanged.
- `238a302b` corrects the TUI unmount-measurement fixture's scroll geometry. The
  old scroll position could unmount the row before the stale-cache update being
  tested. The fixture now deliberately commits those updates separately and
  still requires exactly one adjustment of one row. Independent review passed
  all 17 affected tests; the full local TUI check passed. No production scrolling
  behavior, timeout or retry policy changes.
- `148a06fa` adds protected-only `hermes.recovery-admission-result/v1` metadata to
  original and exact-replay 202 responses. The first store UUID and original
  member incarnation now come from durable admission, so BytFactory need not
  obtain its expected identity from the later seal being checked. A shared
  bounded validator reads the store singleton, member, root relation and verified
  provider admission in one transaction. Reserve returns that checked identity
  only after commit; early replay uses a query-only snapshot without recapturing
  a retired provider. Ordinary 202 bytes are unchanged. Strict integer generation,
  status, response-loss replay and dispatch after HTTP-timeout checks passed
  independent review with 121 affected tests. An immutable-checkout run covering
  all direct reservation callers passed 463 tests in 25 files without retries.
  The admission owner incarnation is distinct from the seal-time incarnation.
  This adds no SQL schema or cleanup
  authority; the corresponding Factory consumer and installed pair remain separate.
- `2e954886` avoids a false read-only diagnosis when SQLite removes an optional
  WAL or SHM sidecar between preflight enumeration and its permission check.
  Only a missing sidecar with an extant parent is ignored; present unreadable
  sidecars, the main database and its parent retain their existing refusal rules.
  Deterministic disappearance tests failed before the fix. Two independent
  reviews passed all 59 preflight and recovery-store tests without retries. No
  WAL deletion, extra retry or permission-repair scope is introduced.
- `6559afe5` keeps the real constants module in the slash-worker profile fixture
  while directing its home lookup to scratch. Its old whole-module mock omitted
  newly imported recovery helpers. The original subprocess/profile assertion
  remains; independent review passed all five related tests without retries.
- `12131a09` makes the hosted-room page-budget fixture use fixed per-row times.
  The first event's serialized length cannot bound later independently sampled
  floating-point timestamps: a deterministic reproduction produced singleton
  pages of 512 and 520 bytes against a 513-byte fixture budget. The reader's
  refusal was correct. The fixture now checks all four pages, their byte bounds,
  advancing cursors and final `has_more`, without changing product limits or
  retry policy. Two canonical runs passed all 45 tests without retries.

At this pre-merge checkpoint, an immutable 272-file selection at `4453db94`
passed 4,717 tests, failed those same three macOS binary fixtures and skipped 43,
without retries. The second full hosted run, at `58686a7b`, had 49,949 passing tests,
59 failures and 500 skips, including a benchmark timeout; it predates the final
corrections and remains failed evidence. The later full run at `7eafc454` passed
50,109 Python tests with one failure (the slash-worker fixture above) and 506
skips. Its JavaScript lane failed TUI unmount and desktop checks; the desktop
failure output was truncated. The output-drain correction preserves diagnostics
for the next run. Full hosted CI at `0206efd4` passed every selected lane,
including JavaScript/desktop and Python's 50,125 tests with 501 skips, in
[run 36607723776](https://github.com/ih-hugh/hermes-agent/actions/runs/36607723776).
That Python result includes one retried hosted-room fixture, corrected above;
it is not a retry-free result. The next full run at `91e71461` passed 50,125
Python tests with zero failures and 501 skips in 2,751 seconds, with no recorded
test retry. Its desktop UI suite failed one group follow-up scheduling test
(7,720 passed, one failed); the aggregate run remains failed. The test exposed
same-millisecond local entries being reordered by the UUID tie-breaker during
an echo merge, while delivery watermarks still referenced append positions.
The narrow ordering correction and deterministic regression qualification are
recorded below. Fresh exact-head aggregate CI remains required before readiness.
A mixed-source local run, where another worker changed initializer files after import, is invalid
evidence for the source-epoch checks and was discarded in favor of an immutable
checkout. No upstream submission is recorded for these follow-ups. Preserve their
behavioral regressions during upstream intake; retire compatibility-only fixture
changes when the corresponding upstream fixture and contract agree. The fork
merge, Factory pin, installed source-pair qualification and deployment are separate.


### R0 qualification follow-up — desktop local message ordering

- `2f93c02e` keeps newly appended room messages after the usable timestamp
  maximum in the bounded retained log. Echo merges sort by timestamp and UUID;
  the old same-tick timestamps could reorder entries beneath index-based member
  watermarks, dropping or repeating a queued follow-up. Deterministic same-tick
  and backward-clock regressions fail against the exact fork base and pass with
  the correction. No persisted field, sync schema, dependency or check changes.
- Local timestamps can lead wall time during bursts or clock rollback. This
  preserves local append order, not causal ordering between independent peers.
  Unorderable legacy timestamps are not repaired, and safe-integer exhaustion
  refuses a new append. Existing duplicate suppression remains unchanged.
- Independent review passed 102 room tests. Final focused tests, TypeScript and
  scoped ESLint passed after padding-only cleanup. The full local desktop run
  passed 9,947 tests and failed one unchanged Electron fixture, which invokes
  `/bin/true`, absent on this Mac. That test and its production dependencies are
  byte-identical to fork base `47e1cea1`; its isolated run reproduced the same
  failure. All local UI tests passed. The local desktop result remains non-green;
  only fresh hosted aggregate CI on the final commit can clear the merge gate.
- No upstream submission is recorded for this fix. Retain the behavior tests
  during upstream intake and retire the patch when the equivalent invariant is
  present upstream. Shared gateway/runtime deployment remains a separate step.

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
This register does not freshly attest the running gateway. R0's fork merge is
recorded above; it still requires qualification of its follow-up fixes, the separate
Factory pin, release and deployment. The much
larger upstream catch-up remains a separate reviewed compatibility scope.

## Protected structured reasoning — qualification checkpoint

The Factory's five role defaults request low reasoning. The protected runs route
previously refused their structured model_options, and passing reasoning_config
alone would still omit the scalar on direct OpenAI Chat Completions. This maintained
patch admits only model_options={reasoning:{effort:low|medium|high}}. Absence retains
the previously qualified wire behavior. Unknown levels and keys, generic overrides,
service tiers, disabled reasoning and alternate routes remain refused.

The immutable, actually issued preparation retains the scalar; the real constructor
checks its exact configuration before effects. The request builder projects that
choice into top-level SDK reasoning_effort and the final streaming/nonstreaming guard
rechecks it before each physical send. Mutable request or agent configuration does
not replace the issued choice; copied preparations, changed constructor inputs and
dropped/substituted send fields refuse. Existing selected-provider, terminal-only,
no-MCP, producer, hidden-retry and no-override boundaries remain in force. Complete
normalized-body fingerprints bind effort changes to keyed root/nudge requests.

Behavioral qualification uses the canonical isolated test runner, real Hermes
imports, scratch state stores and actual served root/nudge-to-AIAgent-to-OpenAI SDK
paths. Only the SDK transport boundary and the existing selected-provider fixture
are substituted; no provider call, installed Factory bundle, shared runtime or
production deployment is qualified here. The affected suite retains producer
closure, source accounting, exact retries, constructor drift and effective tool
guards. Fixture repairs preserve the same issued selected-plugin identity and give
minimal sender fixtures genuine supported-route absence preparations.

Upstream equivalence has not been qualified at this checkpoint. Retire the patch
when a released upstream protected route passes strict structured shape, immutable
issued-choice binding, absence, changed-body idempotency and actual root/nudge SDK
propagation/substitution regressions. Independent fork review/CI/merge precede the
separate Factory grammar mirror, reviewed pin and installed-pair qualification.


## Installation-managed self-update protection — 2026-10-01

BytFactory's shared Hermes source is deployed at an explicitly reviewed fork
revision, paired with a separately reviewed Factory pin and trusted workspace
bundle. An ordinary self-update must not replace that source or restart its shared
services outside the coordinated deployment process. A detached Git HEAD is not
protection: the existing updater switches it to its update branch.

This patch reserves `.hermes-self-update-disabled` in the physical code
installation root. The operator explicitly provisions it for a managed
installation. Presence of any entry disables supported self-update paths; contents
are neither parsed nor trusted. An uncertain root or marker lookup also refuses.
The decision is independent of profile home, current directory, remote name and
force flags. Unmarked installations keep their ordinary update behavior. Existing
image/package-managed checks remain in force.

The common Python admission check covers CLI and dashboard updates; outer
interactive, messaging, Desktop and directly invoked update helpers must refuse
before their own service preparation, source replacement or dependency repair.
Read-only planning reports the maintenance requirement. The read-only
`hermes update --policy` command and `system.updatePolicy` TUI RPC expose the
`hermes.update-policy/v1` admission observation before a caller prepares or drains
services. Managed SSH updates require this observation from the exact configured
launcher; an older or unavailable remote interface requires operator maintenance.
The guard is not a filesystem security boundary against an operator who can remove the marker or
manually replace the source, nor does it constrain arbitrary third-party installers.

This source PR does not provision the marker, rewrite remotes, update the live
installation, rebuild its staged helpers, restart the shared gateway or advance
BytFactory's pin. During later coordinated maintenance, install the reviewed
source/helpers, configure the fork as `origin` and Nous as `upstream`, provision
the installation marker, and verify refusal through the deployed entry points.
Only then is the installed runtime protected. Retain the existing drain, backup,
compatible-state rollback and post-restart qualification requirements above.

Scratch tests cover entry shapes, uncertain lookups, profile independence,
preparation refusal, the policy wire contract, staged-target selection and bounded
remote observation. Affected no-runtime updater fixtures explicitly isolate
launchd discovery/restart so tests cannot act on the operator's fleet. Native
observer tests and source review are separate from actual Windows execution,
full Rust integration, packaged-app qualification and deployed protection; the PR
records the completed host/CI evidence and any remaining limits.

Upstream submission/equivalence is not established. Retire this patch when a
released upstream installation-wide maintenance policy passes the same
profile-independent refusal, pre-effect, invalid-entry, native-helper and
unmarked-install compatibility regressions. Qualification results and the final
reviewed patch reference are recorded in the pull request; implementation does
not establish deployment or live acceptance.
