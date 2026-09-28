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
At this checkpoint their maintained-fork writeback is pending in a separate
BytFactory documentation PR: they still contain an obsolete no-fork policy. This
register records the approved fork state; it does not claim that writeback is merged.

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

The next deployment candidate is the small PR #2 change on the existing baseline.
The much larger upstream catch-up is a separate reviewed compatibility scope.
