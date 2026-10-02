import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'

import { test } from 'vitest'

import { assertManagedUpdatePreflightClear, runManagedSshUpdate } from './managed-ssh-update'
import { shq } from './remote-lifecycle'

const CORRELATION = '12345678-1234-4678-9234-567812345678'
const exec = promisify(execFile)

test('exact SSH launcher policy refuses before recovery or healthy-scope teardown', async () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-remote-policy-'))

  try {
    const launcher = path.join(scratch, "different install's launcher")

    const policy = {
      schema: 'hermes.update-policy/v1',
      installation_root: '/separate/code/root',
      allowed: false,
      code: 'self-update-disabled',
      message: 'Self-update is disabled for this installation. Use operator-managed maintenance.'
    }

    fs.writeFileSync(
      launcher,
      `#!/bin/sh\n[ "$1" = update ] && [ "$2" = --policy ] || exit 64\nprintf %s ${shq(JSON.stringify(policy))}\n`
    )
    fs.chmodSync(launcher, 0o700)

    const target = {
      hermesHome: scratch,
      hermesPath: launcher,
      platform: 'Darwin' as const,
      ssh: { exec: async (command: string) => (await exec('/bin/sh', ['-c', command])).stdout }
    }

    const effects: string[] = []

    const result = await runManagedSshUpdate({
      connectionId: 'scratch',
      correlationId: CORRELATION,
      scopes: [{ key: 'primary', profile: 'named' }],
      preflightRemote: () => assertManagedUpdatePreflightClear(target, CORRELATION),
      prepareRecovery: async () => {
        effects.push('recovery')
      },
      drainScope: async () => {
        effects.push('drain')
      },
      updateRemote: async () => {
        effects.push('update')
        throw new Error('Unexpected updater')
      },
      awaitRestoreClearance: async () => {
        effects.push('clearance')
      },
      closeTransports: async () => {},
      restoreScope: async () => {
        effects.push('restore')
      },
      releaseGate: () => {}
    })

    assert.equal(result.ok, false)
    assert.match(result.error || '', /operator-managed maintenance/)
    assert.deepEqual(effects, [])
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})

test('older or malformed remote observations never authorize drain', async () => {
  for (const response of [
    '{}',
    JSON.stringify({ schema: 'unknown', installation_root: '/root', allowed: true, code: null, message: null }),
    JSON.stringify({
      schema: 'hermes.update-policy/v1',
      installation_root: null,
      allowed: true,
      code: null,
      message: null
    }),
    JSON.stringify({
      schema: 'hermes.update-policy/v1',
      installation_root: '/root',
      allowed: 'true',
      code: null,
      message: null
    })
  ]) {
    await assert.rejects(
      assertManagedUpdatePreflightClear(
        {
          hermesHome: '/profiles/named',
          hermesPath: '/chosen/launcher',
          platform: 'Linux',
          ssh: { exec: async () => response }
        },
        CORRELATION
      ),
      /operator-managed maintenance/
    )
  }
})

test('a complete allowed policy from the exact launcher preserves unmarked SSH preflight', async () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-remote-allowed-'))

  try {
    const launcher = path.join(scratch, 'launcher')

    const policy = {
      schema: 'hermes.update-policy/v1',
      installation_root: scratch,
      allowed: true,
      code: null,
      message: null
    }

    fs.writeFileSync(
      launcher,
      `#!/bin/sh\n[ "$1" = update ] && [ "$2" = --policy ] || exit 64\nprintf %s ${shq(JSON.stringify(policy))}\n`
    )
    fs.chmodSync(launcher, 0o700)
    await assertManagedUpdatePreflightClear(
      {
        hermesHome: scratch,
        hermesPath: launcher,
        platform: 'Darwin',
        ssh: { exec: async (command: string) => (await exec('/bin/sh', ['-c', command])).stdout }
      },
      CORRELATION
    )
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})
