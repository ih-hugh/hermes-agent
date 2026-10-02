import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { test } from 'vitest'

import { inspectSelfUpdateInstallation, runGuardedSelfUpdate } from './self-update-installation'

test('protected physical installation refuses local preparation through every alias', async () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-self-update-'))

  try {
    const root = path.join(scratch, 'install')
    fs.mkdirSync(root)
    const alias = path.join(scratch, 'alias')
    fs.symlinkSync(root, alias, 'junction')
    fs.symlinkSync(path.join(scratch, 'missing'), path.join(root, '.hermes-self-update-disabled'))

    for (const selected of [root, alias]) {
      let preparations = 0

      const result = await runGuardedSelfUpdate(selected, async () => {
        preparations += 1

        return { ok: true }
      })

      assert.equal(result.ok, false)
      assert.equal(preparations, 0)
      assert.equal(inspectSelfUpdateInstallation(selected).refusal?.error, 'self-update-disabled')
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})

test.skipIf(process.getuid?.() === 0)('inaccessible installation refuses without preparation', async () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-update-denied-'))

  try {
    fs.chmodSync(scratch, 0o000)
    let preparations = 0

    const result = await runGuardedSelfUpdate(scratch, async () => {
      preparations += 1

      return { ok: true }
    })

    assert.equal(result.ok, false)
    assert.equal(preparations, 0)
  } finally {
    fs.chmodSync(scratch, 0o700)
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})

test('only confirmed absence admits the real target; invalid root or marker lookup refuses', async () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-self-update-'))

  try {
    const admitted = await runGuardedSelfUpdate(scratch, async root => ({ ok: true, root }))
    assert.deepEqual(admitted, { ok: true, root: fs.realpathSync(scratch) })
    assert.equal(
      inspectSelfUpdateInstallation(path.join(scratch, 'missing')).refusal?.error,
      'self-update-guard-unavailable'
    )
    const marker = path.join(scratch, '.hermes-self-update-disabled')
    fs.writeFileSync(marker, Buffer.from([0xff, 0x00]))
    assert.equal(inspectSelfUpdateInstallation(scratch).refusal?.error, 'self-update-disabled')
    fs.unlinkSync(marker)
    fs.mkdirSync(marker)
    assert.equal(inspectSelfUpdateInstallation(scratch).refusal?.error, 'self-update-disabled')
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})

test('a distinct staged target refuses before preparing the unmarked selected checkout', async () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-staged-update-'))

  try {
    const selected = path.join(scratch, 'selected')
    const staged = path.join(scratch, 'home', 'hermes-agent')
    fs.mkdirSync(selected)
    fs.mkdirSync(staged, { recursive: true })
    fs.writeFileSync(path.join(staged, '.hermes-self-update-disabled'), '')
    const alias = path.join(scratch, 'staged-alias')
    fs.symlinkSync(staged, alias, 'junction')
    let preparations = 0

    const prepare = async (root: string) => {
      preparations += 1

      return { ok: true, root }
    }

    const result = await runGuardedSelfUpdate(selected, prepare, [alias])
    assert.equal(result.ok, false)
    assert.equal(preparations, 0)
    const admitted = await runGuardedSelfUpdate(selected, prepare)
    assert.deepEqual(admitted, { ok: true, root: fs.realpathSync(selected) })
    assert.equal(preparations, 1)
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})
