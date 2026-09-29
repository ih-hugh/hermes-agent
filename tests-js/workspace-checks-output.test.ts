import { spawn } from 'node:child_process'
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, dirname, join, resolve } from 'node:path'

import { expect, it } from 'vitest'

it.skipIf(process.platform === 'win32')('retains large failed-check output and the complete summary before exiting', async () => {
  const fixture = mkdtempSync(join(tmpdir(), 'hermes-workspace-output-'))

  try {
    const npm = join(fixture, 'npm')
    writeFileSync(npm, `#!/usr/bin/env node
if (process.argv[2] === 'query') {
  console.log(JSON.stringify([{location:'fixture',scripts:{check:'unused'}}]));
} else {
  process.stdout.write('x'.repeat(2 * 1024 * 1024) + '\\nFAILED_CHECK_TAIL\\n');
  process.exitCode = 1;
}
`)
    chmodSync(npm, 0o700)

    const child = spawn(process.execPath, [resolve('../.github/scripts/run-workspace-checks.mjs'), '--concurrency', '1'], {
      env: { ...process.env, PATH: [fixture, dirname(process.execPath), process.env.PATH].join(delimiter), GITHUB_ACTIONS: 'true' },
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10_000,
    })

    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (data: string) => { stdout += data })
    child.stderr.on('data', (data: string) => { stderr += data })

    const code = await new Promise<number | null>((accept, reject) => {
      child.once('error', reject)
      child.once('close', accept)
    })

    expect(code).toBe(1)
    expect(stdout.includes('x'.repeat(2 * 1024 * 1024) + '\nFAILED_CHECK_TAIL\n')).toBe(true)
    expect(stdout).toContain('=== summary ===')
    expect(stdout).toContain('fixture :: check')
    expect(stderr).toContain('1 of 1 checks failed')
  } finally {
    rmSync(fixture, { recursive: true, force: true })
  }
})
