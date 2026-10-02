import path from 'node:path'

import type { RemoteUpdateTarget } from './managed-ssh-update'
import { expandRemotePath } from './remote-lifecycle'
import { powerShellCommand, psLiteral } from './windows-remote-lifecycle'

const UNAVAILABLE =
  'Self-update protection could not be checked for the remote installation. Use operator-managed maintenance.'

export async function assertRemoteSelfUpdateAllowed(target: RemoteUpdateTarget): Promise<void> {
  const command =
    target.platform === 'Windows'
      ? powerShellCommand(
          `$ErrorActionPreference="Stop";$env:HERMES_HOME=${psLiteral(target.hermesHome)};` +
            `& ${psLiteral(target.hermesPath)} update --policy;if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}`
        )
      : `env HERMES_HOME=${expandRemotePath(target.hermesHome)} ${expandRemotePath(target.hermesPath)} update --policy`

  let policy: Record<string, unknown>

  try {
    const raw = await target.ssh.exec(command, { timeoutMs: 30_000, maxOutputBytes: 16_384 })

    if (Buffer.byteLength(raw, 'utf8') > 16_384) {
      throw new Error(UNAVAILABLE)
    }

    policy = JSON.parse(raw.replace(/^\uFEFF/, '').trim())

    if (
      !policy ||
      policy.schema !== 'hermes.update-policy/v1' ||
      typeof policy.allowed !== 'boolean' ||
      (policy.code !== null && typeof policy.code !== 'string') ||
      (policy.message !== null && typeof policy.message !== 'string') ||
      (policy.installation_root !== null && typeof policy.installation_root !== 'string')
    ) {
      throw new Error(UNAVAILABLE)
    }

    if (policy.allowed) {
      const root = policy.installation_root
      const pathApi = target.platform === 'Windows' ? path.win32 : path.posix

      if (typeof root !== 'string' || !pathApi.isAbsolute(root) || policy.code !== null || policy.message !== null) {
        throw new Error(UNAVAILABLE)
      }

      return
    }
  } catch {
    throw new Error(UNAVAILABLE)
  }

  throw new Error(typeof policy.message === 'string' && policy.message ? policy.message : UNAVAILABLE)
}
