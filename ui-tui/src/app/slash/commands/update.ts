import path from 'node:path'

import type { SlashRunCtx } from '../types.js'

const UNAVAILABLE =
  'Self-update protection could not be checked for this installation. Use operator-managed maintenance.'

export async function requestUpdateHandoff(ctx: SlashRunCtx): Promise<void> {
  try {
    const raw = await ctx.gateway.rpc('system.updatePolicy', {})
    const policy = raw as Record<string, unknown> | null

    if (ctx.stale()) {
      return
    }

    if (
      !policy ||
      policy.schema !== 'hermes.update-policy/v1' ||
      typeof policy.allowed !== 'boolean' ||
      (policy.code !== null && typeof policy.code !== 'string') ||
      (policy.message !== null && typeof policy.message !== 'string') ||
      (policy.installation_root !== null && typeof policy.installation_root !== 'string')
    ) {
      ctx.transcript.sys(UNAVAILABLE)

      return
    }

    if (!policy.allowed) {
      ctx.transcript.sys(typeof policy.message === 'string' && policy.message ? policy.message : UNAVAILABLE)

      return
    }

    if (
      typeof policy.installation_root !== 'string' ||
      !path.isAbsolute(policy.installation_root) ||
      policy.code !== null ||
      policy.message !== null
    ) {
      ctx.transcript.sys(UNAVAILABLE)

      return
    }

    ctx.transcript.sys('exiting TUI to run update...')
    // Python independently rechecks before applying the update.
    setTimeout(() => {
      if (!ctx.stale()) {
        ctx.session.dieWithCode(42)
      }
    }, 100)
  } catch {
    if (!ctx.stale()) {
      ctx.transcript.sys(UNAVAILABLE)
    }
  }
}
