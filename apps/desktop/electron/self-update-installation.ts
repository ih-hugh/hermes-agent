import fs from 'node:fs'
import path from 'node:path'

interface SelfUpdateRefusal {
  ok: false
  supported: false
  error: 'self-update-disabled' | 'self-update-guard-unavailable'
  reason: 'self-update-disabled' | 'self-update-guard-unavailable'
  message: string
  updateCommand: string
  hermesRoot: string
}

export function inspectSelfUpdateInstallation(root: string): { root: string; refusal: SelfUpdateRefusal | null } {
  let physicalRoot = root
  let code: SelfUpdateRefusal['error'] = 'self-update-guard-unavailable'

  try {
    physicalRoot = fs.realpathSync.native(root)

    if (!fs.statSync(physicalRoot).isDirectory()) {
      throw new Error('Installation root is not a directory.')
    }

    try {
      fs.lstatSync(path.join(physicalRoot, '.hermes-self-update-disabled'))
      code = 'self-update-disabled'
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { root: physicalRoot, refusal: null }
      }
    }
  } catch {
    // Failed root resolution never establishes sentinel absence.
  }

  return {
    root: physicalRoot,
    refusal: {
      ok: false,
      supported: false,
      error: code,
      reason: code,
      message:
        code === 'self-update-disabled'
          ? 'Self-update is disabled for this installation. Use operator-managed maintenance.'
          : 'Self-update protection could not be checked for this installation. Use operator-managed maintenance.',
      updateCommand: 'operator-managed maintenance',
      hermesRoot: physicalRoot
    }
  }
}

export async function runGuardedSelfUpdate<T>(
  root: string,
  update: (root: string) => Promise<T>,
  additionalTargets: readonly string[] = []
): Promise<T | SelfUpdateRefusal> {
  const observation = inspectSelfUpdateInstallation(root)

  if (observation.refusal) {
    return observation.refusal
  }

  for (const target of additionalTargets) {
    const targetObservation = inspectSelfUpdateInstallation(target)

    if (targetObservation.refusal) {
      return targetObservation.refusal
    }
  }

  return update(observation.root)
}
