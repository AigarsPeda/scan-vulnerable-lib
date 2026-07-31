/** Temporarily override `process.platform` for contract tests that run on either OS. */
export function withPlatform<T>(platform: NodeJS.Platform, fn: () => T): T {
  const desc = Object.getOwnPropertyDescriptor(process, 'platform')
  Object.defineProperty(process, 'platform', {
    configurable: true,
    enumerable: true,
    value: platform,
  })
  try {
    return fn()
  } finally {
    if (desc) Object.defineProperty(process, 'platform', desc)
    else delete (process as { platform?: string }).platform
  }
}
