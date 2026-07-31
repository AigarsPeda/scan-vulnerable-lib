import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts', 'electron/**/*.test.ts', 'src/**/*.test.ts'],
    exclude: ['node_modules', 'out', 'release', 'dist'],
    testTimeout: 60_000,
  },
  resolve: {
    alias: {
      '@shared': resolve(__dirname, 'src/shared'),
    },
  },
})
