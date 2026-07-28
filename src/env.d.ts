/// <reference types="vite/client" />

declare module '*.png' {
  const src: string
  export default src
}

declare module '*.svg' {
  const src: string
  export default src
}

import type { ScannerApi } from './shared/types'

declare global {
  interface Window {
    scannerApi: ScannerApi
  }
}

export {}
