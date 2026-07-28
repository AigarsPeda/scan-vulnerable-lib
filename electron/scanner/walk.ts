import fs from 'fs'
import path from 'path'
import { LANG_HINTS } from './types'
import { preferredRoots, shouldSkipDir } from './platform'
import type { ProgressState } from './progress'
import { showProgress } from './progress'

export type DetectedLang = {
  eco: string
  manifests: string[]
}

export async function walkDetect(
  roots: string[],
  state: ProgressState
): Promise<Record<string, DetectedLang>> {
  const detected: Record<string, DetectedLang> = {}
  const preferred = preferredRoots()
  const walkRoots: string[] = []
  for (const p of preferred) if (!walkRoots.includes(p)) walkRoots.push(p)
  for (const r of roots) if (!walkRoots.includes(r)) walkRoots.push(r)

  const queue = [...walkRoots]
  const visited = new Set<string>()
  let foldersSeen = 0
  const maxSourceSamples: Record<string, number> = {}

  const manifestNameSet = new Map<string, string>() // name -> language
  const manifestExtSet = new Map<string, string>()
  const sourceExtSet = new Map<string, string>()
  for (const [lang, hint] of Object.entries(LANG_HINTS)) {
    for (const n of hint.manifestNames) manifestNameSet.set(n.toLowerCase(), lang)
    for (const e of hint.manifestExt) manifestExtSet.set(e.toLowerCase(), lang)
    for (const e of hint.sourceExt) sourceExtSet.set(e.toLowerCase(), lang)
  }

  while (queue.length) {
    if (state.stopped) return detected
    const dir = queue.shift()!
    const norm = path.resolve(dir)
    if (visited.has(norm.toLowerCase())) continue
    visited.add(norm.toLowerCase())
    foldersSeen++

    if (foldersSeen % 40 === 0) {
      await showProgress(
        state,
        Math.min(14, 1 + (foldersSeen / 5000) * 13),
        'Phase 1/4: Detecting languages',
        `Folders: ${foldersSeen}`
      )
      if (state.stopped) return detected
    }

    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      continue
    }

    for (const ent of entries) {
      const full = path.join(dir, ent.name)
      if (ent.isDirectory()) {
        if (shouldSkipDir(full, ent.name)) continue
        if (ent.name === '.' || ent.name === '..') continue
        if (ent.name.startsWith('.')) continue
        queue.push(full)
        continue
      }
      if (!ent.isFile()) continue

      const lower = ent.name.toLowerCase()
      const ext = path.extname(ent.name).toLowerCase()

      let lang = manifestNameSet.get(lower)
      if (!lang && ext) lang = manifestExtSet.get(ext)
      if (lang) {
        const hint = LANG_HINTS[lang]
        if (!detected[lang]) detected[lang] = { eco: hint.eco, manifests: [] }
        if (!detected[lang].manifests.includes(full)) detected[lang].manifests.push(full)
        continue
      }

      const srcLang = sourceExtSet.get(ext)
      if (srcLang) {
        maxSourceSamples[srcLang] = (maxSourceSamples[srcLang] || 0) + 1
        if (maxSourceSamples[srcLang] <= 200 && !detected[srcLang]) {
          // source-only hit: mark language but without manifests yet
          const hint = LANG_HINTS[srcLang]
          detected[srcLang] = { eco: hint.eco, manifests: [] }
        }
      }
    }
  }

  // Drop languages that only had source samples and no manifests
  for (const lang of Object.keys(detected)) {
    if (!detected[lang].manifests.length) delete detected[lang]
  }

  await showProgress(state, 14, 'Phase 1/4: Detecting languages', `Found ${Object.keys(detected).length} language(s)`, true)
  return detected
}

export function groupProjects(
  detected: Record<string, DetectedLang>,
  maxProjects: number
): Record<string, string[]> {
  const projects: Record<string, string[]> = {}
  for (const [, info] of Object.entries(detected)) {
    const eco = info.eco
    if (!projects[eco]) projects[eco] = []
    for (const m of info.manifests) {
      const dir = path.dirname(m)
      if (!projects[eco].includes(dir) && projects[eco].length < maxProjects) {
        projects[eco].push(dir)
      }
    }
  }
  return projects
}
