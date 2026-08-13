/**
 * Virtual path handling.
 *
 * A session sees a namespace rooted at `/`. Every request is normalized inside
 * that namespace before it touches disk, so `..` can climb to the root and no
 * further — the root is the floor, not a prefix check that a crafted path can
 * slip past.
 */

/**
 * Normalize a client-supplied path to an absolute virtual path with no `.`,
 * `..`, or empty segments. Relative paths are resolved against `cwd`.
 */
export function normalizeVirtualPath(path: string, cwd = '/'): string {
  const raw = path.length === 0 || path === '.' ? cwd : path
  const base = raw.startsWith('/') ? raw : `${cwd}/${raw}`

  const segments: string[] = []
  for (const segment of base.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      segments.pop()
      continue
    }
    segments.push(segment)
  }

  return `/${segments.join('/')}`
}

/** The parent of a virtual path. The root is its own parent. */
export function virtualDirname(path: string): string {
  const normalized = normalizeVirtualPath(path)
  const index = normalized.lastIndexOf('/')
  return index <= 0 ? '/' : normalized.slice(0, index)
}

/** The final segment of a virtual path. */
export function virtualBasename(path: string): string {
  const normalized = normalizeVirtualPath(path)
  return normalized.slice(normalized.lastIndexOf('/') + 1)
}
