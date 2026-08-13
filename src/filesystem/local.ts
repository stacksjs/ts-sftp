/**
 * The default file system: a directory on local disk, exposed to the session as
 * its own root.
 */

import type { FileHandle } from 'node:fs/promises'
import type {
  SftpAttributes,
  SftpDirectoryEntry,
  SftpDirectoryHandle,
  SftpFileHandle,
  SftpFileSystem,
  SftpOpenFlags,
} from '../types'
import { constants } from 'node:fs'
import { open, readdir, readlink, rename, rmdir, stat, lstat, mkdir, symlink, truncate, unlink, utimes, chmod, realpath } from 'node:fs/promises'
import { isAbsolute, join, resolve } from 'node:path'
import { SftpError } from '../errors'
import { normalizeVirtualPath } from './paths'

interface LocalFileHandle extends SftpFileHandle {
  file: FileHandle
  appending: boolean
}

interface LocalDirectoryHandle extends SftpDirectoryHandle {
  /** Real path, so each batch can be stat'd as it is served. */
  realPath: string
  /** Names still to serve, in order. */
  remaining: string[]
}

/**
 * Entries served per SSH_FXP_READDIR. The protocol expects a directory to come
 * back over several replies, and a batch is one `lstat` per name — so this
 * bounds both the work done before a client sees anything and the size of a
 * single response packet.
 */
const READDIR_BATCH = 100

/** Convert node's stat output to SFTP attributes. */
function toAttributes(stats: {
  size: number
  uid: number
  gid: number
  mode: number
  atimeMs: number
  mtimeMs: number
}): SftpAttributes {
  return {
    size: stats.size,
    uid: stats.uid,
    gid: stats.gid,
    mode: stats.mode,
    atime: Math.floor(stats.atimeMs / 1000),
    mtime: Math.floor(stats.mtimeMs / 1000),
  }
}

/** Render the `ls -l` style line clients display for a directory entry. */
export function formatLongname(filename: string, attributes: SftpAttributes): string {
  const mode = attributes.mode ?? 0o100644
  const type = (mode & 0o170000) === 0o040000 ? 'd' : (mode & 0o170000) === 0o120000 ? 'l' : '-'

  let permissions = ''
  for (let shift = 6; shift >= 0; shift -= 3) {
    const bits = (mode >> shift) & 0o7
    permissions += `${bits & 4 ? 'r' : '-'}${bits & 2 ? 'w' : '-'}${bits & 1 ? 'x' : '-'}`
  }

  const size = String(attributes.size ?? 0).padStart(8)
  const date = new Date((attributes.mtime ?? 0) * 1000)
  const month = date.toLocaleString('en-US', { month: 'short' })
  const day = String(date.getDate()).padStart(2)
  const time = `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`

  return `${type}${permissions} 1 ${attributes.uid ?? 0} ${attributes.gid ?? 0} ${size} ${month} ${day} ${time} ${filename}`
}

/** Translate SFTP open flags into the flag string node expects. */
function openFlags(flags: SftpOpenFlags): number {
  let value = 0

  if (flags.read && flags.write) value |= constants.O_RDWR
  else if (flags.write) value |= constants.O_WRONLY
  else value |= constants.O_RDONLY

  if (flags.create) value |= constants.O_CREAT
  if (flags.truncate) value |= constants.O_TRUNC
  if (flags.exclusive) value |= constants.O_EXCL
  if (flags.append) value |= constants.O_APPEND

  return value
}

/** A local-disk file system rooted at a directory. */
export class LocalFileSystem implements SftpFileSystem {
  private readonly root: string

  constructor(
    root: string,
    private readonly options: { readOnly?: boolean; followSymlinks?: boolean } = {},
  ) {
    this.root = resolve(root)
  }

  /** Map a virtual path to a real one that cannot leave the root. */
  private real(path: string): string {
    const virtualPath = normalizeVirtualPath(path)
    const realPath = join(this.root, virtualPath)
    // join() on a normalized virtual path cannot escape, but a caller passing an
    // absolute real path through a custom front end could — check anyway.
    if (realPath !== this.root && !realPath.startsWith(`${this.root}/`))
      throw SftpError.permissionDenied(`path outside the served root: ${path}`)
    return realPath
  }

  private assertWritable(operation: string): void {
    if (this.options.readOnly) throw SftpError.permissionDenied(`${operation} denied: the server is read-only`)
  }

  async open(path: string, flags: SftpOpenFlags, attributes: SftpAttributes): Promise<SftpFileHandle> {
    if (flags.write || flags.create || flags.truncate) this.assertWritable('write')

    const file = await open(this.real(path), openFlags(flags), attributes.mode ?? 0o644)
    const handle: LocalFileHandle = { path: normalizeVirtualPath(path), file, appending: flags.append }
    return handle
  }

  async read(handle: SftpFileHandle, offset: number, length: number): Promise<Uint8Array | undefined> {
    const local = handle as LocalFileHandle
    const buffer = new Uint8Array(length)
    const { bytesRead } = await local.file.read(buffer, 0, length, offset)
    return bytesRead === 0 ? undefined : buffer.subarray(0, bytesRead)
  }

  async write(handle: SftpFileHandle, offset: number, data: Uint8Array): Promise<void> {
    this.assertWritable('write')
    const local = handle as LocalFileHandle
    // O_APPEND ignores the offset by design; every other write is positional so
    // that parallel uploads land where the client asked.
    await local.file.write(data, 0, data.length, local.appending ? null : offset)
  }

  async close(handle: SftpFileHandle | SftpDirectoryHandle): Promise<void> {
    const local = handle as Partial<LocalFileHandle>
    if (local.file) await local.file.close()
  }

  async fstat(handle: SftpFileHandle): Promise<SftpAttributes> {
    return toAttributes(await (handle as LocalFileHandle).file.stat())
  }

  async fsetstat(handle: SftpFileHandle, attributes: SftpAttributes): Promise<void> {
    this.assertWritable('setstat')
    const local = handle as LocalFileHandle
    if (attributes.size !== undefined) await local.file.truncate(attributes.size)
    if (attributes.mode !== undefined) await local.file.chmod(attributes.mode & 0o7777)
    if (attributes.atime !== undefined && attributes.mtime !== undefined)
      await local.file.utimes(new Date(attributes.atime * 1000), new Date(attributes.mtime * 1000))
  }

  async opendir(path: string): Promise<SftpDirectoryHandle> {
    const realPath = this.real(path)
    const names = await readdir(realPath)
    const handle: LocalDirectoryHandle = {
      path: normalizeVirtualPath(path),
      realPath,
      remaining: ['.', '..', ...names],
    }
    return handle
  }

  async readdir(handle: SftpDirectoryHandle): Promise<SftpDirectoryEntry[] | undefined> {
    const local = handle as LocalDirectoryHandle
    if (local.remaining.length === 0) return undefined

    const batch = local.remaining.splice(0, READDIR_BATCH)
    const entries: SftpDirectoryEntry[] = []

    for (const name of batch) {
      try {
        const attributes = toAttributes(await lstat(join(local.realPath, name)))
        entries.push({ filename: name, longname: formatLongname(name, attributes), attributes })
      }
      catch {
        // A file that vanished between readdir and lstat is simply not listed.
      }
    }

    // Every name in this batch vanished: report the next batch rather than an
    // empty reply, which a client reads as the end of the directory.
    return entries.length === 0 ? this.readdir(handle) : entries
  }

  async stat(path: string): Promise<SftpAttributes> {
    return toAttributes(await stat(this.real(path)))
  }

  async lstat(path: string): Promise<SftpAttributes> {
    return toAttributes(await lstat(this.real(path)))
  }

  async setstat(path: string, attributes: SftpAttributes): Promise<void> {
    this.assertWritable('setstat')
    const realPath = this.real(path)
    if (attributes.size !== undefined) await truncate(realPath, attributes.size)
    if (attributes.mode !== undefined) await chmod(realPath, attributes.mode & 0o7777)
    if (attributes.atime !== undefined && attributes.mtime !== undefined)
      await utimes(realPath, new Date(attributes.atime * 1000), new Date(attributes.mtime * 1000))
  }

  async remove(path: string): Promise<void> {
    this.assertWritable('remove')
    await unlink(this.real(path))
  }

  async mkdir(path: string, attributes: SftpAttributes): Promise<void> {
    this.assertWritable('mkdir')
    await mkdir(this.real(path), { mode: attributes.mode === undefined ? 0o755 : attributes.mode & 0o7777 })
  }

  async rmdir(path: string): Promise<void> {
    this.assertWritable('rmdir')
    await rmdir(this.real(path))
  }

  async realpath(path: string): Promise<string> {
    const virtualPath = normalizeVirtualPath(path)
    try {
      // Resolve symlinks where the target exists, then map back into the
      // virtual namespace so a link cannot report a path outside the root.
      const resolved = await realpath(this.real(virtualPath))
      if (resolved === this.root) return '/'
      if (resolved.startsWith(`${this.root}/`)) return `/${resolved.slice(this.root.length + 1)}`
      return virtualPath
    }
    catch {
      return virtualPath
    }
  }

  async rename(from: string, to: string): Promise<void> {
    this.assertWritable('rename')
    await rename(this.real(from), this.real(to))
  }

  async readlink(path: string): Promise<string> {
    const target = await readlink(this.real(path))
    if (!isAbsolute(target)) return target
    if (target === this.root) return '/'
    if (target.startsWith(`${this.root}/`)) return `/${target.slice(this.root.length + 1)}`
    throw SftpError.permissionDenied('symlink points outside the served root')
  }

  async symlink(target: string, path: string): Promise<void> {
    this.assertWritable('symlink')
    // Store links relative to the link's own directory so they stay inside the
    // root no matter where it is mounted.
    await symlink(target.startsWith('/') ? this.real(target) : target, this.real(path))
  }
}
