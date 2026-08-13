/**
 * The SFTP subsystem itself: version 3 requests decoded off the channel,
 * dispatched to a file system, and answered.
 */

import type { SftpAttributes, SftpDirectoryEntry, SftpDirectoryHandle, SftpFileHandle, SftpFileSystem, SftpLogger, SftpOpenFlags } from './types'
import { SFTP, SFTP_ATTR, SFTP_OPEN, SFTP_STATUS, SFTP_VERSION } from './constants'
import { statusForError } from './errors'
import { formatLongname } from './filesystem/local'
import { concat, SshReader, SshWriter } from './wire'

/** Largest chunk we return for one READ, matching what clients ask for. */
const MAX_READ_LENGTH = 256 * 1024

type OpenHandle =
  | { kind: 'file'; handle: SftpFileHandle }
  | { kind: 'directory'; handle: SftpDirectoryHandle }

/** Decode an SSH_FXP_ATTRS structure. */
export function readAttributes(reader: SshReader): SftpAttributes {
  const flags = reader.uint32()
  const attributes: SftpAttributes = {}

  if (flags & SFTP_ATTR.SIZE) attributes.size = Number(reader.uint64())
  if (flags & SFTP_ATTR.UIDGID) {
    attributes.uid = reader.uint32()
    attributes.gid = reader.uint32()
  }
  if (flags & SFTP_ATTR.PERMISSIONS) attributes.mode = reader.uint32()
  if (flags & SFTP_ATTR.ACMODTIME) {
    attributes.atime = reader.uint32()
    attributes.mtime = reader.uint32()
  }
  if (flags & SFTP_ATTR.EXTENDED) {
    const count = reader.uint32()
    for (let i = 0; i < count; i++) {
      reader.string()
      reader.string()
    }
  }

  return attributes
}

/** Encode an SSH_FXP_ATTRS structure, flagging only the fields that are set. */
export function writeAttributes(writer: SshWriter, attributes: SftpAttributes): SshWriter {
  let flags = 0
  if (attributes.size !== undefined) flags |= SFTP_ATTR.SIZE
  if (attributes.uid !== undefined && attributes.gid !== undefined) flags |= SFTP_ATTR.UIDGID
  if (attributes.mode !== undefined) flags |= SFTP_ATTR.PERMISSIONS
  if (attributes.atime !== undefined && attributes.mtime !== undefined) flags |= SFTP_ATTR.ACMODTIME

  writer.uint32(flags)
  if (flags & SFTP_ATTR.SIZE) writer.uint64(attributes.size!)
  if (flags & SFTP_ATTR.UIDGID) writer.uint32(attributes.uid!).uint32(attributes.gid!)
  if (flags & SFTP_ATTR.PERMISSIONS) writer.uint32(attributes.mode!)
  if (flags & SFTP_ATTR.ACMODTIME) writer.uint32(attributes.atime!).uint32(attributes.mtime!)

  return writer
}

/** Translate SSH_FXP_OPEN pflags into the flags a file system takes. */
export function parseOpenFlags(pflags: number): SftpOpenFlags {
  return {
    read: (pflags & SFTP_OPEN.READ) !== 0,
    write: (pflags & SFTP_OPEN.WRITE) !== 0,
    append: (pflags & SFTP_OPEN.APPEND) !== 0,
    create: (pflags & SFTP_OPEN.CREAT) !== 0,
    truncate: (pflags & SFTP_OPEN.TRUNC) !== 0,
    exclusive: (pflags & SFTP_OPEN.EXCL) !== 0,
  }
}

/**
 * Handles one client's SFTP traffic. Bytes arrive through {@link receive} and
 * responses go out through the `send` callback given to the constructor.
 */
export class SftpSession {
  private buffered: Uint8Array = new Uint8Array(0)
  private handles = new Map<string, OpenHandle>()
  private nextHandleId = 1
  /** Requests are answered in arrival order per handle, but may overlap. */
  private pending = 0

  constructor(
    private readonly fs: SftpFileSystem,
    private readonly send: (data: Uint8Array) => void,
    private readonly logger: SftpLogger = {},
  ) {}

  /** Feed bytes from the channel. Complete packets are dispatched in order. */
  async receive(chunk: Uint8Array): Promise<void> {
    this.buffered = this.buffered.length === 0 ? chunk : concat(this.buffered, chunk)

    for (;;) {
      if (this.buffered.length < 4) return

      const view = new DataView(this.buffered.buffer, this.buffered.byteOffset, this.buffered.byteLength)
      const length = view.getUint32(0, false)
      if (length === 0 || length > MAX_READ_LENGTH + 1024) {
        // The framing is unrecoverable: everything after this length is at an
        // unknown offset. Drop what is buffered so the error is raised once,
        // rather than on every byte that follows it.
        this.buffered = new Uint8Array(0)
        throw new Error(`sftp: invalid packet length ${length}`)
      }
      if (this.buffered.length < 4 + length) return

      const packet = this.buffered.subarray(4, 4 + length)
      this.buffered = this.buffered.subarray(4 + length)
      await this.dispatch(packet)
    }
  }

  /** Release every handle the session still holds. */
  async close(): Promise<void> {
    const open = [...this.handles.values()]
    this.handles.clear()
    for (const entry of open) {
      try {
        await this.fs.close(entry.handle)
      }
      catch {
        // Closing on teardown is best-effort.
      }
    }
  }

  private reply(packet: Uint8Array): void {
    this.send(concat(new SshWriter().uint32(packet.length).toBuffer(), packet))
  }

  private status(id: number, code: number, message = ''): void {
    this.reply(
      new SshWriter().byte(SFTP.STATUS).uint32(id).uint32(code).string(message).string('').toBuffer(),
    )
  }

  private ok(id: number): void {
    this.status(id, SFTP_STATUS.OK)
  }

  private handleFor(id: string): OpenHandle {
    const entry = this.handles.get(id)
    if (!entry) throw new Error('sftp: unknown handle')
    return entry
  }

  private track(entry: OpenHandle): string {
    const id = `${entry.kind === 'file' ? 'f' : 'd'}${this.nextHandleId++}`
    this.handles.set(id, entry)
    return id
  }

  private async dispatch(packet: Uint8Array): Promise<void> {
    const reader = new SshReader(packet)
    const type = reader.byte()

    if (type === SFTP.INIT) {
      // Version negotiation: we answer with our version and no extensions.
      reader.uint32()
      this.reply(new SshWriter().byte(SFTP.VERSION).uint32(SFTP_VERSION).toBuffer())
      return
    }

    const id = reader.uint32()
    this.pending++

    try {
      await this.handleRequest(type, id, reader)
    }
    catch (error) {
      const status = statusForError(error)
      this.logger.debug?.('sftp request failed', {
        type,
        id,
        status,
        error: error instanceof Error ? error.message : String(error),
      })
      this.status(id, status, error instanceof Error ? error.message : 'request failed')
    }
    finally {
      this.pending--
    }
  }

  private async handleRequest(type: number, id: number, reader: SshReader): Promise<void> {
    switch (type) {
      case SFTP.REALPATH: {
        const path = await this.fs.realpath(reader.utf8())
        this.name(id, [{ filename: path, longname: path, attributes: {} }])
        return
      }

      case SFTP.STAT:
      case SFTP.LSTAT: {
        const path = reader.utf8()
        const attributes = type === SFTP.STAT ? await this.fs.stat(path) : await this.fs.lstat(path)
        this.reply(writeAttributes(new SshWriter().byte(SFTP.ATTRS).uint32(id), attributes).toBuffer())
        return
      }

      case SFTP.FSTAT: {
        const entry = this.handleFor(reader.utf8())
        if (entry.kind !== 'file') throw new Error('sftp: fstat on a directory handle')
        const attributes = await this.fs.fstat(entry.handle)
        this.reply(writeAttributes(new SshWriter().byte(SFTP.ATTRS).uint32(id), attributes).toBuffer())
        return
      }

      case SFTP.OPEN: {
        const path = reader.utf8()
        const flags = parseOpenFlags(reader.uint32())
        const attributes = readAttributes(reader)
        const handle = await this.fs.open(path, flags, attributes)
        this.reply(new SshWriter().byte(SFTP.HANDLE).uint32(id).string(this.track({ kind: 'file', handle })).toBuffer())
        return
      }

      case SFTP.CLOSE: {
        const handleId = reader.utf8()
        const entry = this.handleFor(handleId)
        this.handles.delete(handleId)
        await this.fs.close(entry.handle)
        this.ok(id)
        return
      }

      case SFTP.READ: {
        const entry = this.handleFor(reader.utf8())
        if (entry.kind !== 'file') throw new Error('sftp: read on a directory handle')
        const offset = Number(reader.uint64())
        const length = Math.min(reader.uint32(), MAX_READ_LENGTH)
        const data = await this.fs.read(entry.handle, offset, length)

        if (!data || data.length === 0) {
          this.status(id, SFTP_STATUS.EOF, 'end of file')
          return
        }
        this.reply(new SshWriter().byte(SFTP.DATA).uint32(id).string(data).toBuffer())
        return
      }

      case SFTP.WRITE: {
        const entry = this.handleFor(reader.utf8())
        if (entry.kind !== 'file') throw new Error('sftp: write on a directory handle')
        const offset = Number(reader.uint64())
        await this.fs.write(entry.handle, offset, reader.string())
        this.ok(id)
        return
      }

      case SFTP.OPENDIR: {
        const handle = await this.fs.opendir(reader.utf8())
        this.reply(
          new SshWriter().byte(SFTP.HANDLE).uint32(id).string(this.track({ kind: 'directory', handle })).toBuffer(),
        )
        return
      }

      case SFTP.READDIR: {
        const entry = this.handleFor(reader.utf8())
        if (entry.kind !== 'directory') throw new Error('sftp: readdir on a file handle')
        const entries = await this.fs.readdir(entry.handle)

        if (!entries || entries.length === 0) {
          this.status(id, SFTP_STATUS.EOF, 'end of directory')
          return
        }
        this.name(id, entries)
        return
      }

      case SFTP.REMOVE: {
        await this.fs.remove(reader.utf8())
        this.ok(id)
        return
      }

      case SFTP.MKDIR: {
        const path = reader.utf8()
        await this.fs.mkdir(path, readAttributes(reader))
        this.ok(id)
        return
      }

      case SFTP.RMDIR: {
        await this.fs.rmdir(reader.utf8())
        this.ok(id)
        return
      }

      case SFTP.RENAME: {
        const from = reader.utf8()
        await this.fs.rename(from, reader.utf8())
        this.ok(id)
        return
      }

      case SFTP.SETSTAT: {
        const path = reader.utf8()
        await this.fs.setstat(path, readAttributes(reader))
        this.ok(id)
        return
      }

      case SFTP.FSETSTAT: {
        const entry = this.handleFor(reader.utf8())
        if (entry.kind !== 'file') throw new Error('sftp: fsetstat on a directory handle')
        await this.fs.fsetstat(entry.handle, readAttributes(reader))
        this.ok(id)
        return
      }

      case SFTP.READLINK: {
        if (!this.fs.readlink) {
          this.status(id, SFTP_STATUS.OP_UNSUPPORTED, 'readlink is not supported')
          return
        }
        const target = await this.fs.readlink(reader.utf8())
        this.name(id, [{ filename: target, longname: target, attributes: {} }])
        return
      }

      case SFTP.SYMLINK: {
        if (!this.fs.symlink) {
          this.status(id, SFTP_STATUS.OP_UNSUPPORTED, 'symlink is not supported')
          return
        }
        // OpenSSH sends target first, then the link path.
        const target = reader.utf8()
        await this.fs.symlink(target, reader.utf8())
        this.ok(id)
        return
      }

      default:
        this.status(id, SFTP_STATUS.OP_UNSUPPORTED, `unsupported request type ${type}`)
    }
  }

  private name(id: number, entries: SftpDirectoryEntry[]): void {
    const writer = new SshWriter().byte(SFTP.NAME).uint32(id).uint32(entries.length)

    for (const entry of entries) {
      writer.string(entry.filename)
      writer.string(entry.longname ?? formatLongname(entry.filename, entry.attributes))
      writeAttributes(writer, entry.attributes)
    }

    this.reply(writer.toBuffer())
  }
}
