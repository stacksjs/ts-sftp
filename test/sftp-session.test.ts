/**
 * Drives {@link SftpSession} with raw protocol packets — the same bytes a
 * client would send — and inspects the replies.
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SFTP, SFTP_ATTR, SFTP_OPEN, SFTP_STATUS, SFTP_VERSION } from '../src/constants'
import { LocalFileSystem } from '../src/filesystem/local'
import { parseOpenFlags, SftpSession } from '../src/sftp-session'
import { concat, SshReader, SshWriter } from '../src/wire'

/** Frame a request the way the channel does: uint32 length, then the packet. */
function frame(build: (writer: SshWriter) => SshWriter): Uint8Array {
  const packet = build(new SshWriter()).toBuffer()
  return concat(new SshWriter().uint32(packet.length).toBuffer(), packet)
}

describe('sftp session', () => {
  let root: string
  let session: SftpSession
  let replies: Uint8Array[]

  /** Send a request and return the reader positioned after the packet type. */
  async function request(build: (writer: SshWriter) => SshWriter): Promise<{ type: number; reader: SshReader }> {
    replies = []
    await session.receive(frame(build))
    const reply = replies.at(-1)!
    const reader = new SshReader(reply, 4)
    return { type: reader.byte(), reader }
  }

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'ts-sftp-session-'))
    await writeFile(join(root, 'readme.txt'), 'hello sftp')
    replies = []
    session = new SftpSession(new LocalFileSystem(root), (data) => replies.push(data))
  })

  afterEach(async () => {
    await session.close()
    await rm(root, { recursive: true, force: true })
  })

  it('answers INIT with its version', async () => {
    const { type, reader } = await request((writer) => writer.byte(SFTP.INIT).uint32(3))
    expect(type).toBe(SFTP.VERSION)
    expect(reader.uint32()).toBe(SFTP_VERSION)
  })

  it('resolves the working directory to the session root', async () => {
    const { type, reader } = await request((writer) => writer.byte(SFTP.REALPATH).uint32(1).string('.'))
    expect(type).toBe(SFTP.NAME)
    reader.uint32() // request id
    expect(reader.uint32()).toBe(1)
    expect(reader.utf8()).toBe('/')
  })

  it('stats a file', async () => {
    const { type, reader } = await request((writer) => writer.byte(SFTP.STAT).uint32(2).string('/readme.txt'))
    expect(type).toBe(SFTP.ATTRS)
    reader.uint32()
    const flags = reader.uint32()
    expect(flags & SFTP_ATTR.SIZE).toBeTruthy()
    expect(Number(reader.uint64())).toBe(10)
  })

  it('reads a file and reports EOF past its end', async () => {
    const opened = await request((writer) =>
      writer.byte(SFTP.OPEN).uint32(3).string('/readme.txt').uint32(SFTP_OPEN.READ).uint32(0),
    )
    expect(opened.type).toBe(SFTP.HANDLE)
    opened.reader.uint32()
    const handle = opened.reader.utf8()

    const data = await request((writer) =>
      writer.byte(SFTP.READ).uint32(4).string(handle).uint64(0).uint32(1024),
    )
    expect(data.type).toBe(SFTP.DATA)
    data.reader.uint32()
    expect(new TextDecoder().decode(data.reader.string())).toBe('hello sftp')

    const eof = await request((writer) => writer.byte(SFTP.READ).uint32(5).string(handle).uint64(100).uint32(10))
    expect(eof.type).toBe(SFTP.STATUS)
    eof.reader.uint32()
    expect(eof.reader.uint32()).toBe(SFTP_STATUS.EOF)
  })

  it('writes a new file through open, write, close', async () => {
    const flags = SFTP_OPEN.WRITE | SFTP_OPEN.CREAT | SFTP_OPEN.TRUNC
    const opened = await request((writer) => writer.byte(SFTP.OPEN).uint32(6).string('/out.txt').uint32(flags).uint32(0))
    opened.reader.uint32()
    const handle = opened.reader.utf8()

    const written = await request((writer) =>
      writer.byte(SFTP.WRITE).uint32(7).string(handle).uint64(0).string('written by the test'),
    )
    written.reader.uint32()
    expect(written.reader.uint32()).toBe(SFTP_STATUS.OK)

    const closed = await request((writer) => writer.byte(SFTP.CLOSE).uint32(8).string(handle))
    closed.reader.uint32()
    expect(closed.reader.uint32()).toBe(SFTP_STATUS.OK)

    expect(await Bun.file(join(root, 'out.txt')).text()).toBe('written by the test')
  })

  it('lists a directory once, then reports EOF', async () => {
    const opened = await request((writer) => writer.byte(SFTP.OPENDIR).uint32(9).string('/'))
    opened.reader.uint32()
    const handle = opened.reader.utf8()

    const listing = await request((writer) => writer.byte(SFTP.READDIR).uint32(10).string(handle))
    expect(listing.type).toBe(SFTP.NAME)
    listing.reader.uint32()
    const count = listing.reader.uint32()
    const names: string[] = []
    for (let i = 0; i < count; i++) {
      names.push(listing.reader.utf8())
      listing.reader.utf8() // longname
      // Skip the attributes for this entry.
      const flags = listing.reader.uint32()
      if (flags & SFTP_ATTR.SIZE) listing.reader.uint64()
      if (flags & SFTP_ATTR.UIDGID) {
        listing.reader.uint32()
        listing.reader.uint32()
      }
      if (flags & SFTP_ATTR.PERMISSIONS) listing.reader.uint32()
      if (flags & SFTP_ATTR.ACMODTIME) {
        listing.reader.uint32()
        listing.reader.uint32()
      }
    }
    expect(names).toContain('readme.txt')

    const end = await request((writer) => writer.byte(SFTP.READDIR).uint32(11).string(handle))
    end.reader.uint32()
    expect(end.reader.uint32()).toBe(SFTP_STATUS.EOF)
  })

  it('reports a missing file as NO_SUCH_FILE rather than a generic failure', async () => {
    const { type, reader } = await request((writer) =>
      writer.byte(SFTP.OPEN).uint32(12).string('/missing.txt').uint32(SFTP_OPEN.READ).uint32(0),
    )
    expect(type).toBe(SFTP.STATUS)
    reader.uint32()
    expect(reader.uint32()).toBe(SFTP_STATUS.NO_SUCH_FILE)
  })

  it('answers an unknown request type with OP_UNSUPPORTED', async () => {
    const { type, reader } = await request((writer) => writer.byte(199).uint32(13))
    expect(type).toBe(SFTP.STATUS)
    reader.uint32()
    expect(reader.uint32()).toBe(SFTP_STATUS.OP_UNSUPPORTED)
  })

  it('reassembles requests split across channel reads', async () => {
    const packet = frame((writer) => writer.byte(SFTP.REALPATH).uint32(14).string('/'))
    replies = []

    await session.receive(packet.subarray(0, 3))
    expect(replies).toHaveLength(0)
    await session.receive(packet.subarray(3, 9))
    expect(replies).toHaveLength(0)
    await session.receive(packet.subarray(9))
    expect(replies).toHaveLength(1)
  })

  it('handles two requests arriving in one read', async () => {
    replies = []
    await session.receive(
      concat(
        frame((writer) => writer.byte(SFTP.REALPATH).uint32(15).string('/')),
        frame((writer) => writer.byte(SFTP.REALPATH).uint32(16).string('/')),
      ),
    )
    expect(replies).toHaveLength(2)
  })

  it('translates open flags', () => {
    expect(parseOpenFlags(SFTP_OPEN.READ)).toMatchObject({ read: true, write: false })
    expect(parseOpenFlags(SFTP_OPEN.WRITE | SFTP_OPEN.APPEND | SFTP_OPEN.CREAT)).toMatchObject({
      write: true,
      append: true,
      create: true,
      exclusive: false,
    })
  })
})
