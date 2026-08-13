/**
 * What the server does with input it did not ask for: garbage on the socket,
 * algorithms it does not speak, truncated packets, and oversized frames.
 *
 * The bar is that the connection dies and the process does not.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { MAX_PACKET_LENGTH, PacketCodec } from '../src/packet'
import { generateHostKeyFiles } from '../src/keys'
import { SftpServer } from '../src/server'
import { LocalFileSystem } from '../src/filesystem/local'
import { SftpSession } from '../src/sftp-session'
import { concat, SshWriter } from '../src/wire'

/** Open a socket, send bytes, and report what came back before it closed. */
async function speak(port: number, payloads: Uint8Array[]): Promise<{ received: Uint8Array; closed: boolean }> {
  let received: Uint8Array = new Uint8Array(0)
  let closed = false

  const socket = await Bun.connect({
    hostname: '127.0.0.1',
    port,
    socket: {
      data: (_socket, data) => {
        received = concat(received, new Uint8Array(data))
      },
      close: () => {
        closed = true
      },
      error: () => {
        closed = true
      },
    },
  })

  for (const payload of payloads) {
    socket.write(payload)
    await Bun.sleep(50)
  }

  await Bun.sleep(400)
  // Sample before hanging up: ending the socket ourselves would fire the same
  // close handler and make every case look like the server dropped us.
  const closedByServer = closed
  socket.end()
  return { received, closed: closedByServer }
}

describe('hostile input', () => {
  let server: SftpServer
  let port: number

  beforeAll(() => {
    server = new SftpServer({
      port: 0,
      hostname: '127.0.0.1',
      hostKeys: [generateHostKeyFiles('host').privateKey],
      users: {},
      logger: {},
    })
    port = server.listen().port
  })

  afterAll(async () => {
    await server.stop()
  })

  it('greets a client before it says anything', async () => {
    const { received } = await speak(port, [])
    expect(new TextDecoder().decode(received.subarray(0, 8))).toBe('SSH-2.0-')
  })

  it('hangs up on a non-SSH protocol version', async () => {
    const { closed } = await speak(port, [new TextEncoder().encode('SSH-1.5-ancient\r\n')])
    expect(closed).toBe(true)
  })

  it('survives random bytes in place of a packet', async () => {
    const noise = new Uint8Array(512)
    crypto.getRandomValues(noise)

    const { closed } = await speak(port, [new TextEncoder().encode('SSH-2.0-noise\r\n'), noise])
    expect(closed).toBe(true)

    // The listener is still up for everyone else.
    const { received } = await speak(port, [])
    expect(new TextDecoder().decode(received.subarray(0, 8))).toBe('SSH-2.0-')
  })

  it('refuses a client with no algorithm in common', async () => {
    const codec = new PacketCodec()
    const kexInit = new SshWriter()
      .byte(20)
      .raw(new Uint8Array(16))
      .nameList(['diffie-hellman-group1-sha1'])
      .nameList(['ssh-dss'])
      .nameList(['3des-cbc'])
      .nameList(['3des-cbc'])
      .nameList(['hmac-md5'])
      .nameList(['hmac-md5'])
      .nameList(['none'])
      .nameList(['none'])
      .nameList([])
      .nameList([])
      .boolean(false)
      .uint32(0)
      .toBuffer()

    const { closed } = await speak(port, [
      new TextEncoder().encode('SSH-2.0-legacy\r\n'),
      codec.encode(kexInit),
    ])
    expect(closed).toBe(true)
  })

  it('rejects a packet that claims an impossible length', async () => {
    const huge = new Uint8Array(8)
    new DataView(huge.buffer).setUint32(0, MAX_PACKET_LENGTH * 4, false)

    const { closed } = await speak(port, [new TextEncoder().encode('SSH-2.0-liar\r\n'), huge])
    expect(closed).toBe(true)
  })

  it('waits rather than guessing on a truncated packet', async () => {
    const codec = new PacketCodec()
    const packet = codec.encode(new Uint8Array([21]))

    // Half a packet: the server should still be holding the connection open.
    const { closed } = await speak(port, [
      new TextEncoder().encode('SSH-2.0-slow\r\n'),
      packet.subarray(0, Math.floor(packet.length / 2)),
    ])
    expect(closed).toBe(false)
  })

  it('does not let an over-long identification string grow without bound', async () => {
    const flood = new TextEncoder().encode('x'.repeat(4096))
    const { closed } = await speak(port, [flood, flood])
    expect(closed).toBe(true)
  })
})

describe('hostile sftp requests', () => {
  let root: string
  let session: SftpSession
  let replies: Uint8Array[]

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'ts-sftp-hostile-'))
    await writeFile(join(root, 'file.txt'), 'content')
  })

  beforeEach(() => {
    replies = []
    session = new SftpSession(new LocalFileSystem(root), (data) => replies.push(data))
  })

  afterEach(async () => {
    await session.close()
  })

  afterAll(async () => {
    await rm(root, { recursive: true, force: true })
  })

  it('rejects a frame longer than any request can be', async () => {
    const bogus = new SshWriter().uint32(64 * 1024 * 1024).byte(3).toBuffer()
    await expect(session.receive(bogus)).rejects.toThrow(/invalid packet length/)
  })

  it('rejects a zero-length frame', async () => {
    await expect(session.receive(new SshWriter().uint32(0).toBuffer())).rejects.toThrow(/invalid packet length/)
  })

  it('raises a framing error once rather than on every later byte', async () => {
    const bogus = new SshWriter().uint32(64 * 1024 * 1024).byte(3).toBuffer()
    await expect(session.receive(bogus)).rejects.toThrow(/invalid packet length/)

    // The poisoned bytes are gone, so a well-formed request is answered again.
    const packet = new SshWriter().byte(16).uint32(1).string('.').toBuffer()
    await session.receive(concat(new SshWriter().uint32(packet.length).toBuffer(), packet))
    expect(replies).toHaveLength(1)
  })

  it('answers a request for an unknown handle with a status, not a crash', async () => {
    replies = []
    const packet = new SshWriter().byte(4).uint32(7).string('not-a-handle').toBuffer()
    await session.receive(concat(new SshWriter().uint32(packet.length).toBuffer(), packet))

    expect(replies).toHaveLength(1)
    // 101 is SSH_FXP_STATUS; the request id follows.
    expect(replies[0]![4]).toBe(101)
  })

  it('answers a truncated request body with a status, not a crash', async () => {
    replies = []
    // An OPEN packet that stops before its flags.
    const packet = new SshWriter().byte(3).uint32(8).string('/file.txt').toBuffer()
    await session.receive(concat(new SshWriter().uint32(packet.length).toBuffer(), packet))

    expect(replies).toHaveLength(1)
    expect(replies[0]![4]).toBe(101)
  })
})
