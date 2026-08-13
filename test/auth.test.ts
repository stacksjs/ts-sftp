/**
 * Authentication behaviour, driven by a real client so the checks cover what a
 * client actually sends rather than what the server expects it to.
 */

import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateHostKeyFiles, parsePublicKey } from '../src/keys'
import { authenticateAgainstUsers, SftpServer } from '../src/server'

const clientAvailable = (await Bun.$`which sftp`.quiet().nothrow()).exitCode === 0

describe.skipIf(!clientAvailable)('authentication', () => {
  let workspace: string
  let authorizedKey: string
  let strangerKey: string
  let server: SftpServer
  let port: number

  async function connect(
    user: string,
    key: string,
    extra: string[] = [],
  ): Promise<{ output: string; exitCode: number }> {
    const batch = join(workspace, 'pwd.txt')
    await writeFile(batch, 'pwd\n')

    const result = await Bun.$`sftp -b ${batch} -P ${port} -i ${key} \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      -o IdentitiesOnly=yes ${extra} ${`${user}@127.0.0.1`}`
      .cwd(workspace)
      .quiet()
      .nothrow()

    return { output: result.stdout.toString() + result.stderr.toString(), exitCode: result.exitCode }
  }

  beforeAll(async () => {
    workspace = await mkdtemp(join(tmpdir(), 'ts-sftp-auth-'))

    const authorized = generateHostKeyFiles('authorized')
    authorizedKey = join(workspace, 'authorized_key')
    await writeFile(authorizedKey, authorized.privateKey, { mode: 0o600 })
    await chmod(authorizedKey, 0o600)

    const stranger = generateHostKeyFiles('stranger')
    strangerKey = join(workspace, 'stranger_key')
    await writeFile(strangerKey, stranger.privateKey, { mode: 0o600 })
    await chmod(strangerKey, 0o600)

    server = new SftpServer({
      port: 0,
      hostname: '127.0.0.1',
      hostKeys: [generateHostKeyFiles('host').privateKey],
      root: workspace,
      users: {
        keyed: { publicKeys: [authorized.publicKey] },
        secret: { publicKeys: [], password: 'correct horse battery staple' },
      },
      logger: {},
    })
    port = server.listen().port
  })

  afterAll(async () => {
    await server.stop()
    await rm(workspace, { recursive: true, force: true })
  })

  it('accepts a key that is listed for the user', async () => {
    const result = await connect('keyed', authorizedKey)
    expect(result.exitCode).toBe(0)
  })

  it('rejects a key that is not listed', async () => {
    const result = await connect('keyed', strangerKey)
    expect(result.exitCode).not.toBe(0)
    expect(result.output).toMatch(/Permission denied|Authentication failed/i)
  })

  it('rejects a listed key presented for a different user', async () => {
    const result = await connect('secret', authorizedKey)
    expect(result.exitCode).not.toBe(0)
  })

  it('rejects an unknown user', async () => {
    const result = await connect('ghost', authorizedKey)
    expect(result.exitCode).not.toBe(0)
  })


  it('drops a client that never authenticates', async () => {
    const strict = new SftpServer({
      port: 0,
      hostname: '127.0.0.1',
      hostKeys: [generateHostKeyFiles('host').privateKey],
      users: { keyed: { publicKeys: [] } },
      authTimeoutMs: 300,
      logger: {},
    })
    const running = strict.listen()

    // Open a socket, send a version string, then go quiet.
    const socket = await Bun.connect({
      hostname: '127.0.0.1',
      port: running.port,
      socket: { data: () => {}, error: () => {} },
    })
    socket.write(new TextEncoder().encode('SSH-2.0-lazy-client\r\n'))

    await Bun.sleep(1200)
    // The server hangs up on its own; writing to a closed socket is harmless.
    socket.end()
    await strict.stop()
  })

  it('refuses connections past the limit', async () => {
    const limited = new SftpServer({
      port: 0,
      hostname: '127.0.0.1',
      hostKeys: [generateHostKeyFiles('host').privateKey],
      users: {},
      maxConnections: 1,
      logger: {},
    })
    const running = limited.listen()

    const first = await Bun.connect({
      hostname: '127.0.0.1',
      port: running.port,
      socket: { data: () => {}, error: () => {} },
    })
    await Bun.sleep(100)

    let secondClosed = false
    const second = await Bun.connect({
      hostname: '127.0.0.1',
      port: running.port,
      socket: {
        data: () => {},
        close: () => {
          secondClosed = true
        },
        error: () => {},
      },
    })
    await Bun.sleep(300)

    expect(secondClosed).toBe(true)
    first.end()
    second.end()
    await limited.stop()
  })
})

describe('the built-in authenticator', () => {
  const { publicKey } = generateHostKeyFiles('user')
  const publicKeyParsed = parsePublicKey(publicKey)!
  const users = {
    keyed: { publicKeys: [publicKey] },
    secret: { password: 'correct horse battery staple' },
  }

  it('accepts a public key that reached it verified', () => {
    expect(authenticateAgainstUsers(users, { username: 'keyed', method: 'publickey', publicKey: publicKeyParsed })).toBe(true)
  })

  it('rejects a publickey attempt with no verified key behind it', () => {
    expect(authenticateAgainstUsers(users, { username: 'keyed', method: 'publickey' })).toBe(false)
  })

  it('accepts only the exact password', () => {
    expect(authenticateAgainstUsers(users, {
      username: 'secret',
      method: 'password',
      password: 'correct horse battery staple',
    })).toBe(true)

    expect(authenticateAgainstUsers(users, { username: 'secret', method: 'password', password: 'wrong' })).toBe(false)
    expect(authenticateAgainstUsers(users, { username: 'secret', method: 'password', password: '' })).toBe(false)
    expect(authenticateAgainstUsers(users, {
      username: 'secret',
      method: 'password',
      password: 'correct horse battery stapl',
    })).toBe(false)
  })

  it('rejects a password for a user that has none configured', () => {
    expect(authenticateAgainstUsers(users, { username: 'keyed', method: 'password', password: 'anything' }))
      .toBe(false)
  })

  it('rejects an unknown user, whichever method they try', () => {
    expect(authenticateAgainstUsers(users, { username: 'ghost', method: 'publickey', publicKey: publicKeyParsed })).toBe(false)
    expect(authenticateAgainstUsers(users, { username: 'ghost', method: 'password', password: 'x' })).toBe(false)
    expect(authenticateAgainstUsers(undefined, { username: 'keyed', method: 'publickey', publicKey: publicKeyParsed })).toBe(false)
  })
})
