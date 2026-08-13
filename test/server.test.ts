/**
 * End-to-end tests: a real server, driven by the system's OpenSSH `sftp`
 * client. If the client is not installed the suite is skipped rather than
 * silently passing.
 */

import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateHostKeyFiles } from '../src/keys'
import { SftpServer } from '../src/server'

async function hasSftpClient(): Promise<boolean> {
  try {
    return (await Bun.$`which sftp`.quiet().nothrow()).exitCode === 0
  }
  catch {
    return false
  }
}

const clientAvailable = await hasSftpClient()

describe.skipIf(!clientAvailable)('server (OpenSSH client)', () => {
  let workspace: string
  let root: string
  let userKey: string
  let server: SftpServer
  let port: number

  /** Run a batch of sftp commands against the server. */
  async function sftp(commands: string[], user = 'deploy'): Promise<{ stdout: string; exitCode: number }> {
    const batch = join(workspace, `batch-${Math.random().toString(36).slice(2)}.txt`)
    await writeFile(batch, `${commands.join('\n')}\n`)

    const result = await Bun.$`sftp -b ${batch} -P ${port} -i ${userKey} \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \
      ${`${user}@127.0.0.1`}`
      .cwd(workspace)
      .quiet()
      .nothrow()

    return { stdout: result.stdout.toString() + result.stderr.toString(), exitCode: result.exitCode }
  }

  beforeAll(async () => {
    workspace = await mkdtemp(join(tmpdir(), 'ts-sftp-e2e-'))
    root = join(workspace, 'served')
    await mkdir(join(root, 'nested'), { recursive: true })
    await writeFile(join(root, 'readme.txt'), 'hello from ts-sftp')
    await writeFile(join(root, 'nested', 'inner.txt'), 'nested file')

    // A client key pair, generated with our own code rather than ssh-keygen.
    const client = generateHostKeyFiles('client')
    userKey = join(workspace, 'client_key')
    await writeFile(userKey, client.privateKey, { mode: 0o600 })
    await chmod(userKey, 0o600)

    const host = generateHostKeyFiles('host')

    server = new SftpServer({
      port: 0,
      hostname: '127.0.0.1',
      hostKeys: [host.privateKey],
      root,
      users: {
        deploy: { publicKeys: [client.publicKey] },
        viewer: { publicKeys: [client.publicKey], readOnly: true },
      },
      logger: {},
    })
    port = server.listen().port
  })

  afterAll(async () => {
    await server.stop()
    await rm(workspace, { recursive: true, force: true })
  })

  it('authenticates with a public key and lists the root', async () => {
    const result = await sftp(['pwd', 'ls'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('readme.txt')
    expect(result.stdout).toContain('Remote working directory: /')
  })

  it('rejects a user that is not configured', async () => {
    const result = await sftp(['pwd'], 'nobody')
    expect(result.exitCode).not.toBe(0)
    expect(result.stdout).toMatch(/Permission denied|Authentication failed/i)
  })

  it('downloads a file byte for byte', async () => {
    const result = await sftp(['get readme.txt fetched.txt'])
    expect(result.exitCode).toBe(0)
    expect(await readFile(join(workspace, 'fetched.txt'), 'utf8')).toBe('hello from ts-sftp')
  })

  it('uploads a megabyte and reads it back unchanged', async () => {
    const payload = new Uint8Array(1024 * 1024)
    crypto.getRandomValues(payload)
    await writeFile(join(workspace, 'upload.bin'), payload)

    const result = await sftp(['put upload.bin uploaded.bin', 'get uploaded.bin roundtrip.bin'])
    expect(result.exitCode).toBe(0)

    const roundtrip = await readFile(join(workspace, 'roundtrip.bin'))
    expect(roundtrip.length).toBe(payload.length)
    expect(Buffer.compare(roundtrip, Buffer.from(payload))).toBe(0)
  })

  it('creates, renames, and removes directories and files', async () => {
    const result = await sftp([
      'mkdir uploads',
      'put upload.bin uploads/file.bin',
      'rename uploads/file.bin uploads/renamed.bin',
      'ls uploads',
      'rm uploads/renamed.bin',
      'rmdir uploads',
      'ls',
    ])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('renamed.bin')
    expect(result.stdout.split('\n').at(-2)).not.toContain('uploads')
  })

  it('serves nested directories', async () => {
    const result = await sftp(['cd nested', 'ls', 'get inner.txt inner.txt'])
    expect(result.exitCode).toBe(0)
    expect(await readFile(join(workspace, 'inner.txt'), 'utf8')).toBe('nested file')
  })

  it('refuses writes for a read-only user', async () => {
    const result = await sftp(['put upload.bin denied.bin'], 'viewer')
    expect(result.exitCode).not.toBe(0)
    expect(result.stdout).toMatch(/read-only|Permission denied/i)

    // Reading still works for the same user.
    const read = await sftp(['get readme.txt viewer.txt'], 'viewer')
    expect(read.exitCode).toBe(0)
  })

  it('keeps a client inside its root', async () => {
    const result = await sftp(['ls ../..'])
    // `..` resolves within the served namespace, so this lists the root itself.
    expect(result.stdout).toContain('readme.txt')
    expect(result.stdout).not.toContain('served')
  })
})
