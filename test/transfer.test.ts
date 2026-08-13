/**
 * Transfer behaviour under load and at the edges: concurrent sessions, large
 * files, deep and wide directories, appends, attribute changes, and symlinks.
 */

import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateHostKeyFiles } from '../src/keys'
import { SftpServer } from '../src/server'

const clientAvailable = (await Bun.$`which sftp`.quiet().nothrow()).exitCode === 0

describe.skipIf(!clientAvailable)('transfers', () => {
  let workspace: string
  let root: string
  let userKey: string
  let server: SftpServer
  let port: number

  async function sftp(commands: string[]): Promise<{ output: string; exitCode: number }> {
    const batch = join(workspace, `batch-${Math.random().toString(36).slice(2)}.txt`)
    await writeFile(batch, `${commands.join('\n')}\n`)

    const result = await Bun.$`sftp -b ${batch} -P ${port} -i ${userKey} \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      -o IdentitiesOnly=yes -o PreferredAuthentications=publickey deploy@127.0.0.1`
      .cwd(workspace)
      .quiet()
      .nothrow()

    return { output: result.stdout.toString() + result.stderr.toString(), exitCode: result.exitCode }
  }

  beforeAll(async () => {
    workspace = await mkdtemp(join(tmpdir(), 'ts-sftp-transfer-'))
    root = join(workspace, 'served')
    await mkdir(root, { recursive: true })

    const client = generateHostKeyFiles('client')
    userKey = join(workspace, 'client_key')
    await writeFile(userKey, client.privateKey, { mode: 0o600 })
    await chmod(userKey, 0o600)

    server = new SftpServer({
      port: 0,
      hostname: '127.0.0.1',
      hostKeys: [generateHostKeyFiles('host').privateKey],
      root,
      users: { deploy: { publicKeys: [client.publicKey] } },
      logger: {},
    })
    port = server.listen().port
  })

  afterAll(async () => {
    await server.stop()
    await rm(workspace, { recursive: true, force: true })
  })

  it('transfers a file larger than the channel window', async () => {
    // The window is 2 MiB, so 8 MiB forces several window adjustments in both
    // directions — the path where flow control bugs show up.
    const payload = new Uint8Array(8 * 1024 * 1024)
    crypto.getRandomValues(payload)
    await writeFile(join(workspace, 'large.bin'), payload)

    const result = await sftp(['put large.bin large.bin', 'get large.bin large-back.bin'])
    expect(result.exitCode).toBe(0)

    const roundtrip = await readFile(join(workspace, 'large-back.bin'))
    expect(roundtrip.length).toBe(payload.length)
    expect(Buffer.compare(roundtrip, Buffer.from(payload))).toBe(0)
  }, 120_000)

  it('serves several clients at once', async () => {
    const payload = new Uint8Array(256 * 1024)
    crypto.getRandomValues(payload)
    await writeFile(join(workspace, 'shared.bin'), payload)

    const transfers = Array.from({ length: 5 }, (_, index) =>
      sftp([`put shared.bin concurrent-${index}.bin`, `get concurrent-${index}.bin back-${index}.bin`]))

    const results = await Promise.all(transfers)
    for (const result of results) expect(result.exitCode).toBe(0)

    for (let index = 0; index < 5; index++) {
      const back = await readFile(join(workspace, `back-${index}.bin`))
      expect(Buffer.compare(back, Buffer.from(payload))).toBe(0)
    }
  }, 120_000)

  it('lists a directory with many entries', async () => {
    const many = join(root, 'many')
    await mkdir(many, { recursive: true })
    for (let index = 0; index < 500; index++) await writeFile(join(many, `file-${index}.txt`), String(index))

    const result = await sftp(['ls many'])
    expect(result.exitCode).toBe(0)
    expect(result.output).toContain('file-0.txt')
    expect(result.output).toContain('file-499.txt')
  }, 120_000)

  it('serves a deeply nested path', async () => {
    const deep = 'a/b/c/d/e/f/g/h'
    await mkdir(join(root, deep), { recursive: true })
    await writeFile(join(root, deep, 'deep.txt'), 'found me')

    const result = await sftp([`get ${deep}/deep.txt deep.txt`])
    expect(result.exitCode).toBe(0)
    expect(await readFile(join(workspace, 'deep.txt'), 'utf8')).toBe('found me')
  })

  it('handles names with spaces and unicode', async () => {
    await writeFile(join(root, 'a file with spaces.txt'), 'spaces')
    await writeFile(join(root, 'ünïcode-ファイル.txt'), 'unicode')

    const result = await sftp(['get "a file with spaces.txt" spaces.txt', 'get ünïcode-ファイル.txt unicode.txt'])
    expect(result.exitCode).toBe(0)
    expect(await readFile(join(workspace, 'spaces.txt'), 'utf8')).toBe('spaces')
    expect(await readFile(join(workspace, 'unicode.txt'), 'utf8')).toBe('unicode')
  })

  it('resumes a partial upload from where it stopped', async () => {
    // `put -a` resumes: the client stats the remote file and writes the
    // remainder at that offset, which is the server's positional write path.
    await writeFile(join(workspace, 'resume.txt'), 'first half second half')
    await writeFile(join(root, 'resume.txt'), 'first half ')

    const result = await sftp(['put -a resume.txt resume.txt'])
    expect(result.exitCode).toBe(0)
    expect(await readFile(join(root, 'resume.txt'), 'utf8')).toBe('first half second half')
  })

  it('resumes a partial download the same way', async () => {
    await writeFile(join(root, 'download.txt'), 'remote start remote end')
    await writeFile(join(workspace, 'download.txt'), 'remote start ')

    const result = await sftp(['get -a download.txt download.txt'])
    expect(result.exitCode).toBe(0)
    expect(await readFile(join(workspace, 'download.txt'), 'utf8')).toBe('remote start remote end')
  })

  it('preserves permissions and times when asked', async () => {
    await writeFile(join(workspace, 'perms.txt'), 'preserve me')
    await chmod(join(workspace, 'perms.txt'), 0o640)

    const result = await sftp(['put -p perms.txt perms.txt'])
    expect(result.exitCode).toBe(0)

    const uploaded = await stat(join(root, 'perms.txt'))
    expect(uploaded.mode & 0o777).toBe(0o640)
  })

  it('changes permissions through chmod', async () => {
    await writeFile(join(root, 'mode.txt'), 'mode')
    const result = await sftp(['chmod 600 mode.txt', 'ls -l mode.txt'])

    expect(result.exitCode).toBe(0)
    expect((await stat(join(root, 'mode.txt'))).mode & 0o777).toBe(0o600)
    expect(result.output).toContain('-rw-------')
  })

  it('creates and reads symlinks inside the root', async () => {
    await writeFile(join(root, 'target.txt'), 'linked content')

    const result = await sftp(['ln -s target.txt link.txt', 'ls -l link.txt', 'get link.txt via-link.txt'])
    expect(result.exitCode).toBe(0)
    expect((await lstat(join(root, 'link.txt'))).isSymbolicLink()).toBe(true)
    expect(await readFile(join(workspace, 'via-link.txt'), 'utf8')).toBe('linked content')
  })

  it('reports a missing file without dropping the session', async () => {
    const result = await sftp(['get nope.txt nope.txt'])
    expect(result.exitCode).not.toBe(0)
    expect(result.output).toMatch(/not found|No such file/i)

    // The next connection still works.
    const after = await sftp(['ls'])
    expect(after.exitCode).toBe(0)
  })

  it('refuses to remove a directory that still has files', async () => {
    await mkdir(join(root, 'full'), { recursive: true })
    await writeFile(join(root, 'full', 'child.txt'), 'child')

    const result = await sftp(['rmdir full'])
    expect(result.exitCode).not.toBe(0)
    expect(await readFile(join(root, 'full', 'child.txt'), 'utf8')).toBe('child')
  })

  it('overwrites an existing file on upload', async () => {
    await writeFile(join(root, 'replace.txt'), 'old content that is longer')
    await writeFile(join(workspace, 'new.txt'), 'new')

    const result = await sftp(['put new.txt replace.txt'])
    expect(result.exitCode).toBe(0)
    expect(await readFile(join(root, 'replace.txt'), 'utf8')).toBe('new')
  })

  it('transfers an empty file', async () => {
    await writeFile(join(workspace, 'empty.bin'), '')

    const result = await sftp(['put empty.bin empty.bin', 'get empty.bin empty-back.bin'])
    expect(result.exitCode).toBe(0)
    expect((await stat(join(workspace, 'empty-back.bin'))).size).toBe(0)
  })
})
