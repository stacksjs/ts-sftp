/**
 * The CLI, run as a user runs it: as a subprocess, checking what it writes and
 * what it exits with.
 */

import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parsePublicKey } from '../src/keys'

const CLI = join(import.meta.dir, '..', 'bin', 'cli.ts')

async function run(args: string[], cwd: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const result = await Bun.$`bun ${CLI} ${args}`.cwd(cwd).quiet().nothrow()
  return {
    stdout: result.stdout.toString(),
    stderr: result.stderr.toString(),
    exitCode: result.exitCode,
  }
}

describe('ts-sftp cli', () => {
  let workspace: string

  beforeAll(async () => {
    workspace = await mkdtemp(join(tmpdir(), 'ts-sftp-cli-'))
  })

  afterAll(async () => {
    await rm(workspace, { recursive: true, force: true })
  })

  it('lists its commands', async () => {
    const result = await run(['--help'], workspace)
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('serve')
    expect(result.stdout).toContain('keygen')
  })

  it('documents the serve options', async () => {
    const result = await run(['serve', '--help'], workspace)
    expect(result.exitCode).toBe(0)
    for (const flag of ['--config', '--port', '--host', '--root', '--host-key', '--user', '--read-only', '--verbose'])
      expect(result.stdout).toContain(flag)
  })

  it('prints its version', async () => {
    const { version } = await import('../package.json')
    const result = await run(['--version'], workspace)
    expect(result.stdout).toContain(version)
  })

  it('generates a usable key pair with private-only permissions', async () => {
    const result = await run(['keygen', '--out', './host_key', '--comment', 'from-cli'], workspace)
    expect(result.exitCode).toBe(0)

    const privateKey = await readFile(join(workspace, 'host_key'), 'utf8')
    expect(privateKey).toStartWith('-----BEGIN OPENSSH PRIVATE KEY-----')
    expect((await stat(join(workspace, 'host_key'))).mode & 0o777).toBe(0o600)

    const publicKey = await readFile(join(workspace, 'host_key.pub'), 'utf8')
    expect(parsePublicKey(publicKey)?.comment).toBe('from-cli')
  })

  it('creates the directory a key is written into', async () => {
    const result = await run(['keygen', '--out', './nested/deep/host_key'], workspace)
    expect(result.exitCode).toBe(0)
    expect(await readFile(join(workspace, 'nested/deep/host_key.pub'), 'utf8')).toContain('ssh-ed25519')
  })

  it('refuses to serve with no users configured', async () => {
    const result = await run(['serve', '--root', '.', '--port', '0'], workspace)
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toContain('no users configured')
  })

  it('rejects a --user that is not name:path', async () => {
    const result = await run(['serve', '--user', 'nocolon', '--port', '0'], workspace)
    expect(result.exitCode).not.toBe(0)
    expect(`${result.stdout}${result.stderr}`).toContain('<name>:<authorized_keys path>')
  })

  it('accepts --user once and repeated', async () => {
    await run(['keygen', '--out', './alice'], workspace)
    await run(['keygen', '--out', './bob'], workspace)
    await writeFile(join(workspace, 'sftp.config.ts'), '')

    // The server holds the process open, so read its startup lines and stop it.
    const serve = Bun.spawn(
      ['bun', CLI, 'serve', '--root', '.', '--port', '0', '--user', 'alice:./alice.pub', '--user', 'bob:./bob.pub'],
      { cwd: workspace, stdout: 'pipe', stderr: 'pipe' },
    )

    // The stream stays open for as long as the server runs, so read it in
    // chunks until the line appears rather than waiting for it to end.
    const deadline = 10_000
    const reader = serve.stdout.getReader()
    const decoder = new TextDecoder()
    let started = ''

    while (!started.includes('users:')) {
      const chunk = await Promise.race([reader.read(), Bun.sleep(deadline).then(() => undefined)])
      if (!chunk || chunk.done) break
      started += decoder.decode(chunk.value, { stream: true })
    }

    reader.cancel().catch(() => undefined)
    serve.kill()

    expect(started).toContain('users: alice, bob')
  }, 30_000)
})
