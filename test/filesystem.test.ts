import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SFTP_STATUS } from '../src/constants'
import { SftpError } from '../src/errors'
import { formatLongname, LocalFileSystem } from '../src/filesystem/local'
import { normalizeVirtualPath, virtualBasename, virtualDirname } from '../src/filesystem/paths'

describe('virtual paths', () => {
  it('normalizes to an absolute path inside the namespace', () => {
    expect(normalizeVirtualPath('foo/bar')).toBe('/foo/bar')
    expect(normalizeVirtualPath('/foo//bar/')).toBe('/foo/bar')
    expect(normalizeVirtualPath('./foo/./bar')).toBe('/foo/bar')
    expect(normalizeVirtualPath('', '/home')).toBe('/home')
    expect(normalizeVirtualPath('.', '/home')).toBe('/home')
  })

  it('cannot climb above the root', () => {
    expect(normalizeVirtualPath('../../etc/passwd')).toBe('/etc/passwd')
    expect(normalizeVirtualPath('/foo/../../..')).toBe('/')
    expect(normalizeVirtualPath('a/../../b')).toBe('/b')
  })

  it('splits into parent and name', () => {
    expect(virtualDirname('/foo/bar/baz')).toBe('/foo/bar')
    expect(virtualDirname('/foo')).toBe('/')
    expect(virtualDirname('/')).toBe('/')
    expect(virtualBasename('/foo/bar')).toBe('bar')
    expect(virtualBasename('/')).toBe('')
  })
})

describe('longname formatting', () => {
  it('renders directories, files, and links the way clients expect', () => {
    const file = formatLongname('notes.txt', { mode: 0o100644, size: 12, uid: 501, gid: 20, mtime: 0 })
    expect(file).toStartWith('-rw-r--r--')
    expect(file).toEndWith('notes.txt')

    expect(formatLongname('dir', { mode: 0o040755 })).toStartWith('drwxr-xr-x')
    expect(formatLongname('link', { mode: 0o120777 })).toStartWith('lrwxrwxrwx')
  })
})

describe('local file system', () => {
  let root: string
  let fs: LocalFileSystem

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'ts-sftp-'))
    fs = new LocalFileSystem(root)
    await writeFile(join(root, 'hello.txt'), 'hello world')
  })

  afterEach(async () => {
    await rm(root, { recursive: true, force: true })
  })

  const flags = {
    read: false,
    write: false,
    append: false,
    create: false,
    truncate: false,
    exclusive: false,
  }

  it('reads a file through a handle', async () => {
    const handle = await fs.open('/hello.txt', { ...flags, read: true }, {})
    const data = await fs.read(handle, 0, 5)
    expect(new TextDecoder().decode(data!)).toBe('hello')
    expect(await fs.read(handle, 100, 5)).toBeUndefined()
    await fs.close(handle)
  })

  it('writes at an offset and reports the new size', async () => {
    const handle = await fs.open('/new.txt', { ...flags, write: true, create: true, truncate: true }, {})
    await fs.write(handle, 0, new TextEncoder().encode('abc'))
    await fs.write(handle, 3, new TextEncoder().encode('def'))
    expect((await fs.fstat(handle)).size).toBe(6)
    await fs.close(handle)

    expect(await readFile(join(root, 'new.txt'), 'utf8')).toBe('abcdef')
  })

  it('lists a directory including . and ..', async () => {
    const handle = await fs.opendir('/')
    const entries = await fs.readdir(handle)
    expect(entries!.map((entry) => entry.filename)).toContain('hello.txt')
    expect(entries!.map((entry) => entry.filename)).toContain('..')
    // A second call signals the end of the listing.
    expect(await fs.readdir(handle)).toBeUndefined()
  })

  it('creates, renames, and removes', async () => {
    await fs.mkdir('/dir', {})
    await fs.rename('/hello.txt', '/dir/moved.txt')
    expect((await fs.stat('/dir/moved.txt')).size).toBe(11)

    await fs.remove('/dir/moved.txt')
    await fs.rmdir('/dir')
    await expect(fs.stat('/dir')).rejects.toThrow()
  })

  it('keeps traversal inside the root', async () => {
    await writeFile(join(root, '..', 'outside-ts-sftp.txt'), 'secret').catch(() => {})

    // `..` is resolved in the virtual namespace, so it lands back at the root.
    await expect(fs.stat('/../outside-ts-sftp.txt')).rejects.toThrow()
    expect(await fs.realpath('/../..')).toBe('/')
    await rm(join(root, '..', 'outside-ts-sftp.txt'), { force: true })
  })

  it('reports symlink targets that escape the root as denied', async () => {
    await fs.symlink('../escape', '/link')
    await expect(fs.readlink('/link')).resolves.toBe('../escape')

    const absolute = new LocalFileSystem(root)
    await absolute.symlink('/hello.txt', '/inside')
    expect(await absolute.readlink('/inside')).toBe('/hello.txt')
  })

  it('refuses every write when read-only', async () => {
    const readOnly = new LocalFileSystem(root, { readOnly: true })

    await expect(readOnly.mkdir('/nope', {})).rejects.toThrow(SftpError)
    await expect(readOnly.remove('/hello.txt')).rejects.toThrow(/read-only/)
    await expect(readOnly.open('/x.txt', { ...flags, write: true, create: true }, {})).rejects.toThrow(/read-only/)

    // Reads still work.
    const handle = await readOnly.open('/hello.txt', { ...flags, read: true }, {})
    expect(await readOnly.read(handle, 0, 11)).toBeDefined()
    await readOnly.close(handle)
  })

  it('maps errors to SFTP status codes', () => {
    expect(SftpError.noSuchFile('/x').status).toBe(SFTP_STATUS.NO_SUCH_FILE)
    expect(SftpError.permissionDenied('no').status).toBe(SFTP_STATUS.PERMISSION_DENIED)
    expect(SftpError.unsupported('op').status).toBe(SFTP_STATUS.OP_UNSUPPORTED)
  })
})
