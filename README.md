# ts-sftp

An SFTP server for Bun, with no dependencies.

The SSH transport, key exchange, public key authentication, and the SFTP
subsystem are implemented in TypeScript on top of `node:crypto` — nothing else
is installed, nothing native is compiled, and the whole thing runs anywhere Bun
runs.

## Features

- **SSH transport** — `curve25519-sha256` key exchange, Ed25519 host keys,
  `aes256-gcm@openssh.com` encryption, and OpenSSH's strict KEX extension
- **Public key auth** — Ed25519 and RSA (`rsa-sha2-256`/`512`) user keys, read
  straight from `authorized_keys` lines
- **SFTP v3** — what every client speaks, including the OpenSSH `sftp` command,
  FileZilla, Cyberduck, and WinSCP
- **Per-user roots** — each user is chrooted to their own directory, with `..`
  resolved inside that namespace so it cannot climb out
- **Pluggable storage** — implement `SftpFileSystem` to serve something other
  than local disk (object storage, a database, a virtual tree)
- **Read-only mode** — per server or per user

## Install

```bash
bun add ts-sftp
```

## Quick start

Generate a host key and serve a directory:

```bash
bunx ts-sftp keygen --out ./host_key
bunx ts-sftp serve --root ./uploads --host-key ./host_key --user deploy:./deploy.pub
```

Then connect with any client:

```bash
sftp -P 2222 -i ~/.ssh/id_ed25519 deploy@localhost
```

## Library

```ts
import { SftpServer } from 'ts-sftp'

const server = new SftpServer({
  port: 2222,
  hostKeys: [await Bun.file('./host_key').text()],
  users: {
    deploy: {
      publicKeys: ['ssh-ed25519 AAAAC3Nz... deploy@example.com'],
      root: './uploads',
    },
    viewer: {
      publicKeys: [await Bun.file('./viewer.pub').text()],
      root: './uploads',
      readOnly: true,
    },
  },
})

const { port } = server.listen()
console.log(`listening on ${port}`)
```

### Custom authentication

`authenticate` runs after the signature has been verified, so a `true` return
means the key is genuine as well as accepted:

```ts
const server = new SftpServer({
  authenticate: async ({ username, method, publicKey }) => {
    if (method !== 'publickey' || !publicKey) return false
    return await isEnabled(username, publicKey.comment)
  },
})
```

### Custom storage

Any object implementing `SftpFileSystem` can back a session — the built-in
`LocalFileSystem` is one implementation, not a requirement:

```ts
import type { SftpFileSystem } from 'ts-sftp'
import { SftpServer } from 'ts-sftp'

const server = new SftpServer({
  createFileSystem: ({ username }): SftpFileSystem => bucketBackedFileSystem(username),
})
```

## CLI

```
ts-sftp serve [options]        Serve a directory over SFTP
ts-sftp keygen [options]       Generate an Ed25519 host key

Serve options:
  --config <path>              Config file (default: sftp.config.ts, if present)
  --port <port>                Port to listen on (default: 2222)
  --host <address>             Address to bind (default: 0.0.0.0)
  --root <dir>                 Directory to serve (default: the working directory)
  --host-key <path>            Host key file. Generated in memory when omitted
  --user <name>:<keys path>    Grant a user access using an authorized_keys file. Repeatable
  --read-only                  Reject every write
  --verbose                    Log each connection and request
```

## Config file

```ts
// sftp.config.ts
import { defineConfig } from 'ts-sftp'

export default defineConfig({
  port: 2222,
  root: './uploads',
  users: {
    deploy: { publicKeys: ['ssh-ed25519 AAAAC3Nz... deploy@example.com'] },
  },
})
```

## What it does not do

- No shells, no `exec`, no port forwarding — file transfer only, by design
- No password-by-default: passwords work if you configure one, keys are the
  path everything else assumes
- No SFTP v4-v6 extensions; version 3 is what clients negotiate in practice

## Testing

The suite includes end-to-end tests that drive the server with the system's own
OpenSSH `sftp` client, covering uploads, downloads, directory operations, and
the chroot boundary.

```bash
bun test
```

## License

MIT
