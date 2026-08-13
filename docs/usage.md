# Usage

## Serve a directory

Generate a host key once, then serve:

```bash
ts-sftp keygen --out ./host_key
ts-sftp serve --root ./uploads --host-key ./host_key --user deploy:./deploy.pub
```

`--user` takes a name and the path to an `authorized_keys` file, and can be
repeated for as many users as you need. Without `--host-key` a key is generated
in memory, which means a new fingerprint on every restart — fine for a local
try, wrong for anything a client trusts.

Connect with any SFTP client:

```bash
sftp -P 2222 -i ~/.ssh/id_ed25519 deploy@localhost
```

## Embed the server

```ts
import { SftpServer } from 'ts-sftp'

const server = new SftpServer({
  port: 2222,
  hostKeys: [await Bun.file('./host_key').text()],
  root: './uploads',
  users: {
    deploy: { publicKeys: [await Bun.file('./deploy.pub').text()] },
    viewer: { publicKeys: [await Bun.file('./viewer.pub').text()], readOnly: true },
  },
})

const running = server.listen()
console.log(`ts-sftp on ${running.hostname}:${running.port}`)
```

`listen()` returns the bound port, which is how you get the real port when you
pass `port: 0`.

## Authenticate against your own system

`authenticate` runs after the signature check, so a `true` return means the key
is genuine as well as allowed:

```ts
new SftpServer({
  users: { deploy: { publicKeys: [...] } },
  authenticate: async ({ username, method, publicKey, remoteAddress }) => {
    if (method !== 'publickey' || !publicKey) return false
    return await accountIsActive(username, remoteAddress)
  },
})
```

## Serve something other than disk

A session's storage is an `SftpFileSystem`. Implement it to serve object
storage, a database, or a synthetic tree:

```ts
import type { SftpFileSystem } from 'ts-sftp'

new SftpServer({
  createFileSystem: ({ username }): SftpFileSystem => storageFor(username),
})
```

The built-in `LocalFileSystem` is a normal implementation of the same
interface, so it is worth reading as a reference — including how it keeps
paths inside the served root.

## Run it as a service

```ini
# /etc/systemd/system/ts-sftp.service
[Unit]
Description=ts-sftp
After=network.target

[Service]
ExecStart=/usr/local/bin/ts-sftp serve --config /etc/ts-sftp/sftp.config.ts
Restart=always
User=sftp

[Install]
WantedBy=multi-user.target
```
