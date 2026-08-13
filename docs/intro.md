# Introduction

`ts-sftp` is an SFTP server written in TypeScript for Bun. It implements the
SSH transport, key exchange, public key authentication, and the SFTP subsystem
directly, using only `node:crypto` — there is no dependency to audit, nothing
native to compile, and no `sshd` to configure alongside your app.

## Why run your own

A general-purpose SSH daemon gives users shell access you then have to take
away. `ts-sftp` starts from the other end: it serves files and nothing else.
There is no `exec`, no shell, and no port forwarding to disable, and each user
is confined to their own directory.

Because the file system behind a session is an interface, the same server can
put files on local disk, in object storage, or into whatever tree your
application already models.

## What it speaks

| Layer | Algorithms |
| --- | --- |
| Key exchange | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
| Host key | `ssh-ed25519` |
| Cipher | `aes256-gcm@openssh.com` |
| User keys | `ssh-ed25519`, `rsa-sha2-256`, `rsa-sha2-512` |
| Subsystem | SFTP version 3 |

The list is deliberately short. Every algorithm on it is one a current client
already prefers, and there is no legacy option to negotiate down to.

## Next

- [Installation](/install)
- [Usage](/usage)
- [Configuration](/config)
