---
layout: home

hero:
  name: "ts-sftp"
  text: "An SFTP server for Bun."
  tagline: "SSH transport, public key auth, and pluggable storage — implemented from the wire up."
  actions:
    - theme: brand
      text: Get Started
      link: /intro
    - theme: alt
      text: View on GitHub
      link: https://github.com/stacksjs/ts-sftp

features:
  - title: "No Protocol Dependencies"
    icon: "📦"
    details: "Key exchange, ciphers, and the SFTP protocol implemented on node:crypto alone."
  - title: "Modern Crypto"
    icon: "🔐"
    details: "curve25519-sha256, Ed25519 host keys, AES-256-GCM, and strict KEX."
  - title: "Pluggable Storage"
    icon: "🗂️"
    details: "Serve local disk, object storage, or any tree you can describe."
  - title: "Real Clients"
    icon: "🔌"
    details: "Tested end to end against the OpenSSH sftp client."
---
