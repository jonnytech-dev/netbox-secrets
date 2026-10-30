# NetBox Secrets — Master Password Fork

A fork of [netbox-secrets](https://github.com/Onemind-Services-LLC/netbox-secrets) v3.1.2.

## Current Environment
The current Netbox environment this fork is targeted for is Netbox 4.6.1.
This fork may still work for newer versions, try at your own risk.

## Why

The native netbox-secrets plugin makes you paste your full RSA private key every time you unlock secrets. That's slow. I personally like a password manager apporach where there is one master password that unlocks all of your passwords (ex. NordPass, 1Password, etc).

The fork of this plugin does exactly that. I've added a master password option when creating the RSA private key (user key).
The same process of creating a user key exists. You can choose to use the private key or the master password. 
I recommend saving the private key somewhere secure, then using the master password for general use.

## What changed

- **Master password.** Each user can set a master password that unlocks their private key. Type the password instead of pasting the key. Pasting the key still works.
- **Not your login.** The master password is separate from your NetBox account.
- **Same access.** Users still only see the secrets their permissions allow.
- **Lockout.** Too many wrong passwords blocks master password unlock for a while.
- **Bug fix.** The Activate User Keys page now activates every selected key, not just the first.

Details: [docs/master-password.md](docs/master-password.md)

---

*Upstream README below.*

# NetBox Secrets

NetBox Secrets is a NetBox plugin for securely storing and managing secrets (passwords, API keys, tokens, certificates, etc.)
with end-to-end encryption. Secrets are encrypted at rest and can be assigned to any supported NetBox object.

## Highlights
- Public-key (RSA) based master key distribution
- AES-256 encryption for secret values
- Session-key workflow for encryption/decryption
- Flexible secret assignment to NetBox objects
- Secret roles for organization and access control
- REST API + GraphQL integration

## Compatibility

| NetBox Version | Plugin Version |
|----------------|----------------|
| 3.3.x          | 1.4.x - 1.5.x  |
| 3.4.x          | 1.6.x - 1.7.x  |
| 3.5.x          | 1.8.x          |
| 3.6.x          | 1.9.x          |
| 3.7.x          | 1.10.x         |
| 4.0.x          | 2.0.x          |
| 4.1.x          | 2.1.x          |
| 4.2.x          | 2.2.x          |
| 4.3.x          | 2.3.x          |
| 4.4.x          | 2.4.x          |
| 4.5.x          | 3.0.x          |
| 4.6.x          | 3.1.x          |

## Quickstart
- Setup (installation + configuration): [docs/installation.md](docs/installation.md)
- Then create your first User Key in the UI

## Documentation
- Setup: [docs/installation.md](docs/installation.md)
- Usage: [docs/usage.md](docs/usage.md)
- API: [docs/api.md](docs/api.md)
- Cryptography: [docs/cryptography.md](docs/cryptography.md)
- Permissions: [docs/permissions.md](docs/permissions.md)
- Troubleshooting: [docs/troubleshooting.md](docs/troubleshooting.md)

## Release Notes
- Release notes are maintained in GitHub for each version.

## Deprecations & Migration
- Legacy API endpoints supported until NetBox v4.6: [docs/api.md](docs/api.md)

## Legacy Migration
Legacy guidance for netbox-secretstore migrations is available here:
[docs/legacy-migration.md](docs/legacy-migration.md)

## Support
- Issues and feature requests: open a ticket in your internal tracker or this repository's issue tracker.
- Security concerns: see `SECURITY.md`.

## License

See `LICENSE.md`.
