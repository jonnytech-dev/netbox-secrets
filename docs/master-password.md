# Master Password

A master password lets you unlock secrets by typing a password instead of pasting your RSA private key.

```
                    ┌─ paste private key ─────────────────────────┐
User wants secrets ─┤                                             ├─► private key ─► master key ─► session key
                    └─ type master password ─► unlock stored ────┘
                                               encrypted private key
```

- It is **per user**. Each user sets their own.
- It is **not** your NetBox login password. Login resets, LDAP, SSO, and MFA do not touch it.
- Your private key still works. Both paths end at the same private key.
- It does not change what you can see. NetBox permissions still decide which secrets you can view.

## How it works

When you set a master password, the plugin stores a copy of your private key on your User Key, encrypted with that password.

| Detail | Value |
|---|---|
| Format | Encrypted PKCS#8 PEM |
| Key derivation | scrypt (cost set by `master_password_scrypt_n`) |
| Encryption | AES-256-GCM (authenticated) |
| Stored on | `UserKey.encrypted_private_key` |

The master password itself is never stored or logged.

## Set it up

1. Open **Secrets → User Keys** and go to your key.
2. In the **Master Password** panel, click **Set Master Password**.
3. Paste your private key to prove it's yours.
4. Enter a new master password twice, then click **Save**.

## Use it

When NetBox asks you to unlock secrets, the **Master Password** tab is selected. Type your password and press Enter.

Administrators can also use their master password on the **Activate User Keys** page.

## Change or remove it

Use **Change** or **Remove** on the Master Password panel. Prove it's you with your private key or your current master password.

## Forgot it?

There is no reset. Paste your private key, then set a new master password. Keep a backup of your private key somewhere safe, such as a password manager.

If your public key changes, the stored copy no longer matches, so the master password is cleared automatically.

## Failed attempts

After too many wrong master passwords, unlocking with a master password is blocked for a while. Pasting your private key still works during a lockout.

## Settings

```python
PLUGINS_CONFIG = {
    'netbox_secrets': {
        'master_password_enabled': True,          # turn the feature on or off
        'master_password_min_length': 12,         # minimum password length
        'master_password_max_attempts': 5,        # failures before lockout
        'master_password_lockout_seconds': 900,   # lockout length
        'master_password_scrypt_n': 131072,       # scrypt cost (power of two, at least 16384)
    },
}
```

`master_password_scrypt_n` sets how slow each guess is. Higher is safer but slower and uses more memory (about 128 MiB at 131072). It only affects passwords set after the change. On small hardware such as a Raspberry Pi, `65536` is a reasonable choice.

## Security trade-off

Without a master password, a stolen database is useless on its own, because private keys are never stored.

With a master password, the database holds an encrypted copy of your private key. An attacker with the database could try to guess your password offline. scrypt makes each guess slow, but a weak password can still be cracked. Use a long, unique master password.

## API

| Method | Endpoint | Body |
|---|---|---|
| `GET` | `/api/plugins/secrets/user-keys/master-password/` | (none) returns `enabled`, `has_master_password`, `min_length` |
| `POST` | `/api/plugins/secrets/user-keys/master-password/` | `private_key` or `current_master_password`, plus `master_password`, `master_password_confirm` |
| `DELETE` | `/api/plugins/secrets/user-keys/master-password/` | `private_key` or `current_master_password` |
| `POST` | `/api/plugins/secrets/session-key/` | `master_password` (instead of `private_key`), optional `preserve_key` |
| `POST` | `/api/plugins/secrets/user-keys/activate/` | `master_password` (instead of `private_key`), `user_key_ids` |

A locked-out master password attempt returns `429 Too Many Requests`.
