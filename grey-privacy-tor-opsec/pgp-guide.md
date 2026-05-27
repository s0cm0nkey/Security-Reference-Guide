---
description: Maintained OpenPGP/GnuPG reference for key generation, encryption, signatures, and verification.
---

# PGP Guide

{% embed url="https://youtu.be/CEADq-B8KtI" %}

PGP/OpenPGP is still useful for signing, encryption, file verification, and key continuity, but old darknet-market examples and GnuPG 2.0 transcripts age badly. This page is the maintained reference; the Jolly Roger page remains an untouched historical archive.

## Core Guidance

* Prefer current GnuPG documentation and maintained platform docs over old forum workflows.
* Do not generate or store sensitive keys on an untrusted host.
* Verify key fingerprints through a separate trusted channel before trusting a public key.
* Protect the private key and maintain an offline backup of your key material and revocation certificate.
* Add dates, context, and purpose to signed messages so a valid signature cannot be easily replayed out of context.
* Use SHA-256 or stronger hashes and OpenPGP signatures for verification. MD5 and SHA-1 are legacy-only for security purposes.
* Use `--no-comments` and `--no-emit-version` when you do not want GnuPG version comments included in armored output.

## References

* [GnuPG manual](https://gnupg.org/documentation/manuals/gnupg/)
* [GnuPG getting started](https://gnupg.org/gph/en/manual.html)
* [Tails OpenPGP and encryption documentation](https://tails.net/doc/encryption_and_privacy/)
* [EFF Surveillance Self-Defense: PGP](https://ssd.eff.org/)
* [Gpg4win](https://www.gpg4win.org/) - Windows OpenPGP distribution.

## Generate a Key

Modern GnuPG uses `--full-generate-key` for the interactive flow.

```bash
gpg --full-generate-key
```

Recommended defaults for most users:

* Use RSA/RSA or the current GnuPG default unless you have a specific key-type requirement.
* Use a strong passphrase.
* Set an expiration date so old keys age out naturally.
* Create and protect a revocation certificate.

List keys and fingerprints:

```bash
gpg --list-keys --fingerprint
gpg --list-secret-keys --fingerprint
```

## Export and Back Up Keys

Export a public key:

```bash
gpg --armor --export "Name or key ID" > public-key.asc
```

Export a private key only for offline backup:

```bash
gpg --armor --export-secret-keys "Name or key ID" > private-key-backup.asc
```

Create a revocation certificate:

```bash
gpg --output revoke.asc --gen-revoke "Name or key ID"
```

## Import Public Keys

Import from a file:

```bash
gpg --import public-key.asc
```

Import pasted armored text safely from a file or heredoc:

```bash
cat <<'EOF' | gpg --import
-----BEGIN PGP PUBLIC KEY BLOCK-----
PASTE KEY HERE
-----END PGP PUBLIC KEY BLOCK-----
EOF
```

Set trust only after independently verifying the fingerprint:

```bash
gpg --edit-key "Name or key ID"
gpg> fpr
gpg> trust
```

## Encrypt and Decrypt Messages

Encrypt a file for a recipient:

```bash
gpg --encrypt --armor --recipient "Recipient key ID" --output message.asc message.txt
```

Encrypt text from stdin:

```bash
cat message.txt | gpg --encrypt --armor --recipient "Recipient key ID" > message.asc
```

Decrypt:

```bash
gpg --decrypt message.asc
gpg --output message.txt --decrypt message.asc
```

For lower-noise armored output:

```bash
gpg --encrypt --armor --no-comments --no-emit-version --recipient "Recipient key ID" --output message.asc message.txt
```

## Sign and Verify

Clearsign text:

```bash
gpg --clearsign message.txt
```

Create a detached signature:

```bash
gpg --armor --detach-sign file.zip
```

Verify a signed message or detached signature:

```bash
gpg --verify message.txt.asc
gpg --verify file.zip.asc file.zip
```

If verification fails after any text changes, treat the content as modified.

## Tails and OpenPGP

Tails no longer uses the old `gpgapplet` documentation paths commonly found in historical guides. Use the current Tails encryption and OpenPGP documentation for supported workflows.

{% content-ref url="jolly-rogers-security-for-beginners.md" %}
[jolly-rogers-security-for-beginners.md](jolly-rogers-security-for-beginners.md)
{% endcontent-ref %}
