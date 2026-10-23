## OpenPGP keys for Skydoge releases

`keys.txt` lists the fingerprint of every key used to sign a Skydoge release or
a gitian build assertion.

### The release key

From 0.45.3b on, each release's `SHA256SUMS` is signed (`SHA256SUMS.asc`) with
the Skydoge Release Signing Key:

    915D 0BAA 47E6 056B 5E02  FDAE 2DE1 360A 2AE8 EC88

The public key is `skydoge-release-key.asc` in this directory. Earlier releases
are not signed with it. The Windows installer and macOS disk image themselves
are not code-signed. The reproducible build stays the strongest check: build
the same commit yourself and compare. See `doc/release-process.md`.

### Verifying

The security is in the **fingerprint**, not in where the key was downloaded
from. A key server will hand out whatever anyone uploaded to it, including a
key bearing this project's name that this project never made, so fetching a key
by name and trusting it verifies nothing.

Get the fingerprint from a channel you already trust, then check that whatever
key you obtained actually has it:

```sh
# 1. import the key committed alongside this file
gpg --import contrib/gitian-keys/*.asc

# 2. compare its fingerprint against the one published at https://skydoge.net
gpg --fingerprint 915D0BAA47E6056B5E02FDAE2DE1360A2AE8EC88

# 3. only then does the signature mean anything
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

Two independent sources - this repository and the project website over TLS -
have to agree on the fingerprint. If they disagree, stop.

### Key servers

A key server is a convenience for fetching a key you can already identify, not
a source of trust. If you use one, verify the fingerprint afterwards as above.

Note that the `sks-keyservers.net` pool referenced by older Bitcoin Core
documentation no longer exists; it was shut down after certificate-flooding
attacks made keys in it unimportable. `keys.openpgp.org` is the usable
replacement.

### Adding a key

Add a fingerprint to `keys.txt` only for a key that has actually signed a
release or a gitian assertion for **this** project, and commit the public key
beside it as an `.asc` in the same directory.
