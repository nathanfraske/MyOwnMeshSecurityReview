# Release signing (minisign)

The release workflow and shipped self-updater use mandatory minisign
provenance. Every release payload has an exact SHA-256 digest in the
build-owned asset manifest and a detached `<asset>.minisig`; portable archives
also publish `<asset>.sha256` sidecars. Missing, orphaned, or mismatched
digests/signatures fail closed before publication or staging. The updater’s
release builds bake the matching public key through
`MYOWNMESH_RELEASE_PUBKEY`, so an unsigned artifact is never accepted.

There is no unsigned, optional, no-op, or SHA-only release mode. Configure both
required Actions secrets before cutting a release.

## One-time setup

1. **Generate a password-less signing key** (CI must sign non-interactively):

   ```sh
   minisign -G -W -p minisign.pub -s minisign.key
   ```

   - `minisign.pub` holds a comment line and the base64 **public key** (line 2).
   - `minisign.key` is the **secret key** — treat it like any signing secret.

2. **Add both keys to GitHub Actions** using the exact repository secret names:

   - `MINISIGN_SECRET_KEY`: the full contents of `minisign.key`.
   - `MINISIGN_PUBLIC_KEY`: the base64 public-key string from `minisign.pub`.

   The workflow deliberately reads the public key as
   `${{ secrets.MINISIGN_PUBLIC_KEY }}`. It passes that exact value to the
   updater build as `MYOWNMESH_RELEASE_PUBKEY` and checks the two values for
   equality; do not substitute a differently named variable.

3. **Cut a test release** and confirm `.minisig` sidecars sit next to each
   `myownmesh-*.tar.gz` / `.zip`, and that `myownmesh update` on a build compiled
   with the pubkey accepts it.

## Scope of this key

This key signs every published release payload, including the opaque Tauri
installers. The self-updater consumes the signatures for the portable MyOwnMesh
artifacts it downloads; Tauri installers are verified as release payloads but
are not updater inputs.

An application that embeds or bundles this daemon — fetching or building it at
its own build time and shipping it as a sidecar — is outside that scope. Such a
copy never passes through `myownmesh update`, so nothing here verifies it, and
the embedder is responsible for covering it under its own release verification.
Stated explicitly because the gap is easy to assume closed: a signed project is
not the same as a signed copy of it.

## Rotation

Generate a new key, update both `MINISIGN_SECRET_KEY` and
`MINISIGN_PUBLIC_KEY`, then cut a new release so the updater build receives the
new `MYOWNMESH_RELEASE_PUBKEY`. Do not publish an artifact signed by a key that
does not match the public key baked into the release build.
