# myownmesh-updater

Self-update for the `myownmesh` daemon and installed portable GUI. Pulled separately so an
embedder that ships its own update story doesn't inherit ours.

```toml
myownmesh-updater = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "vX.Y.Z" }
```

## Lifecycle

1. Background ticker polls the release feed every
   `check_interval_hours` (default 6). Each feed and artifact request uses
   its explicit `auto_update.feed_request_timeout_ms` and
   `auto_update.artifact_download_timeout_ms` owner-configured limits
   (defaults 15000 and 300000 milliseconds); zero values are rejected.
2. Latest version compared to running `CARGO_PKG_VERSION`. If
   newer and policy permits, the asset is downloaded.
3. SHA-256 is verified against a required published checksum
   (`<artifact>.sha256` or a matching `SHA256SUMS` entry).
   With `MYOWNMESH_RELEASE_PUBKEY` compiled into the updater,
   a valid detached `<artifact>.minisig` signature is also required before
   staging; a missing or invalid signature refuses that artifact. Builds
   without the compiled key warn and check SHA-256 only, not release authenticity.
4. Extracted into `~/.myownmesh/updates/<version>/` with a
   `pending.json` marker.
5. On next process start, `apply_pending_if_any()` swaps the daemon and
   staged portable GUI individually, not as an atomic two-binary transaction.

Package-manager installs (Homebrew / apt / rpm / MSI / choco) are
detected on first launch and self-update is skipped — the OS
package manager stays the source of truth.

Portable installs update the `myownmesh` daemon and the matching
`myownmesh-gui` binary installed beside it. GUI discovery also honors
`MYOWNMESH_GUI_BIN` and PATH. Both target the same release, but GUI staging
and replacement are best-effort and do not block a successful daemon update;
an unresolved staged GUI replacement remains pending for a later launch.
Headless installs update only the daemon. Full desktop bundles remain owned
by their installers and are not interchangeable with portable GUI archives.

## Input and archive ceilings

Every network body is read incrementally. Advertised oversized lengths are
refused before the body is read; missing or dishonest lengths do not bypass
the actual-byte limit. The fixed ceilings per request are 4 MiB for release
JSON, 1 MiB for checksums, 64 KiB for detached signatures, and 256 MiB for an
encoded artifact. HTTP content encoding is disabled and non-identity encoded
responses are refused; archive decompression is a separate bounded step.
Existing configured request deadlines cover each whole response, including
its body. Feed, artifact, sidecar, and redirect targets must all use HTTPS.

Staged-file snapshots and extracted executables are limited to 256 MiB. Tar
streams (including concatenated gzip members and trailing padding) have a
272 MiB total decompressed ceiling; at most 16 raw headers and 64 KiB total
GNU long-name/local PAX metadata are allowed. ZIP central-directory metadata
and comments are each limited to 64 KiB, with a single entry required before
the directory parser allocates its map. ZIP64 directories, encryption, links, sparse or
extra files, and non-flat executable names are refused. Release ZIPs support
stored and deflated data; tar, gzip-tar, and the existing raw executable path
remain supported. An archive must contain one nonempty regular executable.

The archive reader shares one 30-second absolute deadline across inspection
and materialization, checked before and after reads/seeks. This is a
cooperative in-process deadline, not OS-enforced CPU/RSS isolation. Parsing
writes no files and spawns no processes: there are no tar stdin/stdout/stderr
pipes, output collectors, or child termination obligations. A refused archive
does not publish its download part or replace an installed executable.
These ceilings bound retained input/output bytes, not exact allocator or
dependency memory use; the existing operation residual remains in force.

## CLI

The daemon stages updates in the background; drive it by hand with:

```
myownmesh update check          # force a check now and stage if permitted
myownmesh update apply           # apply a staged update (effective next start)
myownmesh update status          # version, channel, policy, last check, staged
myownmesh update enable          # turn background checks on
myownmesh update disable         # turn background checks off
```

`check` and `status` take `--json`. `MYOWNMESH_AUTOUPDATE=0` hard-
disables self-update regardless of config.

## Configurable release URL

Build-time env defaults:

```
MYOWNMESH_RELEASE_URL_STABLE  → https://api.github.com/repos/mrjeeves/MyOwnMesh/releases/latest
MYOWNMESH_RELEASE_URL_BETA    → https://api.github.com/repos/mrjeeves/MyOwnMesh/releases
```

Runtime overrides in `~/.myownmesh/config.json`:

The endpoint must serve GitHub-release-shaped JSON, not an HTML release page:
stable expects a release object; beta expects an array and selects the first
non-draft release. The selected object supplies `tag_name` and `assets` with
`name`/`browser_download_url` entries for artifacts, checksums and signatures.
A runtime mirror must retain signatures accepted by the compiled trusted key.
Using a vendor key requires rebuilding with `MYOWNMESH_RELEASE_PUBKEY`; a URL
override does not replace the trust key. See [key rotation](../../RELEASE-SIGNING.md#rotation).

```jsonc
  {
    "auto_update": {
      "channel": "stable",
      "auto_apply": "all",
      "feed_request_timeout_ms": 15000,
      "artifact_download_timeout_ms": 300000,
      "stable_url": "https://your.cdn/myownmesh/latest"
  }
}
```

## Apply policy

`auto_update.auto_apply`:

- `patch` — `0.1.5 → 0.1.6` only
- `minor` — `0.1.5 → 0.2.0` ok
- `all`   — any upgrade
- `none`  — stage but never auto-apply

See [`../../RELEASE.md`](../../RELEASE.md) for the publisher side
of the contract — how artifacts get into the feed this crate
consumes.
